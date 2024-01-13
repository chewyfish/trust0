use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;
use serde_json::Value;

use crate::client::connection::ClientConnVisitor;
use crate::client::device::Device;
use crate::config::AppConfig;
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;
use trust0_common::authn::authenticator::{AuthenticatorServer, AuthnMessage, AuthnType};
use trust0_common::authn::insecure_authenticator::InsecureAuthenticatorServer;
use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorServer;
use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use trust0_common::model;
use trust0_common::net::tls_server::conn_std::{ConnectionEvent, TlsServerConnection};
use trust0_common::net::tls_server::{conn_std, server_std};

/// (MFA) Authentication context
struct AuthnContext {
    authenticator: Box<dyn AuthenticatorServer>,
    authn_thread_handle: Option<JoinHandle<Result<AuthnMessage, AppError>>>,
}

/// Process control plane commands. Clients use a connection REPL shell to issue requests.
pub struct ControlPlane {
    app_config: Arc<AppConfig>,
    processor: request::RequestProcessor,
    access_repo: Arc<Mutex<dyn AccessRepository>>,
    _service_repo: Arc<Mutex<dyn ServiceRepository>>,
    user_repo: Arc<Mutex<dyn UserRepository>>,
    event_channel_sender: Sender<ConnectionEvent>,
    device: Device,
    user: model::user::User,
    authn_context: Rc<Mutex<AuthnContext>>,
    services_by_id: HashMap<u64, model::service::Service>,
    services_by_name: HashMap<String, model::service::Service>,
}

impl ControlPlane {
    /// ControlPlane constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        access_repo: Arc<Mutex<dyn AccessRepository>>,
        service_repo: Arc<Mutex<dyn ServiceRepository>>,
        user_repo: Arc<Mutex<dyn UserRepository>>,
        event_channel_sender: Sender<ConnectionEvent>,
        device: Device,
        user: model::user::User,
    ) -> Result<Self, AppError> {
        let (services_by_id, services_by_name) = Self::setup_services_maps(&service_repo)?;

        let authenticator: Box<dyn AuthenticatorServer> = match &app_config.mfa_scheme {
            AuthnType::ScramSha256 => Box::new(ScramSha256AuthenticatorServer::new(
                user.clone(),
                Duration::from_millis(10_000),
            )),
            AuthnType::Insecure => Box::new(InsecureAuthenticatorServer::new()),
        };

        Ok(Self {
            app_config,
            processor: request::RequestProcessor::new(),
            access_repo,
            _service_repo: service_repo,
            user_repo,
            event_channel_sender,
            device,
            user,
            authn_context: Rc::new(Mutex::new(AuthnContext {
                authenticator,
                authn_thread_handle: None,
            })),
            services_by_id,
            services_by_name,
        })
    }

    /// Prepare response stringified JSON
    fn prepare_response(
        code: u16,
        message: &Option<String>,
        request: &request::Request,
        data: &Option<Value>,
    ) -> Result<String, AppError> {
        Self::jsonify(&response::Response::new(code, message, request, data))
    }

    /// Process 'about' command
    fn process_cmd_about(&self) -> Result<String, AppError> {
        let device = &self.device;
        let user_id = device.get_cert_access_context().user_id;
        let user = self
            .user_repo
            .lock()
            .unwrap()
            .get(user_id)?
            .map(|u| response::User::new(u.user_id, &u.name, &format!("{:?}", u.status)));

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::About,
            &Some(
                response::About::new(
                    &Some(format!("{:?}", device.get_cert_subj())),
                    &Some(format!("{:?}", device.get_cert_alt_subj())),
                    &Some(format!("{:?}", device.get_cert_access_context())),
                    &user,
                )
                .try_into()?,
            ),
        )
    }

    /// Process 'login' command
    fn process_cmd_login(&self) -> Result<String, AppError> {
        let mut authn_context = self.authn_context.lock().unwrap();

        let response_authn_msg = if authn_context.authenticator.is_authenticated() {
            Some(AuthnMessage::Authenticated)
        } else {
            if AuthnType::ScramSha256 == self.app_config.mfa_scheme {
                let mut authenticator = ScramSha256AuthenticatorServer::new(
                    self.user.clone(),
                    Duration::from_millis(10_000),
                );
                authn_context.authn_thread_handle = authenticator.spawn_authentication();
                authn_context.authenticator = Box::new(authenticator);
            }
            None
        };

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Login,
            &Some(
                response::LoginData::new(self.app_config.mfa_scheme.clone(), response_authn_msg)
                    .try_into()?,
            ),
        )
    }

    /// Process 'login-data' command
    fn process_cmd_login_data(&self, authn_msg: AuthnMessage) -> Result<String, AppError> {
        let mut authn_context = self.authn_context.lock().unwrap();

        let response_authn_msg = if authn_context.authenticator.is_authenticated() {
            Some(AuthnMessage::Authenticated)
        } else if authn_context.authn_thread_handle.is_none() {
            return Err(AppError::GenWithCodeAndMsg(
                response::CODE_FORBIDDEN,
                "Login process flow not initiated".to_string(),
            ));
        } else {
            authn_context
                .authenticator
                .exchange_messages(Some(authn_msg.clone()))?
        };

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::LoginData {
                message: authn_msg.clone(),
            },
            &Some(
                response::LoginData::new(self.app_config.mfa_scheme.clone(), response_authn_msg)
                    .try_into()?,
            ),
        )
    }

    /// Process 'connections' command
    fn process_cmd_connections(
        &self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
    ) -> Result<String, AppError> {
        let mask_addrs = self.app_config.mask_addresses;

        let service_proxies = service_mgr.lock().unwrap().get_service_proxies();

        let connections: Vec<Value> = service_proxies
            .iter()
            .map(|service_proxy| {
                let service_proxy = service_proxy.lock().unwrap();

                let proxy_addrs_list = service_proxy.get_proxy_addrs_for_user(self.user.user_id);

                let binds = proxy_addrs_list
                    .iter()
                    .map(|proxy_addrs| {
                        if !mask_addrs {
                            vec![proxy_addrs.0.clone(), proxy_addrs.1.clone()]
                        } else {
                            vec![proxy_addrs.0.clone()]
                        }
                    })
                    .collect();

                response::Connection::new(&service_proxy.get_service().name, binds).try_into()
            })
            .collect::<Result<Vec<Value>, AppError>>()?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Connections,
            &Some(connections.into()),
        )
    }

    /// Process 'proxies' command
    fn process_cmd_proxies(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
    ) -> Result<String, AppError> {
        let user_services: HashSet<u64> = self
            .access_repo
            .lock()
            .unwrap()
            .get_all_for_user(&self.user)?
            .iter()
            .map(|access| access.service_id)
            .collect();

        let service_proxies = service_mgr.lock().unwrap().get_service_proxies();

        let proxies: Vec<Value> = service_proxies
            .iter()
            .filter_map(|service_proxy| {
                let service_proxy = service_proxy.lock().unwrap();
                let service = service_proxy.get_service();
                if user_services.contains(&service.service_id) {
                    Some(
                        response::Proxy::new(
                            &service.into(),
                            &service_proxy.get_proxy_host(),
                            service_proxy.get_proxy_port(),
                            &None,
                        )
                        .try_into(),
                    )
                } else {
                    None
                }
            })
            .collect::<Result<Vec<Value>, AppError>>()?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Proxies,
            &Some(proxies.into()),
        )
    }

    /// Process 'services' command
    fn process_cmd_services(&mut self) -> Result<String, AppError> {
        let mask_addrs = self.app_config.mask_addresses;

        let user_services: Vec<Value> = self
            .access_repo
            .lock()
            .unwrap()
            .get_all_for_user(&self.user)?
            .iter()
            .filter_map(|access| self.services_by_id.get(&access.service_id))
            .map(|service| {
                let service = Self::prepare_response_service(service, mask_addrs);
                service.try_into()
            })
            .collect::<Result<Vec<Value>, AppError>>()?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Services,
            &Some(user_services.into()),
        )
    }

    /// Process 'start' command
    fn process_cmd_start(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        service_name: &str,
        local_port: u16,
    ) -> Result<String, AppError> {
        // Validate requested service is valid and user is authorized
        let service =
            self.services_by_name
                .get(service_name)
                .ok_or(AppError::GenWithCodeAndMsg(
                    response::CODE_NOT_FOUND,
                    format!("Unknown service: svc_name={}", service_name),
                ))?;

        if self
            .access_repo
            .lock()
            .unwrap()
            .get_for_user(service.service_id, &self.user)?
            .is_none()
        {
            return Err(AppError::GenWithCodeAndMsg(
                response::CODE_FORBIDDEN,
                format!(
                    "User is not authorized for service: user_id={}, svc_id={}",
                    self.user.user_id, service.service_id
                ),
            ));
        }

        // Start up service proxy
        let service_mgr_copy = service_mgr.clone();
        let (gateway_service_host, gateway_service_port) = service_mgr
            .lock()
            .unwrap()
            .startup(service_mgr_copy, service)?;

        // Return service proxy connection
        let service = Self::prepare_response_service(service, self.app_config.mask_addresses);

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Start {
                service_name: service_name.to_string(),
                local_port,
            },
            &Some(
                response::Proxy::new(
                    &service,
                    &gateway_service_host,
                    gateway_service_port,
                    &Some(local_port),
                )
                .try_into()?,
            ),
        )
    }

    /// Process 'stop' command
    fn process_cmd_stop(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        service_name: &str,
    ) -> Result<String, AppError> {
        // Validate requested service is valid and proxy is currently active
        let service =
            self.services_by_name
                .get(service_name)
                .ok_or(AppError::GenWithCodeAndMsg(
                    response::CODE_NOT_FOUND,
                    format!("Unknown service: svc_name={}", service_name),
                ))?;

        if !service_mgr
            .lock()
            .unwrap()
            .has_proxy_for_user_and_service(self.user.user_id, service.service_id)
        {
            return Err(AppError::GenWithCodeAndMsg(
                response::CODE_NOT_FOUND,
                format!(
                    "No active proxy found: user_id={}, svc_id={}",
                    self.user.user_id, service.service_id
                ),
            ));
        }

        // Shutdown service proxy
        service_mgr
            .lock()
            .unwrap()
            .shutdown_connections(Some(self.user.user_id), Some(service.service_id))?;

        // Return service proxy connection
        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Stop {
                service_name: service_name.to_string(),
            },
            &None,
        )
    }

    /// Process 'quit' command
    fn process_cmd_quit(&self) -> Result<String, AppError> {
        self.event_channel_sender
            .send(ConnectionEvent::Closing)
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err))
            })?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Quit,
            &Some("bye".into()),
        )
    }

    /// Protected (authenticated) resource guard
    fn assert_authenticated(&self) -> Result<(), AppError> {
        if self
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated()
        {
            Ok(())
        } else {
            Err(AppError::GenWithCodeAndMsg(
                response::CODE_FORBIDDEN,
                format!(
                    "Not authenticated, please perform the '{}' request flow first",
                    request::PROTOCOL_REQUEST_LOGIN
                ),
            ))
        }
    }

    /// Convert model service to response service
    fn prepare_response_service(
        service: &model::service::Service,
        mask_addrs: bool,
    ) -> response::Service {
        let mut service = service.clone();
        if mask_addrs {
            service.host.clear();
            service.port = 0;
        }
        service.into()
    }

    /// Serialize object to JSON
    fn jsonify<T: serde::Serialize>(object: &T) -> Result<String, AppError> {
        serde_json::to_string(&object).map_err(|err| {
            AppError::GenWithMsgAndErr("Error serializing response".to_string(), Box::new(err))
        })
    }

    #[allow(clippy::complexity)]
    /// Setup services maps
    fn setup_services_maps(
        service_repo: &Arc<Mutex<dyn ServiceRepository>>,
    ) -> Result<
        (
            HashMap<u64, model::service::Service>,
            HashMap<String, model::service::Service>,
        ),
        AppError,
    > {
        let services = service_repo.lock().unwrap().get_all()?;
        let services_by_id: HashMap<u64, model::service::Service> = services
            .iter()
            .map(|service| (service.service_id, service.clone()))
            .collect();
        let services_by_name: HashMap<String, model::service::Service> = services
            .iter()
            .map(|service| (service.name.clone(), service.clone()))
            .collect();

        Ok((services_by_id, services_by_name))
    }
}

unsafe impl Send for ControlPlane {}

impl RequestProcessor for ControlPlane {
    /// Process given command request
    fn process_request(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        command_line: &str,
    ) -> Result<request::Request, AppError> {
        let client_request: request::Request;
        let client_response: Result<String, AppError>;

        match self.processor.parse(command_line) {
            Ok(request::Request::About) => {
                client_request = request::Request::About;
                client_response = self.process_cmd_about();
            }
            Ok(request::Request::Connections) => {
                client_request = request::Request::Connections;
                client_response = self
                    .assert_authenticated()
                    .and(self.process_cmd_connections(service_mgr));
            }
            Ok(request::Request::Ignore) => return Ok(request::Request::Ignore),
            Ok(request::Request::Login) => {
                client_request = request::Request::Login;
                client_response = self.process_cmd_login();
            }
            Ok(request::Request::LoginData { message: authn_msg }) => {
                client_request = request::Request::LoginData {
                    message: authn_msg.clone(),
                };
                client_response = self.process_cmd_login_data(authn_msg);
            }
            Ok(request::Request::Ping) => {
                client_request = request::Request::Ping;
                client_response = Self::prepare_response(
                    response::CODE_OK,
                    &Some("pong".to_string()),
                    &client_request,
                    &None,
                );
            }
            Ok(request::Request::Proxies) => {
                client_request = request::Request::Proxies;
                client_response = self
                    .assert_authenticated()
                    .and(self.process_cmd_proxies(service_mgr));
            }
            Ok(request::Request::Services) => {
                client_request = request::Request::Services;
                client_response = self.assert_authenticated().and(self.process_cmd_services());
            }
            Ok(request::Request::Start {
                service_name,
                local_port,
            }) => {
                client_request = request::Request::Start {
                    service_name: service_name.clone(),
                    local_port,
                };
                client_response = self.assert_authenticated().and(self.process_cmd_start(
                    service_mgr,
                    &service_name,
                    local_port,
                ));
            }
            Ok(request::Request::Stop { service_name }) => {
                client_request = request::Request::Stop {
                    service_name: service_name.clone(),
                };
                client_response = self
                    .assert_authenticated()
                    .and(self.process_cmd_stop(service_mgr, &service_name));
            }
            Ok(request::Request::Quit) => {
                client_request = request::Request::Quit;
                client_response = self.process_cmd_quit();
            }
            Ok(request::Request::None) => {
                client_request = request::Request::None;
                client_response = Self::prepare_response(
                    response::CODE_OK,
                    &Some("".to_string()),
                    &client_request,
                    &None,
                );
            }
            Err(err) => {
                client_request = request::Request::None;
                client_response = Err(err);
            }
        }

        let client_response_str = client_response.unwrap_or_else(|err| {
            let err_response: Result<String, AppError> = match err.get_code() {
                Some(code) if code == response::CODE_BAD_REQUEST => {
                    Self::prepare_response(code, &None, &client_request, &None)
                }
                Some(code) => {
                    Self::prepare_response(code, &Some(err.to_string()), &client_request, &None)
                }
                _ => Self::prepare_response(
                    response::CODE_INTERNAL_SERVER_ERROR,
                    &Some(err.to_string()),
                    &client_request,
                    &None,
                ),
            };
            err_response
                .unwrap_or_else(|err| format!("Error serializing error response: err={:?}", err))
        });

        if !client_response_str.is_empty() {
            let client_response_str = format!("{client_response_str}\n");

            if let Err(err) = self
                .event_channel_sender
                .send(ConnectionEvent::Write(client_response_str.into_bytes()))
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending client stream write channel event".to_string(),
                        Box::new(err),
                    )
                })
            {
                let _ = self.event_channel_sender.send(ConnectionEvent::Closing);

                return Err(err);
            }
        }

        Ok(client_request)
    }

    fn is_authenticated(&self) -> bool {
        self.authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated()
    }
}

pub trait RequestProcessor: Send {
    /// Process given command request
    fn process_request(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        command_line: &str,
    ) -> Result<request::Request, AppError>;

    /// Returns (secondary) authentication state
    fn is_authenticated(&self) -> bool;
}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct ControlPlaneServerVisitor {
    app_config: Arc<AppConfig>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
}

impl ControlPlaneServerVisitor {
    /// ServerVisitor constructor
    pub fn new(app_config: Arc<AppConfig>, service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {
        Self {
            app_config,
            service_mgr,
        }
    }
}

impl server_std::ServerVisitor for ControlPlaneServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
    ) -> Result<conn_std::Connection, AppError> {
        let mut conn_visitor =
            ClientConnVisitor::new(self.app_config.clone(), self.service_mgr.clone());

        let alpn_protocol = conn_visitor.process_authorization(&tls_conn, None)?;

        let connection =
            conn_std::Connection::new(Box::new(conn_visitor), tls_conn, alpn_protocol)?;

        Ok(connection)
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        server_std::Server::spawn_connection_processor(connection);

        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::client::controller::RequestProcessor;
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::tests::MockSvcMgr;
    use crate::service::proxy::proxy_base::tests::MockGwSvcProxyVisitor;
    use mockall::{mock, predicate};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use trust0_common::authn::authenticator::{AuthenticatorClient, AuthenticatorServer};
    use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorClient;
    use trust0_common::crypto::file::load_certificates;
    use trust0_common::model::access::{EntityType, ServiceAccess};

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];

    // mocks
    // =====
    mock! {
        pub AuthServer {}
        impl AuthenticatorServer for AuthServer {
            fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>>;
            fn authenticate(&mut self) -> Result<AuthnMessage, AppError>;
            fn exchange_messages(&mut self, inbound_msg: Option<AuthnMessage>) -> Result<Option<AuthnMessage>, AppError>;
            fn is_authenticated(&self) -> bool;
        }
    }

    mock! {
        pub ReqProcessor {}
        impl RequestProcessor for ReqProcessor {
            fn process_request(&mut self, service_mgr: &Arc<Mutex<dyn ServiceMgr>>, command_line: &str) -> Result<request::Request, AppError>;
            fn is_authenticated(&self) -> bool;
        }
    }

    // utils
    // =====

    fn create_device() -> Result<Device, AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().unwrap().to_string())?;
        Device::new(certs)
    }

    fn create_user() -> model::user::User {
        model::user::User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=".to_string()),
            name: "user100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
        }
    }

    fn create_repos(
        expect_user_get: bool,
        expect_access_get_all_for_user: bool,
        expect_access_get_for_user: bool,
    ) -> (
        Arc<Mutex<dyn UserRepository>>,
        Arc<Mutex<dyn ServiceRepository>>,
        Arc<Mutex<dyn AccessRepository>>,
    ) {
        let mut user_repo = MockUserRepo::new();
        let user = create_user();
        let user_copy = user.clone();
        if expect_user_get {
            user_repo
                .expect_get()
                .with(predicate::eq(100))
                .times(1)
                .return_once(move |_| Ok(Some(user_copy)));
        }

        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get_all().times(1).return_once(move || {
            Ok(vec![
                model::service::Service {
                    service_id: 200,
                    name: "Service200".to_string(),
                    transport: model::service::Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8200,
                },
                model::service::Service {
                    service_id: 201,
                    name: "Service201".to_string(),
                    transport: model::service::Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8201,
                },
                model::service::Service {
                    service_id: 202,
                    name: "Service202".to_string(),
                    transport: model::service::Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8202,
                },
                model::service::Service {
                    service_id: 203,
                    name: "chat-tcp".to_string(),
                    transport: model::service::Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8500,
                },
                model::service::Service {
                    service_id: 204,
                    name: "echo-udp".to_string(),
                    transport: model::service::Transport::UDP,
                    host: "localhost".to_string(),
                    port: 8600,
                },
            ])
        });

        let mut access_repo = MockAccessRepo::new();
        if expect_access_get_all_for_user {
            access_repo
                .expect_get_all_for_user()
                .with(predicate::eq(user.clone()))
                .times(1)
                .return_once(move |_| {
                    Ok(vec![
                        ServiceAccess {
                            service_id: 200,
                            entity_type: EntityType::User,
                            entity_id: 100,
                        },
                        ServiceAccess {
                            service_id: 203,
                            entity_type: EntityType::Role,
                            entity_id: 50,
                        },
                        ServiceAccess {
                            service_id: 204,
                            entity_type: EntityType::Role,
                            entity_id: 51,
                        },
                        ServiceAccess {
                            service_id: 202,
                            entity_type: EntityType::User,
                            entity_id: 101,
                        },
                        ServiceAccess {
                            service_id: 203,
                            entity_type: EntityType::User,
                            entity_id: 101,
                        },
                    ])
                });
        }
        if expect_access_get_for_user {
            access_repo
                .expect_get_for_user()
                .with(predicate::eq(200), predicate::eq(user))
                .return_once(move |_, _| {
                    Ok(Some(ServiceAccess {
                        service_id: 200,
                        entity_type: EntityType::User,
                        entity_id: 100,
                    }))
                });
        }

        (
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(access_repo)),
        )
    }

    fn create_service_mgr(
        expect_connection_details: bool,
        expect_proxy_details: bool,
        expect_startup_proxy: bool,
        expect_shutdown_proxy: bool,
    ) -> Arc<Mutex<dyn ServiceMgr>> {
        let mut service_mgr = MockSvcMgr::new();

        if expect_connection_details || expect_proxy_details {
            let mut service_proxy = MockGwSvcProxyVisitor::new();
            service_proxy
                .expect_get_service()
                .times(1)
                .return_once(move || model::service::Service {
                    service_id: 200,
                    name: "Service200".to_string(),
                    transport: model::service::Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8200,
                });
            if expect_connection_details {
                service_proxy
                    .expect_get_proxy_addrs_for_user()
                    .with(predicate::eq(100))
                    .times(1)
                    .return_once(move |_| vec![("addr1".to_string(), "addr2".to_string())]);
            }
            if expect_proxy_details {
                service_proxy
                    .expect_get_proxy_host()
                    .times(1)
                    .return_once(move || Some("proxyhost1".to_string()));
                service_proxy
                    .expect_get_proxy_port()
                    .times(1)
                    .return_once(move || 6000);
            }
            service_mgr
                .expect_get_service_proxies()
                .times(1)
                .return_once(move || vec![Arc::new(Mutex::new(service_proxy))]);
        }

        if expect_startup_proxy {
            let service = model::service::Service {
                service_id: 200,
                name: "Service200".to_string(),
                transport: model::service::Transport::TCP,
                host: "localhost".to_string(),
                port: 8200,
            };
            service_mgr
                .expect_startup()
                .with(predicate::always(), predicate::eq(service))
                .times(1)
                .return_once(move |_, _| Ok((Some("proxyhost1".to_string()), 6000)));
        }

        if expect_shutdown_proxy {
            service_mgr
                .expect_has_proxy_for_user_and_service()
                .with(predicate::eq(100), predicate::eq(200))
                .times(1)
                .return_once(move |_, _| true);
            service_mgr
                .expect_shutdown_connections()
                .with(predicate::eq(Some(100)), predicate::eq(Some(200)))
                .times(1)
                .return_once(move |_, _| Ok(()));
        }

        Arc::new(Mutex::new(service_mgr))
    }

    fn create_control_plane(
        event_channel_sender: Sender<ConnectionEvent>,
        user_repo: &Arc<Mutex<dyn UserRepository>>,
        service_repo: &Arc<Mutex<dyn ServiceRepository>>,
        access_repo: &Arc<Mutex<dyn AccessRepository>>,
        device: Device,
        user: model::user::User,
        mfa_scheme: AuthnType,
    ) -> Result<ControlPlane, AppError> {
        let mut app_config = config::tests::create_app_config_with_repos(
            user_repo.clone(),
            service_repo.clone(),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            access_repo.clone(),
        )?;
        app_config.mfa_scheme = mfa_scheme;

        Ok(ControlPlane::new(
            Arc::new(app_config),
            access_repo.clone(),
            service_repo.clone(),
            user_repo.clone(),
            event_channel_sender,
            device,
            user,
        )?)
    }

    // tests
    // =====

    #[test]
    fn ctlplane_process_request_when_valid_login_and_already_authed() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let mut authenticator = MockAuthServer::new();
        authenticator
            .expect_is_authenticated()
            .times(1)
            .return_once(|| true);
        control_plane.authn_context.lock().unwrap().authenticator = Box::new(authenticator);

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_LOGIN);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Login);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(
                    String::from_utf8(response_bytes.clone()).unwrap(),
                    "{\"code\":200,\"message\":null,\"request\":\"Login\",\"data\":{\"authnType\":\"insecure\",\"message\":\"authenticated\"}}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_login_and_insecure_authn() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_LOGIN);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Login);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(
                    String::from_utf8(response_bytes.clone()).unwrap(),
                    "{\"code\":200,\"message\":null,\"request\":\"Login\",\"data\":{\"authnType\":\"insecure\",\"message\":\"authenticated\"}}\n");
            }
        }

        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated());
    }

    #[test]
    fn ctlplane_process_request_when_valid_login_and_scramsha256_authn() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::ScramSha256,
        )
        .unwrap();

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_LOGIN);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Login);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(
                    String::from_utf8(response_bytes.clone()).unwrap(),
                    "{\"code\":200,\"message\":null,\"request\":\"Login\",\"data\":{\"authnType\":\"scramSha256\",\"message\":null}}\n");
            }
        }

        assert!(!control_plane
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated());
    }

    #[test]
    fn ctlplane_process_request_when_login_data_and_already_authed() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::ScramSha256,
        )
        .unwrap();

        let mut authenticator = MockAuthServer::new();
        authenticator
            .expect_is_authenticated()
            .times(1)
            .return_once(|| true);
        control_plane.authn_context.lock().unwrap().authenticator = Box::new(authenticator);

        let request = format!(
            r#"{} --{} "{}""#,
            request::PROTOCOL_REQUEST_LOGIN_DATA,
            request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
            AuthnMessage::Payload("data1".to_string())
                .to_json_str()
                .unwrap()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );

        let result = control_plane.process_request(&service_mgr, &request);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(
            processed_request,
            request::Request::LoginData {
                message: AuthnMessage::Payload("data1".to_string())
            }
        );

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(
                    String::from_utf8(response_bytes.clone()).unwrap(),
                    "{\"code\":200,\"message\":null,\"request\":{\"LoginData\":{\"message\":{\"payload\":\"data1\"}}},\"data\":{\"authnType\":\"scramSha256\",\"message\":\"authenticated\"}}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_login_data_and_scramsha256_authn_and_uninitialized() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::ScramSha256,
        )
        .unwrap();

        let request = format!(
            r#"{} --{} "{}""#,
            request::PROTOCOL_REQUEST_LOGIN_DATA,
            request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
            AuthnMessage::Payload("data1".to_string())
                .to_json_str()
                .unwrap()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );

        let result = control_plane.process_request(&service_mgr, &request);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(
            processed_request,
            request::Request::LoginData {
                message: AuthnMessage::Payload("data1".to_string())
            }
        );

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                let expected_response_start = "{\"code\":403,\"message\":\"Response: code=403, msg=Login process flow not initiated\"".to_string();
                let response = String::from_utf8(response_bytes.clone()).unwrap();
                assert!(response.len() > expected_response_start.len());
                assert_eq!(
                    &response[..expected_response_start.len()],
                    &expected_response_start
                );
            }
        }

        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .authn_thread_handle
            .is_none());
    }

    #[test]
    fn ctlplane_process_request_when_valid_login_data_and_scramsha256_authn_client_1st() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user.clone(),
            AuthnType::ScramSha256,
        )
        .unwrap();
        let mut authenticator =
            ScramSha256AuthenticatorServer::new(user.clone(), Duration::from_millis(10_000));
        let authn_thread_handle = authenticator.spawn_authentication();
        *control_plane.authn_context.lock().unwrap() = AuthnContext {
            authenticator: Box::new(authenticator),
            authn_thread_handle,
        };
        let mut auth_client = ScramSha256AuthenticatorClient::new(
            user.user_name.as_ref().unwrap(),
            user.password.as_ref().unwrap(),
            Duration::from_millis(100),
        );
        auth_client.spawn_authentication().unwrap();

        let client_first_msg = auth_client.exchange_messages(None).unwrap().unwrap();
        let client_first_msg_str = client_first_msg.to_json_str().unwrap();

        let request = format!(
            r#"{} --{} "{}""#,
            request::PROTOCOL_REQUEST_LOGIN_DATA,
            request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
            &client_first_msg_str
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );

        let result = control_plane.process_request(&service_mgr, &request);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(
            processed_request,
            request::Request::LoginData {
                message: client_first_msg
            }
        );

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                let expected_response_start = format!(
                    "{}{}{}",
                    "{\"code\":200,\"message\":null,\"request\":{\"LoginData\":{\"message\":",
                    &client_first_msg_str,
                    "}},\"data\":{\"authnType\":\"scramSha256\",\"message\":{\"payload\"",
                );
                let response = String::from_utf8(response_bytes.clone()).unwrap();
                assert!(response.len() > expected_response_start.len());
                assert_eq!(
                    &response[..expected_response_start.len()],
                    &expected_response_start
                );
            }
        }

        assert!(!control_plane
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated());
    }

    #[test]
    fn ctlplane_process_request_when_valid_about() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(true, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_ABOUT);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::About);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                let actual_response_str = String::from_utf8(response_bytes.clone()).unwrap();
                assert!(actual_response_str.contains(
                    "{\"code\":200,\"message\":null,\"request\":\"About\",\"data\":{\"cert_alt_subj\":\"{\\\"URI\\\": [\\\"{\\\\\\\"userId\\\\\\\":100,\\\\\\\"platform\\\\\\\":\\\\\\\"Linux\\\\\\\"}\\\"]}"));
                assert!(actual_response_str.contains(
                    "user\":{\"name\":\"user100\",\"status\":\"Active\",\"user_id\":100}"
                ));
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_connections() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(true, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result =
            control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_CONNECTIONS);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Connections);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":200,\"message\":null,\"request\":\"Connections\",\"data\":[{\"binds\":[[\"addr1\",\"addr2\"]],\"service_name\":\"Service200\"}]}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_ping() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_PING);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Ping);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(
                    String::from_utf8(response_bytes.clone()).unwrap(),
                    "{\"code\":200,\"message\":\"pong\",\"request\":\"Ping\",\"data\":null}\n"
                );
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_proxies() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, true, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, true, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_PROXIES);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Proxies);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":200,\"message\":null,\"request\":\"Proxies\",\"data\":[{\"client_port\":null,\"gateway_host\":\"proxyhost1\",\"gateway_port\":6000,\"service\":{\"address\":\"localhost:8200\",\"id\":200,\"name\":\"Service200\",\"transport\":\"TCP\"}}]}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_quit() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result = control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_QUIT);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Quit);

        let result0 = event_channel.1.try_recv();
        if let Err(err) = &result0 {
            panic!("Unexpected first channel recv result: err={:?}", err);
        }
        let result1 = event_channel.1.try_recv();
        if let Err(err) = &result1 {
            panic!("Unexpected second channel recv result: err={:?}", err);
        }

        match &result0.unwrap() {
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                panic!(
                    "Unexpected connection event: val=Write, resp={}",
                    String::from_utf8(response_bytes.clone()).unwrap()
                );
            }
            _ => {}
        }
        match &result1.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(
                    String::from_utf8(response_bytes.clone()).unwrap(),
                    "{\"code\":200,\"message\":null,\"request\":\"Quit\",\"data\":\"bye\"}\n"
                );
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_services() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, true, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let result =
            control_plane.process_request(&service_mgr, request::PROTOCOL_REQUEST_SERVICES);

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Services);

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":200,\"message\":null,\"request\":\"Services\",\"data\":[{\"address\":\"localhost:8200\",\"id\":200,\"name\":\"Service200\",\"transport\":\"TCP\"},{\"address\":\"localhost:8500\",\"id\":203,\"name\":\"chat-tcp\",\"transport\":\"TCP\"},{\"address\":\"localhost:8600\",\"id\":204,\"name\":\"echo-udp\",\"transport\":\"UDP\"},{\"address\":\"localhost:8202\",\"id\":202,\"name\":\"Service202\",\"transport\":\"TCP\"},{\"address\":\"localhost:8500\",\"id\":203,\"name\":\"chat-tcp\",\"transport\":\"TCP\"}]}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_start() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, true, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let service = model::service::Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: model::service::Transport::TCP,
            host: "localhost".to_string(),
            port: 8200,
        };

        let result = control_plane.process_request(
            &service_mgr,
            &format!(
                "{} -s {} -p {}",
                request::PROTOCOL_REQUEST_START,
                &service.name,
                3000
            ),
        );

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(
            processed_request,
            request::Request::Start {
                service_name: service.name.to_string(),
                local_port: 3000
            }
        );

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":200,\"message\":null,\"request\":{\"Start\":{\"service_name\":\"Service200\",\"local_port\":3000}},\"data\":{\"client_port\":3000,\"gateway_host\":\"proxyhost1\",\"gateway_port\":6000,\"service\":{\"address\":\"localhost:8200\",\"id\":200,\"name\":\"Service200\",\"transport\":\"TCP\"}}}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_invalid_start() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let service_name = "INVALID_SERVICE";
        let local_port = 3000;

        let result = control_plane.process_request(
            &service_mgr,
            &format!(
                "{} -s {} -p {}",
                request::PROTOCOL_REQUEST_START,
                service_name,
                local_port
            ),
        );

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(
            processed_request,
            request::Request::Start {
                service_name: service_name.to_string(),
                local_port
            }
        );

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":404,\"message\":\"Response: code=404, msg=Unknown service: svc_name=INVALID_SERVICE\",\"request\":{\"Start\":{\"service_name\":\"INVALID_SERVICE\",\"local_port\":3000}},\"data\":null}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_valid_stop() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, true);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let service_name = "Service200".to_string();

        let result = control_plane.process_request(
            &service_mgr,
            &format!("{} -s {}", request::PROTOCOL_REQUEST_STOP, &service_name),
        );

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Stop { service_name });

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":200,\"message\":null,\"request\":{\"Stop\":{\"service_name\":\"Service200\"}},\"data\":null}\n");
            }
        }
    }

    #[test]
    fn ctlplane_process_request_when_invalid_stop() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        let service_name = "INVALID_SERVICE".to_string();

        let result = control_plane.process_request(
            &service_mgr,
            &format!("{} -s {}", request::PROTOCOL_REQUEST_STOP, &service_name),
        );

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let processed_request = result.unwrap();
        assert_eq!(processed_request, request::Request::Stop { service_name });

        let result = event_channel.1.try_recv();

        if let Err(err) = &result {
            panic!("Unexpected channel recv result: err={:?}", err);
        }

        match &result.unwrap() {
            ConnectionEvent::Closing => {
                panic!("Unexpected connection event: val=Closing");
            }
            ConnectionEvent::Closed => {
                panic!("Unexpected connection event: val=Closed");
            }
            ConnectionEvent::Write(response_bytes) => {
                assert_eq!(String::from_utf8(response_bytes.clone()).unwrap(),
                           "{\"code\":404,\"message\":\"Response: code=404, msg=Unknown service: svc_name=INVALID_SERVICE\",\"request\":{\"Stop\":{\"service_name\":\"INVALID_SERVICE\"}},\"data\":null}\n");
            }
        }
    }

    #[test]
    fn ctlplane_is_authenticated_when_unauthed_scramsha256_authn() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();

        let control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::ScramSha256,
        )
        .unwrap();

        assert!(!control_plane.is_authenticated());
    }

    #[test]
    fn ctlplane_is_authenticated_when_authed_insecure_authn() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();

        let control_plane = create_control_plane(
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            device,
            user,
            AuthnType::Insecure,
        )
        .unwrap();

        assert!(control_plane.is_authenticated());
    }
}
