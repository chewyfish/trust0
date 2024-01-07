use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

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
use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use trust0_common::model;
use trust0_common::net::tls_server::conn_std::{ConnectionEvent, TlsServerConnection};
use trust0_common::net::tls_server::{conn_std, server_std};

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

        Ok(Self {
            app_config,
            processor: request::RequestProcessor::new(),
            access_repo,
            _service_repo: service_repo,
            user_repo,
            event_channel_sender,
            device,
            user,
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
                client_response = self.process_cmd_connections(service_mgr);
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
                client_response = self.process_cmd_proxies(service_mgr);
            }
            Ok(request::Request::Services) => {
                client_request = request::Request::Services;
                client_response = self.process_cmd_services();
            }
            Ok(request::Request::Start {
                service_name,
                local_port,
            }) => {
                client_request = request::Request::Start {
                    service_name: service_name.clone(),
                    local_port,
                };
                client_response = self.process_cmd_start(service_mgr, &service_name, local_port);
            }
            Ok(request::Request::Stop { service_name }) => {
                client_request = request::Request::Stop {
                    service_name: service_name.clone(),
                };
                client_response = self.process_cmd_stop(service_mgr, &service_name);
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
}

pub trait RequestProcessor {
    /// Process given command request
    fn process_request(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        command_line: &str,
    ) -> Result<request::Request, AppError>;
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

        // TODO
        // .... authenticate_cert
        // .... authenticate_mfa
        // .... authorize_service

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
mod tests {
    use super::*;
    use crate::client::controller::RequestProcessor;
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::tests::MockSvcMgr;
    use crate::service::proxy::proxy_base::tests::MockGwSvcProxyVisitor;
    use mockall::predicate;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use trust0_common::crypto::file::load_certificates;
    use trust0_common::model::access::{EntityType, ServiceAccess};

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];

    fn create_device() -> Result<Device, AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().unwrap().to_string())?;
        Device::new(certs)
    }

    fn create_user() -> model::user::User {
        model::user::User {
            user_id: 100,
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
    ) -> Result<ControlPlane, AppError> {
        let app_config = Arc::new(config::tests::create_app_config_with_repos(
            user_repo.clone(),
            service_repo.clone(),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            access_repo.clone(),
        )?);

        Ok(ControlPlane::new(
            app_config,
            access_repo.clone(),
            service_repo.clone(),
            user_repo.clone(),
            event_channel_sender,
            device,
            user,
        )?)
    }

    #[test]
    fn ctlplane_process_request_when_valid_about() {
        let device = create_device().unwrap();
        let user = create_user();
        let repos = create_repos(true, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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

        let mut control_plane =
            create_control_plane(event_channel.0, &repos.0, &repos.1, &repos.2, device, user)
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
}
