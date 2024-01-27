use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

use crate::client::controller::ChannelProcessor;
use crate::client::device::Device;
use crate::config::AppConfig;
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;
use trust0_common::authn::authenticator::{AuthenticatorServer, AuthnMessage, AuthnType};
use trust0_common::authn::insecure_authenticator::InsecureAuthenticatorServer;
use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorServer;
use trust0_common::control::management;
use trust0_common::control::message::MessageFrame;
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::net::tls_server::conn_std;
use trust0_common::{control, model, target};

/// (MFA) Authentication context
struct AuthnContext {
    authenticator: Box<dyn AuthenticatorServer>,
    authn_thread_handle: Option<JoinHandle<Result<AuthnMessage, AppError>>>,
}

/// Process control plane management commands. Clients use a connection REPL shell to issue requests.
pub struct ManagementController {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Management control plane message processor
    _management_processor: management::request::RequestProcessor,
    /// Access DB repository
    access_repo: Arc<Mutex<dyn AccessRepository>>,
    /// Service DB repository
    _service_repo: Arc<Mutex<dyn ServiceRepository>>,
    /// User DB repository
    user_repo: Arc<Mutex<dyn UserRepository>>,
    /// Channel sender for connection events
    event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
    /// Certificate device context
    device: Device,
    /// User model object
    user: model::user::User,
    /// Queued PDU responses to be sent to client
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Context for an ongoing/past secondary authentication
    authn_context: Rc<Mutex<AuthnContext>>,
    /// Map of services (by service ID)
    services_by_id: HashMap<u64, model::service::Service>,
    /// Map of services (by service name)
    services_by_name: HashMap<String, model::service::Service>,
}

impl ManagementController {
    /// ControlPlane constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    /// * `access_repo` - Access DB repository
    /// * `service_repo` - Service DB repository
    /// * `user_repo` - User DB repository
    /// * `event_channel_sender` - Channel sender for connection events
    /// * `device` - Certificate device context
    /// * `user` - User model object
    /// * `message_outbox` - Queued PDU responses to be sent to client
    ///
    /// # Returns
    ///
    /// a [`Result`] containing a newly constructed [`ManagementController`] object.
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        access_repo: Arc<Mutex<dyn AccessRepository>>,
        service_repo: Arc<Mutex<dyn ServiceRepository>>,
        user_repo: Arc<Mutex<dyn UserRepository>>,
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
        device: Device,
        user: model::user::User,
        message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
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
            service_mgr,
            _management_processor: management::request::RequestProcessor::new(),
            access_repo,
            _service_repo: service_repo,
            user_repo,
            event_channel_sender,
            device,
            user,
            message_outbox,
            authn_context: Rc::new(Mutex::new(AuthnContext {
                authenticator,
                authn_thread_handle: None,
            })),
            services_by_id,
            services_by_name,
        })
    }

    /// Process 'about' command
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the About request.
    ///
    fn process_cmd_about(&self) -> Result<management::response::Response, AppError> {
        let device = &self.device;
        let user_id = device.get_cert_access_context().user_id;
        let user = self.user_repo.lock().unwrap().get(user_id)?.map(|u| {
            management::response::User::new(u.user_id, &u.name, &format!("{:?}", u.status))
        });

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::About,
            &Some(
                management::response::About::new(
                    &Some(format!("{:?}", device.get_cert_subj())),
                    &Some(format!("{:?}", device.get_cert_alt_subj())),
                    &Some(format!("{:?}", device.get_cert_access_context())),
                    &user,
                )
                .try_into()?,
            ),
        ))
    }

    /// Process 'login' command
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the Login request.
    ///
    fn process_cmd_login(&self) -> Result<management::response::Response, AppError> {
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

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Login,
            &Some(
                management::response::LoginData::new(
                    self.app_config.mfa_scheme.clone(),
                    response_authn_msg,
                )
                .try_into()?,
            ),
        ))
    }

    /// Process 'login-data' command
    ///
    /// # Arguments
    ///
    /// * `authn_msg` - Authentication message for the current authn flow.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the given LoginData request.
    ///
    fn process_cmd_login_data(
        &self,
        authn_msg: AuthnMessage,
    ) -> Result<management::response::Response, AppError> {
        let mut authn_context = self.authn_context.lock().unwrap();

        let response_authn_msg = if authn_context.authenticator.is_authenticated() {
            Some(AuthnMessage::Authenticated)
        } else if authn_context.authn_thread_handle.is_none() {
            return Err(AppError::GenWithCodeAndMsg(
                control::message::CODE_FORBIDDEN,
                "Login process flow not initiated".to_string(),
            ));
        } else {
            authn_context
                .authenticator
                .exchange_messages(Some(authn_msg.clone()))?
        };

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::LoginData {
                message: authn_msg.clone(),
            },
            &Some(
                management::response::LoginData::new(
                    self.app_config.mfa_scheme.clone(),
                    response_authn_msg,
                )
                .try_into()?,
            ),
        ))
    }

    /// Process 'connections' command
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the Connections request.
    ///
    fn process_cmd_connections(&self) -> Result<management::response::Response, AppError> {
        let mask_addrs = self.app_config.mask_addresses;

        let service_proxies = self.service_mgr.lock().unwrap().get_service_proxies();

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

                management::response::Connection::new(&service_proxy.get_service().name, binds)
                    .try_into()
            })
            .collect::<Result<Vec<Value>, AppError>>()?;

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Connections,
            &Some(connections.into()),
        ))
    }

    /// Process 'proxies' command
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the Proxies request.
    ///
    fn process_cmd_proxies(&mut self) -> Result<management::response::Response, AppError> {
        let user_services: HashSet<u64> = self
            .access_repo
            .lock()
            .unwrap()
            .get_all_for_user(&self.user)?
            .iter()
            .map(|access| access.service_id)
            .collect();

        let service_proxies = self.service_mgr.lock().unwrap().get_service_proxies();

        let proxies: Vec<Value> = service_proxies
            .iter()
            .filter_map(|service_proxy| {
                let service_proxy = service_proxy.lock().unwrap();
                let service = service_proxy.get_service();
                if user_services.contains(&service.service_id) {
                    Some(
                        management::response::Proxy::new(
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

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Proxies,
            &Some(proxies.into()),
        ))
    }

    /// Process 'services' command
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the Services request.
    ///
    fn process_cmd_services(&mut self) -> Result<management::response::Response, AppError> {
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

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Services,
            &Some(user_services.into()),
        ))
    }

    /// Process 'start' command
    ///
    /// # Arguments
    ///
    /// * `service_name` - The proxy's service name
    /// * `local_port` - The client port to accept connections for proxy
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the given Start request.
    ///
    fn process_cmd_start(
        &mut self,
        service_name: &str,
        local_port: u16,
    ) -> Result<management::response::Response, AppError> {
        // Validate requested service is valid and user is authorized
        let service =
            self.services_by_name
                .get(service_name)
                .ok_or(AppError::GenWithCodeAndMsg(
                    control::message::CODE_NOT_FOUND,
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
                control::message::CODE_FORBIDDEN,
                format!(
                    "User is not authorized for service: user_id={}, svc_id={}",
                    self.user.user_id, service.service_id
                ),
            ));
        }

        // Start up service proxy
        let service_mgr_copy = self.service_mgr.clone();
        let (gateway_service_host, gateway_service_port) = self
            .service_mgr
            .lock()
            .unwrap()
            .startup(service_mgr_copy, service)?;

        // Return service proxy connection
        let service = Self::prepare_response_service(service, self.app_config.mask_addresses);

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Start {
                service_name: service_name.to_string(),
                local_port,
            },
            &Some(
                management::response::Proxy::new(
                    &service,
                    &gateway_service_host,
                    gateway_service_port,
                    &Some(local_port),
                )
                .try_into()?,
            ),
        ))
    }

    /// Process 'stop' command
    ///
    /// # Arguments
    ///
    /// * `service_name` - The proxy's service name
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the given Stop request.
    ///
    fn process_cmd_stop(
        &mut self,
        service_name: &str,
    ) -> Result<management::response::Response, AppError> {
        // Validate requested service is valid and proxy is currently active
        let service =
            self.services_by_name
                .get(service_name)
                .ok_or(AppError::GenWithCodeAndMsg(
                    control::message::CODE_NOT_FOUND,
                    format!("Unknown service: svc_name={}", service_name),
                ))?;

        if !self
            .service_mgr
            .lock()
            .unwrap()
            .has_proxy_for_user_and_service(self.user.user_id, service.service_id)
        {
            return Err(AppError::GenWithCodeAndMsg(
                control::message::CODE_NOT_FOUND,
                format!(
                    "No active proxy found: user_id={}, svc_id={}",
                    self.user.user_id, service.service_id
                ),
            ));
        }

        // Shutdown service proxy
        self.service_mgr
            .lock()
            .unwrap()
            .shutdown_connections(Some(self.user.user_id), Some(service.service_id))?;

        // Return service proxy connection
        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Stop {
                service_name: service_name.to_string(),
            },
            &None,
        ))
    }

    /// Process 'quit' command
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`management::response::Response`] object for the Quit request.
    ///
    fn process_cmd_quit(&self) -> Result<management::response::Response, AppError> {
        self.event_channel_sender
            .send(conn_std::ConnectionEvent::Closing)
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err))
            })?;

        Ok(management::response::Response::new(
            control::message::CODE_OK,
            &None,
            &management::request::Request::Quit,
            &Some("bye".into()),
        ))
    }

    /// Protected (authenticated) resource guard
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating whether authenticated or not.
    ///
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
                control::message::CODE_FORBIDDEN,
                format!(
                    "Not authenticated, please perform the '{}' request flow first",
                    management::request::PROTOCOL_REQUEST_LOGIN
                ),
            ))
        }
    }

    /// Convert model service to response service
    ///
    /// # Arguments
    ///
    /// * `service` - Service model object
    /// * `mask_addrs` - whether or not hide address information from client
    ///
    /// # Returns
    ///
    /// A service response object appropriate for the client connection.
    ///
    fn prepare_response_service(
        service: &model::service::Service,
        mask_addrs: bool,
    ) -> management::response::Service {
        let mut service = service.clone();
        if mask_addrs {
            service.host.clear();
            service.port = 0;
        }
        service.into()
    }

    /// Setup services maps
    ///
    /// # Arguments
    ///
    /// * `service_repo` - Service DB repository
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a tuple of 2 maps:
    ///
    /// * Service model object, keyed on service ID
    /// * Service model object, keyed on service name
    ///
    #[allow(clippy::complexity)]
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

unsafe impl Send for ManagementController {}

impl ChannelProcessor for ManagementController {
    fn process_inbound_messages(&mut self, message: MessageFrame) -> Result<(), AppError> {
        let request_str = format!("{:?}", &message);
        let client_request;
        let client_response: Result<management::response::Response, AppError>;

        // Process request
        match message.try_into() {
            Ok(management::request::Request::About) => {
                client_request = management::request::Request::About;
                client_response = self.process_cmd_about();
            }
            Ok(management::request::Request::Connections) => {
                client_request = management::request::Request::Connections;
                client_response = self
                    .assert_authenticated()
                    .and(self.process_cmd_connections());
            }
            Ok(management::request::Request::Ignore) => return Ok(()),
            Ok(management::request::Request::Login) => {
                client_request = management::request::Request::Login;
                client_response = self.process_cmd_login();
            }
            Ok(management::request::Request::LoginData { message: authn_msg }) => {
                client_request = management::request::Request::LoginData {
                    message: authn_msg.clone(),
                };
                client_response = self.process_cmd_login_data(authn_msg);
            }
            Ok(management::request::Request::Ping) => {
                client_request = management::request::Request::Ping;
                client_response = Ok(management::response::Response::new(
                    control::message::CODE_OK,
                    &Some("pong".to_string()),
                    &management::request::Request::Ping,
                    &None,
                ));
            }
            Ok(management::request::Request::Proxies) => {
                client_request = management::request::Request::Proxies;
                client_response = self.assert_authenticated().and(self.process_cmd_proxies());
            }
            Ok(management::request::Request::Services) => {
                client_request = management::request::Request::Services;
                client_response = self.assert_authenticated().and(self.process_cmd_services());
            }
            Ok(management::request::Request::Start {
                service_name,
                local_port,
            }) => {
                client_request = management::request::Request::Start {
                    service_name: service_name.clone(),
                    local_port,
                };
                client_response = self
                    .assert_authenticated()
                    .and(self.process_cmd_start(&service_name, local_port));
            }
            Ok(management::request::Request::Stop { service_name }) => {
                client_request = management::request::Request::Stop {
                    service_name: service_name.clone(),
                };
                client_response = self
                    .assert_authenticated()
                    .and(self.process_cmd_stop(&service_name));
            }
            Ok(management::request::Request::Quit) => {
                client_request = management::request::Request::Quit;
                client_response = self.process_cmd_quit();
            }
            Ok(management::request::Request::None) => {
                client_request = management::request::Request::None;
                client_response = Ok(management::response::Response::new(
                    control::message::CODE_OK,
                    &Some("".to_string()),
                    &management::request::Request::None,
                    &None,
                ));
            }
            Err(err) => {
                client_request = management::request::Request::None;
                client_response = Err(err);
            }
        }

        // Queue response PDU
        let response_msg_frame = match client_response {
            Ok(response) => response.try_into()?,
            Err(err) => {
                error(
                    &target!(),
                    &format!(
                        "Error processing management request: req={:?}, err={:?}",
                        &request_str, &err
                    ),
                );
                let request_context = serde_json::to_value(client_request).ok();
                match err.get_code() {
                    Some(code) if code == control::message::CODE_BAD_REQUEST => MessageFrame::new(
                        control::message::ControlChannel::Management,
                        code,
                        &None,
                        &request_context,
                        &None,
                    ),
                    Some(code) => MessageFrame::new(
                        control::message::ControlChannel::Management,
                        code,
                        &Some(err.to_string()),
                        &request_context,
                        &None,
                    ),
                    _ => MessageFrame::new(
                        control::message::ControlChannel::Management,
                        control::message::CODE_INTERNAL_SERVER_ERROR,
                        &Some(err.to_string()),
                        &request_context,
                        &None,
                    ),
                }
            }
        };

        self.message_outbox
            .lock()
            .unwrap()
            .push_back(response_msg_frame.build_pdu()?);

        Ok(())
    }

    fn is_authenticated(&self) -> bool {
        self.authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated()
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::client::controller::tests::{create_device, create_user};
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::tests::MockSvcMgr;
    use crate::service::proxy::proxy_base::tests::MockGwSvcProxyVisitor;
    use mockall::{mock, predicate};
    use serde_json::json;
    use std::sync::mpsc;
    use trust0_common::authn::authenticator::{AuthenticatorClient, AuthenticatorServer};
    use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorClient;
    use trust0_common::control::message::ControlChannel;
    use trust0_common::model::access::{EntityType, ServiceAccess};

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

    // utils
    // =====

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

    fn create_controller(
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
        user_repo: &Arc<Mutex<dyn UserRepository>>,
        service_repo: &Arc<Mutex<dyn ServiceRepository>>,
        access_repo: &Arc<Mutex<dyn AccessRepository>>,
        mfa_scheme: AuthnType,
        message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Result<ManagementController, AppError> {
        let mut app_config = config::tests::create_app_config_with_repos(
            user_repo.clone(),
            service_repo.clone(),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            access_repo.clone(),
        )?;
        app_config.mfa_scheme = mfa_scheme;

        Ok(ManagementController::new(
            Arc::new(app_config),
            service_mgr,
            access_repo.clone(),
            service_repo.clone(),
            user_repo.clone(),
            event_channel_sender,
            create_device().unwrap(),
            create_user(),
            message_outbox,
        )?)
    }

    fn assert_msg_frame_pdu_equality(
        pending_pdus: &Arc<Mutex<VecDeque<Vec<u8>>>>,
        expected_pdu: Vec<u8>,
        max_msg_size: Option<usize>,
    ) {
        assert!(!pending_pdus.lock().unwrap().is_empty());

        let pdu = pending_pdus.lock().unwrap().get(0).unwrap().clone();
        assert!(pdu.len() >= 3);
        assert!(expected_pdu.len() >= 3);

        let (msg_size, msg) = pdu.split_at(std::mem::size_of::<u16>());
        let pdu_msg_size = u16::from_be_bytes(msg_size.try_into().unwrap());
        let mut pdu_msg = String::from_utf8(msg.to_vec()).unwrap();

        let (expected_msg_size, expected_msg) = expected_pdu.split_at(std::mem::size_of::<u16>());
        let expected_pdu_msg_size = u16::from_be_bytes(expected_msg_size.try_into().unwrap());
        let mut expected_pdu_msg = String::from_utf8(expected_msg.to_vec()).unwrap();

        if max_msg_size.is_some() {
            println!("PM:{}", &pdu_msg);
            if pdu_msg.len() > max_msg_size.unwrap() {
                pdu_msg = pdu_msg[0..max_msg_size.unwrap()].to_string();
            }
            if expected_pdu_msg.len() > max_msg_size.unwrap() {
                expected_pdu_msg = expected_pdu_msg[0..max_msg_size.unwrap()].to_string();
            }
        }

        assert_eq!(pdu_msg, expected_pdu_msg);

        if max_msg_size.is_none() {
            assert_eq!(pdu_msg_size, expected_pdu_msg_size);
        }
    }

    fn assert_msg_frame_pdu_contains(
        pending_pdus: &Arc<Mutex<VecDeque<Vec<u8>>>>,
        expected_pdu_section: &str,
    ) {
        assert!(!pending_pdus.lock().unwrap().is_empty());

        let pdu = pending_pdus.lock().unwrap().get(0).unwrap().clone();
        assert!(pdu.len() >= 3);

        let (msg_size, msg) = pdu.split_at(std::mem::size_of::<u16>());
        let _pdu_msg_size = u16::from_be_bytes(msg_size.try_into().unwrap());
        let pdu_msg = String::from_utf8(msg.to_vec()).unwrap();

        assert!(pdu_msg.contains(expected_pdu_section));
    }

    // tests
    // =====

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_login_and_already_authed() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let mut authenticator = MockAuthServer::new();
        authenticator
            .expect_is_authenticated()
            .times(1)
            .return_once(|| true);
        controller.authn_context.lock().unwrap().authenticator = Box::new(authenticator);

        let request_json = serde_json::to_value(management::request::Request::Login).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_LOGIN.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!({"authnType":"insecure","message":"authenticated"})),
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_login_and_insecure_authn() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Login).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_LOGIN.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!({"authnType":"insecure","message":"authenticated"})),
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);

        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated());
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_login_and_scramsha256_authn() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::ScramSha256,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Login).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_LOGIN.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!({"authnType":"scramSha256","message":null})),
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);

        assert!(!controller
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated());
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_login_data_and_already_authed() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::ScramSha256,
            message_outbox.clone(),
        )
        .unwrap();

        let mut authenticator = MockAuthServer::new();
        authenticator
            .expect_is_authenticated()
            .times(1)
            .return_once(|| true);
        controller.authn_context.lock().unwrap().authenticator = Box::new(authenticator);

        let request_json = serde_json::to_value(management::request::Request::LoginData {
            message: AuthnMessage::Payload("data1".to_string()),
        })
        .unwrap();

        let request_cmd = format!(
            r#"{} --{} "{}""#,
            management::request::PROTOCOL_REQUEST_LOGIN_DATA,
            management::request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
            AuthnMessage::Payload("data1".to_string())
                .to_json_str()
                .unwrap()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );
        let request_cmd_json = Value::String(request_cmd);

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!({"authnType":"scramSha256","message":"authenticated"})),
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_login_data_and_scramsha256_authn_and_uninitialized()
    {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::ScramSha256,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::LoginData {
            message: AuthnMessage::Payload("data1".to_string()),
        })
        .unwrap();

        let request_cmd = format!(
            r#"{} --{} "{}""#,
            management::request::PROTOCOL_REQUEST_LOGIN_DATA,
            management::request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
            AuthnMessage::Payload("data1".to_string())
                .to_json_str()
                .unwrap()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );

        let request_cmd_json = Value::String(request_cmd);

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_FORBIDDEN,
            &Some("Response: code=403, msg=Login process flow not initiated".to_string()),
            &Some(request_json),
            &None,
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);

        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .authn_thread_handle
            .is_none());
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_login_data_and_scramsha256_authn_client_1st()
    {
        let user = create_user();
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::ScramSha256,
            message_outbox.clone(),
        )
        .unwrap();
        let mut authenticator =
            ScramSha256AuthenticatorServer::new(user.clone(), Duration::from_millis(10_000));
        let authn_thread_handle = authenticator.spawn_authentication();
        *controller.authn_context.lock().unwrap() = AuthnContext {
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

        let request_json = serde_json::to_value(management::request::Request::LoginData {
            message: AuthnMessage::Payload("ignore".to_string()),
        })
        .unwrap();

        let request_cmd = format!(
            r#"{} --{} "{}""#,
            management::request::PROTOCOL_REQUEST_LOGIN_DATA,
            management::request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
            &client_first_msg_str
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );

        let request_cmd_json = Value::String(request_cmd);

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &None,
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, Some(94));

        assert!(!controller
            .authn_context
            .lock()
            .unwrap()
            .authenticator
            .is_authenticated());
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_about() {
        let repos = create_repos(true, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_ABOUT.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        assert_msg_frame_pdu_contains(
            &message_outbox,
            r#"{"channel":"Management","code":200,"message":null,"context":"About","data":{"cert_alt_subj"#,
        );
        assert_msg_frame_pdu_contains(
            &message_outbox,
            r#""user":{"name":"user100","status":"Active","user_id":100}"#,
        );
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_connections() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(true, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Connections).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_CONNECTIONS.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!([{"binds":[["addr1","addr2"]],"service_name":"Service200"}])),
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_ping() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Ping).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_PING.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &Some("pong".to_string()),
            &Some(request_json),
            &None,
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_proxies() {
        let repos = create_repos(false, true, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, true, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Proxies).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_PROXIES.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!([{"client_port":null,"gateway_host":"proxyhost1","gateway_port":6000,"service":{"address":"localhost:8200","id":200,"name":"Service200","transport":"TCP"}}])),
        ).build_pdu().unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_quit() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Quit).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_QUIT.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(Value::String("bye".to_string())),
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_services() {
        let repos = create_repos(false, true, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Services).unwrap();
        let request_cmd_json =
            Value::String(management::request::PROTOCOL_REQUEST_SERVICES.to_string());

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!([{"address":"localhost:8200","id":200,"name":"Service200","transport":"TCP"},{"address":"localhost:8500","id":203,"name":"chat-tcp","transport":"TCP"},{"address":"localhost:8600","id":204,"name":"echo-udp","transport":"UDP"},{"address":"localhost:8202","id":202,"name":"Service202","transport":"TCP"},{"address":"localhost:8500","id":203,"name":"chat-tcp","transport":"TCP"}])),
        ).build_pdu().unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_start() {
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, true, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Start {
            service_name: "Service200".to_string(),
            local_port: 3000,
        })
        .unwrap();
        let request_cmd_json = Value::String(format!(
            "{} -s {} -p {}",
            management::request::PROTOCOL_REQUEST_START,
            "Service200",
            3000
        ));

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &Some(json!({"client_port":3000,"gateway_host":"proxyhost1","gateway_port":6000,"service":{"address":"localhost:8200","id":200,"name":"Service200","transport":"TCP"}})),
        ).build_pdu().unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_invalid_start() {
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Start {
            service_name: "INVALID_SERVICE".to_string(),
            local_port: 3000,
        })
        .unwrap();
        let request_cmd_json = Value::String(format!(
            "{} -s {} -p {}",
            management::request::PROTOCOL_REQUEST_START,
            "INVALID_SERVICE",
            3000
        ));

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_NOT_FOUND,
            &Some("Response: code=404, msg=Unknown service: svc_name=INVALID_SERVICE".to_string()),
            &Some(request_json),
            &None,
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_valid_stop() {
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, true);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Stop {
            service_name: "Service200".to_string(),
        })
        .unwrap();
        let request_cmd_json = Value::String(format!(
            "{} -s {}",
            management::request::PROTOCOL_REQUEST_STOP,
            "Service200",
        ));

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &Some(request_json),
            &None,
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_process_inbound_messages_when_invalid_stop() {
        let repos = create_repos(false, false, true);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        let request_json = serde_json::to_value(management::request::Request::Stop {
            service_name: "INVALID_SERVICE".to_string(),
        })
        .unwrap();
        let request_cmd_json = Value::String(format!(
            "{} -s {}",
            management::request::PROTOCOL_REQUEST_STOP,
            "INVALID_SERVICE",
        ));

        let result = controller.process_inbound_messages(MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_OK,
            &None,
            &None,
            &Some(request_cmd_json.clone()),
        ));

        if let Err(err) = &result {
            panic!("Unexpected process request result: err={:?}", err);
        }

        let expected_response_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::message::CODE_NOT_FOUND,
            &Some("Response: code=404, msg=Unknown service: svc_name=INVALID_SERVICE".to_string()),
            &Some(request_json),
            &None,
        )
        .build_pdu()
        .unwrap();

        assert_msg_frame_pdu_equality(&message_outbox, expected_response_pdu, None);
    }

    #[test]
    fn mgtcontrol_is_authenticated_when_unauthed_scramsha256_authn() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::ScramSha256,
            message_outbox.clone(),
        )
        .unwrap();

        assert!(!controller.is_authenticated());
    }

    #[test]
    fn mgtcontrol_is_authenticated_when_authed_insecure_authn() {
        let repos = create_repos(false, false, false);
        let event_channel = mpsc::channel();
        let service_mgr = create_service_mgr(false, false, false, false);
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let controller = create_controller(
            service_mgr,
            event_channel.0,
            &repos.0,
            &repos.1,
            &repos.2,
            AuthnType::Insecure,
            message_outbox.clone(),
        )
        .unwrap();

        assert!(controller.is_authenticated());
    }
}
