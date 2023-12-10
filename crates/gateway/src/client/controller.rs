use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;

use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;
use serde_json::Value;

use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use trust0_common::model;
use trust0_common::net::tls_server::conn_std::{ConnectionEvent, TlsServerConnection};
use trust0_common::net::tls_server::{conn_std, server_std};
use crate::client::connection::ClientConnVisitor;
use crate::client::device::Device;
use crate::config::AppConfig;
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;

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
    services_by_name: HashMap<String, model::service::Service>
}

impl ControlPlane {

    /// ControlPlane constructor
    pub fn new(app_config: Arc<AppConfig>,
               access_repo: Arc<Mutex<dyn AccessRepository>>,
               service_repo: Arc<Mutex<dyn ServiceRepository>>,
               user_repo: Arc<Mutex<dyn UserRepository>>,
               event_channel_sender: Sender<ConnectionEvent>,
               device: Device,
               user: model::user::User) -> Result<Self, AppError> {

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
            services_by_name
        })
    }

    /// Process given command request
    pub fn process_request(&mut self, service_mgr: &Arc<Mutex<ServiceMgr>>, command_line: &str)
        -> Result<request::Request, AppError> {

        let client_request: request::Request;
        let client_response: Result<String, AppError>;

        match self.processor.parse(command_line) {

            Ok(request::Request::About) => {
                client_request = request::Request::About;
                client_response = self.process_cmd_about();
            },
            Ok(request::Request::Connections) => {
                client_request = request::Request::Connections;
                client_response = self.process_cmd_connections(&service_mgr);
            },
            Ok(request::Request::Ping) => {
                client_request = request::Request::Ping;
                client_response = Self::prepare_response(response::CODE_OK,&Some("pong".to_string()), &client_request, &None);
            },
            Ok(request::Request::Proxies) => {
                client_request = request::Request::Proxies;
                client_response = self.process_cmd_proxies(&service_mgr);
            },
            Ok(request::Request::Services) => {
                client_request = request::Request::Services;
                client_response = self.process_cmd_services();
            },
            Ok(request::Request::Start { service_name, local_port}) => {
                client_request = request::Request::Start { service_name: service_name.clone(), local_port };
                client_response = self.process_cmd_start(&service_mgr, &service_name, local_port);
            },
            Ok(request::Request::Stop { service_name }) => {
                client_request = request::Request::Stop { service_name: service_name.clone() };
                client_response = self.process_cmd_stop(&service_mgr, &service_name );
            },
            Ok(request::Request::Quit) => {
                client_request = request::Request::Quit;
                client_response = self.process_cmd_quit();
            },
            Ok(request::Request::None) => {
                client_request = request::Request::None;
                client_response = Self::prepare_response(response::CODE_OK, &Some("".to_string()), &client_request, &None);
            }
            Err(err) => {
                client_request = request::Request::None;
                client_response = Err(err);
            }
        }

        let client_response_str = match client_response {

            Ok(response) => response,

            Err(err) => {
                let err_response: Result<String, AppError>;
                match err.get_code() {
                    Some(code) if code == response::CODE_BAD_REQUEST => {
                        err_response = Self::prepare_response(code, &None, &client_request, &None);
                    }
                    Some(code) => {
                        err_response = Self::prepare_response(code, &Some(err.to_string()), &client_request, &None);
                    }
                    _ => {
                        err_response = Self::prepare_response(
                            response::CODE_INTERNAL_SERVER_ERROR,
                            &Some(err.to_string()),
                            &client_request,
                            &None);
                    }
                }
                match err_response {
                    Ok(response) => response,
                    Err(err) => format!("Error serializing error response: err={:?}", err)
                }
            }
        };

        if !client_response_str.is_empty() {

            let client_response_str = format!("{client_response_str}\n");

            if let Err(err) = self.event_channel_sender.send(ConnectionEvent::Write(client_response_str.into_bytes())).map_err(|err|
                AppError::GenWithMsgAndErr("Error sending client stream write channel event".to_string(), Box::new(err))) {

                let _ = self.event_channel_sender.send(ConnectionEvent::Closing);

                return Err(err);
            }
        }

        return Ok(client_request);
    }

    /// Prepare response stringified JSON
    fn prepare_response(code: u16, message: &Option<String>, request: &request::Request, data: &Option<Value>)
        -> Result<String, AppError> {

        Self::jsonify(&response::Response::new(code, message, request, data))
    }

    /// Process 'about' command
    fn process_cmd_about(&self) -> Result<String, AppError> {

        let device = &self.device;
        let user_id = device.get_cert_access_context().user_id;
        let user = self.user_repo.lock().unwrap().get(user_id)?.map(|u|
            response::User::new(u.user_id, &u.name, &format!("{:?}", u.status)));

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::About,
            &Some(response::About::new(
                &Some(format!("{:?}", device.get_cert_subj())),
                &Some(format!("{:?}", device.get_cert_alt_subj())),
                &Some(format!("{:?}", device.get_cert_access_context())),
                &user
            ).try_into()?)
        )
    }

    /// Process 'connections' command
    fn process_cmd_connections(&self, service_mgr: &Arc<Mutex<ServiceMgr>>)
        -> Result<String, AppError> {

        let mask_addrs = self.app_config.mask_addresses;

        let service_proxies = service_mgr.lock().unwrap().get_service_proxies();

        let connections: Vec<Value> = service_proxies.iter()
            .map(|service_proxy| {

                let service_proxy = service_proxy.lock().unwrap();

                let proxy_addrs_list = service_proxy.get_proxy_addrs_for_user(self.user.user_id);

                let binds = proxy_addrs_list.iter()
                    .map(|proxy_addrs| {
                        if !mask_addrs {
                            vec![proxy_addrs.0.clone(), proxy_addrs.1.clone()]
                        } else {
                            vec![proxy_addrs.0.clone()]
                        }})
                    .collect();

                Some(response::Connection::new(
                            &service_proxy.get_service().name,
                            binds))
            })
            .filter_map(|connection| connection)
            .map(|connection| connection.try_into())
            .collect::<Result<Vec<Value>, AppError>>()?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Connections,
            &Some(connections.into())
        )
    }

    /// Process 'proxies' command
    fn process_cmd_proxies(&mut self, service_mgr: &Arc<Mutex<ServiceMgr>>)
        -> Result<String, AppError> {

        let user_services: HashSet<u64> = self.access_repo.lock().unwrap().get_all_for_user(self.user.user_id)?.iter()
            .map(|access| access.service_id)
            .collect();

        let service_proxies = service_mgr.lock().unwrap().get_service_proxies();

        let proxies: Vec<Value> = service_proxies.iter()
            .map(|service_proxy| {

                let service_proxy = service_proxy.lock().unwrap();
                if user_services.contains(&service_proxy.get_service().service_id) {
                    Some(response::Proxy::new(
                        &service_proxy.get_service().into(),
                        &service_proxy.get_proxy_host(),
                        service_proxy.get_proxy_port(),
                        &None).try_into())
                } else {
                    None
                }
            })
            .filter_map(|proxy| proxy)
            .collect::<Result<Vec<Value>, AppError>>()?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Proxies,
            &Some(proxies.into())
        )
    }

    /// Process 'services' command
    fn process_cmd_services(&mut self)
        -> Result<String, AppError> {

        let mask_addrs  = self.app_config.mask_addresses;

        let user_services: Vec<Value> = self.access_repo.lock().unwrap().get_all_for_user(self.user.user_id)?.iter()
            .map(|access| self.services_by_id.get(&access.service_id))
            .flatten()
            .map(|service| {
                let service = Self::prepare_response_service(service, mask_addrs);
                service.try_into()
            })
            .collect::<Result<Vec<Value>, AppError>>()?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Services,
            &Some(user_services.into())
        )
    }

    /// Process 'start' command
    fn process_cmd_start(&mut self, service_mgr: &Arc<Mutex<ServiceMgr>>, service_name: &str, local_port: u16)
        -> Result<String, AppError> {

        // Validate requested service is valid and user is authorized
        let service = self.services_by_name.get(service_name).ok_or(
            AppError::GenWithCodeAndMsg(
                response::CODE_NOT_FOUND,
                format!("Unknown service: svc_name={}", service_name)))?;

        if self.access_repo.lock().unwrap().get(self.user.user_id, service.service_id)?.is_none() {
            return Err(AppError::GenWithCodeAndMsg(
                response::CODE_FORBIDDEN,
                format!("User is not authorized for service: user_id={}, svc_id={}", self.user.user_id, service.service_id)));
        }

        // Start up service proxy
        let service_mgr_copy = service_mgr.clone();
        let (gateway_service_host, gateway_service_port)
            = service_mgr.lock().unwrap().startup(service_mgr_copy, service)?;

        // Return service proxy connection
        let service = Self::prepare_response_service(service, self.app_config.mask_addresses);

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Start { service_name: service_name.to_string(), local_port },
            &Some(response::Proxy::new(
                &service,
                &gateway_service_host,
                gateway_service_port,
                &Some(local_port)).try_into()?)
        )
    }

    /// Process 'stop' command
    fn process_cmd_stop(&mut self, service_mgr: &Arc<Mutex<ServiceMgr>>, service_name: &str)
        -> Result<String, AppError> {

        // Validate requested service is valid and proxy is currently active
        let service = self.services_by_name.get(service_name).ok_or(
            AppError::GenWithCodeAndMsg(
                response::CODE_NOT_FOUND,
                format!("Unknown service: svc_name={}", service_name)))?;

        if !service_mgr.lock().unwrap().has_proxy_for_user_and_service(self.user.user_id, service.service_id) {
            return Err(AppError::GenWithCodeAndMsg(
                response::CODE_NOT_FOUND,
                format!("No active proxy found: user_id={}, svc_id={}", self.user.user_id, service.service_id)));
        }

        // Shutdown service proxy
        service_mgr.lock().unwrap().shutdown_connections(Some(self.user.user_id), Some(service.service_id))?;

        // Return service proxy connection
        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Stop { service_name: service_name.to_string() },
            &None
        )
    }

    /// Process 'quit' command
    fn process_cmd_quit(&self)
        -> Result<String, AppError> {

        self.event_channel_sender.send(ConnectionEvent::Closing).map_err(|err|
            AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err)))?;

        Self::prepare_response(
            response::CODE_OK,
            &None,
            &request::Request::Quit,
            &Some("bye".into())
        )
    }

    /// Convert model service to response service
    fn prepare_response_service(service: &model::service::Service, mask_addrs: bool) -> response::Service {

        let mut service = service.clone();
        if mask_addrs {
            service.host.clear();
            service.port = 0;
        }
        service.into()
    }

    /// Serialize object to JSON
    fn jsonify<T: serde::Serialize>(object: &T) -> Result<String, AppError> {

        serde_json::to_string(&object).map_err(|err|
            AppError::GenWithMsgAndErr("Error serializing response".to_string(), Box::new(err)))
    }

    /// Setup services maps
    fn setup_services_maps(service_repo: &Arc<Mutex<dyn ServiceRepository>>)
        -> Result<(HashMap<u64, model::service::Service>, HashMap<String, model::service::Service>), AppError> {

        let services = service_repo.lock().unwrap().get_all()?;
        let services_by_id: HashMap<u64, model::service::Service> = services.iter()
            .map(|service| (service.service_id, service.clone())).collect();
        let services_by_name: HashMap<String, model::service::Service> = services.iter()
            .map(|service| (service.name.clone(), service.clone())).collect();

        Ok((services_by_id, services_by_name))
    }
}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct ControlPlaneServerVisitor {
    app_config: Arc<AppConfig>,
    service_mgr: Arc<Mutex<ServiceMgr>>
}

impl ControlPlaneServerVisitor {

    /// ServerVisitor constructor
    pub fn new(app_config: Arc<AppConfig>,
               service_mgr: Arc<Mutex<ServiceMgr>>) -> Self {

        Self {
            app_config,
            service_mgr
        }
    }
}

impl server_std::ServerVisitor for ControlPlaneServerVisitor {

    fn create_client_conn(&mut self, tls_conn: TlsServerConnection) -> Result<conn_std::Connection, AppError> {

        let mut conn_visitor = ClientConnVisitor::new(
            self.app_config.clone(),
            self.service_mgr.clone());

        let alpn_protocol = conn_visitor.process_authorization(&tls_conn, None)?;

        let connection = conn_std::Connection::new(Box::new(conn_visitor), tls_conn, alpn_protocol)?;

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
