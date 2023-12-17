use std::sync::{Arc, Mutex};

use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;
use trust0_common::crypto::alpn::Protocol;

use trust0_common::error::AppError;
use trust0_common::net::tls_server::{conn_std, server_std};
use trust0_common::net::tls_server::conn_std::{TlsConnection, TlsServerConnection};
use crate::client::connection::ClientConnVisitor;
use crate::client::controller::ControlPlaneServerVisitor;
use crate::config::{self, AppConfig};
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy_base::GatewayServiceProxyVisitor;

/// The Trust0 Gateway TLS Server
pub struct Gateway {
    _app_config: Arc<AppConfig>,
    _server_mode: config::ServerMode,
    tls_server: server_std::Server,
    _visitor: Arc<Mutex<ServerVisitor>>
}

impl Gateway {

    /// Gateway constructor
    pub fn new(app_config: Arc<AppConfig>,
               visitor: Arc<Mutex<ServerVisitor>>
    ) -> Self {

        Self {
            _app_config: Arc::clone(&app_config),
            _server_mode: app_config.server_mode,
            tls_server: server_std::Server::new(
                visitor.clone(),
                app_config.server_port
            ),
            _visitor: visitor
        }
    }

    /// Bind/listen on port
    pub fn bind_listener(&mut self) -> Result<(), AppError> {
        self.tls_server.bind_listener()
    }

    /// Poll and dispatch new connections
    pub fn poll_new_connections(&mut self) -> Result<(), AppError> {
        self.tls_server.poll_new_connections()
    }
}

unsafe impl Send for Gateway {}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct ServerVisitor {
    app_config: Arc<AppConfig>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    control_plane_visitor: ControlPlaneServerVisitor,
    shutdown_requested: bool
}

impl ServerVisitor {

    /// ServerVisitor constructor
    pub fn new(app_config: Arc<AppConfig>,
               service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {

        Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            control_plane_visitor: ControlPlaneServerVisitor::new(app_config, service_mgr),
            shutdown_requested: false
        }
    }

    /// Get active service proxy for given service ID
    pub fn get_service_proxy(&self, service_id: u64)
        -> Result<Arc<Mutex<dyn GatewayServiceProxyVisitor>>, AppError> {

        match self.service_mgr.lock().unwrap().get_service_proxy(service_id) {

            None => Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0425_INACTIVE_SERVICE_PROXY,
                format!("Invalid service proxy: svc_id={}", service_id))),

            Some(service_proxy) => Ok(service_proxy.clone())
        }
    }

    /// Set the shutdown request state
    pub fn set_shutdown_requested(&mut self, shutdown_requested: bool) {
        self.shutdown_requested = shutdown_requested;
    }
}

impl server_std::ServerVisitor for ServerVisitor {

    fn create_client_conn(&mut self, tls_conn: TlsServerConnection) -> Result<conn_std::Connection, AppError> {

        match ClientConnVisitor::parse_alpn_protocol(&tls_conn.alpn_protocol())? {
            Protocol::ControlPlane =>
                self.control_plane_visitor.create_client_conn(tls_conn),
            Protocol::Service(service_id) =>
                self.get_service_proxy(service_id)?.lock().unwrap().create_client_conn(tls_conn)
        }
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {

        match connection.get_alpn_protocol() {
            Protocol::ControlPlane =>
                self.control_plane_visitor.on_conn_accepted(connection),
            Protocol::Service(service_id) =>
                self.get_service_proxy(*service_id)?.lock().unwrap().on_conn_accepted(connection)
        }
    }

    fn get_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}
