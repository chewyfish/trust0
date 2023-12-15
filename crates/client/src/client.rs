use std::sync::{Arc, Mutex};

use anyhow::Result;
use trust0_common::crypto::alpn;

use trust0_common::error::AppError;
use trust0_common::net::tls_client::{client_std, conn_std};
use crate::config::AppConfig;
use crate::gateway::connection::ServerConnVisitor;
use crate::service::manager::ServiceMgr;

/// The Trust0 Gateway TLS Client
pub struct Client {
    _app_config: Arc<AppConfig>,
    tls_client: client_std::Client
}

impl Client {

    /// Client constructor
    pub fn new(app_config: Arc<AppConfig>,
               service_mgr: Arc<Mutex<dyn ServiceMgr>>)
        -> Self {

        let mut tls_client_config = app_config.tls_client_config.clone();
        tls_client_config.alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        Self {
            _app_config: app_config.clone(),
            tls_client: client_std::Client::new(
                Box::new(ClientVisitor::new(app_config.clone(), service_mgr)),
                tls_client_config,
                app_config.gateway_host.to_string(),
                app_config.gateway_port)
        }
    }

    /// Connect to gateway
    pub fn connect(&mut self) -> Result<(), AppError> {
        self.tls_client.connect()
    }

    /// Poll connection events
    pub fn poll_connection(&mut self) -> Result<(), AppError> {
        self.tls_client.poll_connection()
    }
}

unsafe impl Send for Client {}

/// tls_client::std_client::Client strategy visitor pattern implementation
pub struct ClientVisitor {
    app_config: Arc<AppConfig>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>
}

impl ClientVisitor {

    /// ClientVisitor constructor
    pub fn new(app_config: Arc<AppConfig>,
               service_mgr: Arc<Mutex<dyn ServiceMgr>>)
        -> Self {

        Self {
            app_config,
            service_mgr
        }
    }
}

impl client_std::ClientVisitor for ClientVisitor {

    fn create_server_conn(&mut self, tls_conn: conn_std::TlsClientConnection) -> Result<conn_std::Connection, AppError> {

        let conn_visitor = ServerConnVisitor::new(self.app_config.clone(), self.service_mgr.clone())?;
        let connection = conn_std::Connection::new(Box::new(conn_visitor), tls_conn)?;

        Ok(connection)
    }
}
