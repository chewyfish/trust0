use std::sync::{Arc, Mutex};

use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;

use crate::client::connection::ClientConnVisitor;
use crate::client::controller::ControlPlaneServerVisitor;
use crate::config::{self, AppConfig};
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy_base::GatewayServiceProxyVisitor;
use trust0_common::crypto::alpn::Protocol;
use trust0_common::error::AppError;
use trust0_common::net::tls_server::conn_std::{TlsConnection, TlsServerConnection};
use trust0_common::net::tls_server::{conn_std, server_std};

/// The Trust0 Gateway TLS Server
pub struct Gateway {
    _app_config: Arc<AppConfig>,
    tls_server: server_std::Server,
    _visitor: Arc<Mutex<ServerVisitor>>,
}

impl Gateway {
    /// Gateway constructor
    pub fn new(app_config: Arc<AppConfig>, visitor: Arc<Mutex<ServerVisitor>>) -> Self {
        Self {
            _app_config: Arc::clone(&app_config),
            tls_server: server_std::Server::new(visitor.clone(), app_config.server_port),
            _visitor: visitor,
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
    shutdown_requested: bool,
}

impl ServerVisitor {
    /// ServerVisitor constructor
    pub fn new(app_config: Arc<AppConfig>, service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {
        Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            control_plane_visitor: ControlPlaneServerVisitor::new(app_config, service_mgr),
            shutdown_requested: false,
        }
    }

    /// Get active service proxy for given service ID
    pub fn get_service_proxy(
        &self,
        service_id: u64,
    ) -> Result<Arc<Mutex<dyn GatewayServiceProxyVisitor>>, AppError> {
        match self
            .service_mgr
            .lock()
            .unwrap()
            .get_service_proxy(service_id)
        {
            None => Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0425_INACTIVE_SERVICE_PROXY,
                format!("Invalid service proxy: svc_id={}", service_id),
            )),

            Some(service_proxy) => Ok(service_proxy.clone()),
        }
    }

    /// Set the shutdown request state
    pub fn set_shutdown_requested(&mut self, shutdown_requested: bool) {
        self.shutdown_requested = shutdown_requested;
    }
}

impl server_std::ServerVisitor for ServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
    ) -> Result<conn_std::Connection, AppError> {
        match ClientConnVisitor::parse_alpn_protocol(&tls_conn.alpn_protocol())? {
            Protocol::ControlPlane => self.control_plane_visitor.create_client_conn(tls_conn),
            Protocol::Service(service_id) => self
                .get_service_proxy(service_id)?
                .lock()
                .unwrap()
                .create_client_conn(tls_conn),
        }
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        match connection.get_alpn_protocol() {
            Protocol::ControlPlane => self.control_plane_visitor.on_conn_accepted(connection),
            Protocol::Service(service_id) => self
                .get_service_proxy(*service_id)?
                .lock()
                .unwrap()
                .on_conn_accepted(connection),
        }
    }

    fn get_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service;
    use crate::service::proxy::proxy_base::tests::MockGwSvcProxyVisitor;
    use mockall::predicate;

    #[test]
    fn gateway_new() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr = Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let server_visitor = Arc::new(Mutex::new(ServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            control_plane_visitor: ControlPlaneServerVisitor::new(
                app_config.clone(),
                service_mgr.clone(),
            ),
            shutdown_requested: false,
        }));

        let _ = Gateway::new(app_config, server_visitor);
    }

    #[test]
    fn servervisit_new() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr = Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let _ = ServerVisitor::new(app_config.clone(), service_mgr.clone());
    }

    #[test]
    fn servervisit_get_service_proxy_when_existent() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );

        let mut service_mgr = service::manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_get_service_proxy()
            .with(predicate::eq(100))
            .times(1)
            .return_once(|_| Some(Arc::new(Mutex::new(MockGwSvcProxyVisitor::new()))));
        let service_mgr = Arc::new(Mutex::new(service_mgr));

        let server_visitor = ServerVisitor::new(app_config, service_mgr);

        if let Err(err) = server_visitor.get_service_proxy(100) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn servervisit_get_service_proxy_when_nonexistent() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );

        let mut service_mgr = service::manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_get_service_proxy()
            .with(predicate::eq(100))
            .times(1)
            .return_once(|_| None);
        let service_mgr = Arc::new(Mutex::new(service_mgr));

        let server_visitor = ServerVisitor::new(app_config, service_mgr);

        if let Ok(_) = server_visitor.get_service_proxy(100) {
            panic!("Unexpected existent result");
        }
    }

    #[test]
    fn servervisit_set_shutdown_requested() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr = Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let mut server_visitor = ServerVisitor::new(app_config, service_mgr);

        server_visitor.set_shutdown_requested(true);
        assert_eq!(server_visitor.shutdown_requested, true);

        server_visitor.set_shutdown_requested(false);
        assert_eq!(server_visitor.shutdown_requested, false);
    }
}
