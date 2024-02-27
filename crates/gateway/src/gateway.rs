#[cfg(test)]
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rustls::server::Accepted;
use rustls::{ServerConfig, ServerConnection};
use trust0_common::control::tls;

use crate::client::connection::ClientConnVisitor;
use crate::client::controller::ControlPlaneServerVisitor;
use crate::config::{self, AppConfig};
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy_base::GatewayServiceProxyVisitor;
use trust0_common::crypto::alpn::Protocol;
use trust0_common::error::AppError;
#[cfg(not(test))]
use trust0_common::net::tls_server::conn_std::TlsConnection;
use trust0_common::net::tls_server::conn_std::TlsServerConnection;
use trust0_common::net::tls_server::{conn_std, server_std};

/// The Trust0 Gateway TLS Server
pub struct Gateway {
    /// TLS server processor delegate
    tls_server: server_std::Server,
}

impl Gateway {
    /// Gateway constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `visitor` - TLS server visitor pattern object
    ///
    /// # Returns
    ///
    /// A newly constructed [`Gateway`] object.
    ///
    pub fn new(app_config: &Arc<AppConfig>, visitor: Arc<Mutex<ServerVisitor>>) -> Self {
        Self {
            tls_server: server_std::Server::new(
                visitor,
                &app_config.server_host,
                app_config.server_port,
            ),
        }
    }

    /// Bind/listen on port
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the server listen operation.
    ///
    pub fn bind_listener(&mut self) -> Result<(), AppError> {
        self.tls_server.bind_listener()
    }

    /// Poll and dispatch new connections
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the connections polling operation.
    ///
    pub fn poll_new_connections(&mut self) -> Result<(), AppError> {
        self.tls_server.poll_new_connections()
    }
}

unsafe impl Send for Gateway {}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct ServerVisitor {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Control plane visitor pattern object
    control_plane_visitor: ControlPlaneServerVisitor,
    /// Used to request server shutdown
    shutdown_requested: bool,
    /// Map to use as a spy/control for testing
    #[cfg(test)]
    testing_data: HashMap<String, Vec<u8>>,
}

impl ServerVisitor {
    /// ServerVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    ///
    /// # Returns
    ///
    /// A newly constructed [`ServerVisitor`] object.
    ///
    pub fn new(app_config: &Arc<AppConfig>, service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {
        Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            control_plane_visitor: ControlPlaneServerVisitor::new(app_config, &service_mgr),
            shutdown_requested: false,
            #[cfg(test)]
            testing_data: HashMap::new(),
        }
    }

    /// Get active service proxy for given service ID
    ///
    /// # Arguments
    ///
    /// * `service_id` - Service ID for proxy being requested
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the service proxy for the given service ID.
    ///
    pub fn get_service_proxy(
        &self,
        service_id: i64,
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
    ///
    /// # Arguments
    ///
    /// * `shutdown_requested` - Shutdown state being requested
    ///
    pub fn set_shutdown_requested(&mut self, shutdown_requested: bool) {
        self.shutdown_requested = shutdown_requested;
    }
}

impl server_std::ServerVisitor for ServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
    ) -> Result<conn_std::Connection, AppError> {
        let protocol;
        #[cfg(not(test))]
        {
            protocol = tls_conn.alpn_protocol().clone();
        }
        #[cfg(test)]
        {
            protocol = Some(self.testing_data.get("alpn_protocol").unwrap().clone());
        }
        match ClientConnVisitor::parse_alpn_protocol(&protocol)? {
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

    fn on_server_msg_provider(
        &mut self,
        _server_conn: &ServerConnection,
        tcp_stream: &TcpStream,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        Ok(Some(tls::message::SessionMessage::new(
            &tls::message::DataType::Trust0Connection,
            &Some(
                serde_json::to_value(tls::message::Trust0Connection::new(
                    &tls::message::Trust0Connection::create_connection_addrs(tcp_stream),
                ))
                .unwrap(),
            ),
        )))
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
    use crate::service::proxy::proxy_base;
    use crate::service::proxy::proxy_base::tests::MockGwSvcProxyVisitor;
    use mockall::{mock, predicate};
    use rustls::StreamOwned;
    use std::sync::mpsc;
    use trust0_common::crypto::alpn;
    use trust0_common::net::stream_utils;
    use trust0_common::net::tls_server::conn_std;
    use trust0_common::net::tls_server::server_std::ServerVisitor;

    // mocks
    // =====

    mock! {
        pub ConnVisit {}
        impl conn_std::ConnectionVisitor for ConnVisit {
            fn on_connected(&mut self, _event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>) -> Result<(), AppError>;
            fn on_connection_read(&mut self, _data: &[u8]) -> Result<(), AppError>;
            fn on_polling_cycle(&mut self) -> Result<(), AppError>;
            fn on_shutdown(&mut self) -> Result<(), AppError>;
            fn send_error_response(&mut self, err: &AppError);
        }
    }

    // tests
    // =====

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
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let server_visitor = Arc::new(Mutex::new(super::ServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            control_plane_visitor: ControlPlaneServerVisitor::new(&app_config, &service_mgr),
            shutdown_requested: false,
            testing_data: HashMap::new(),
        }));

        let _ = Gateway::new(&app_config, server_visitor);
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
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let _ = super::ServerVisitor::new(&app_config, service_mgr);
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
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(service_mgr));

        let server_visitor = super::ServerVisitor::new(&app_config, service_mgr);

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
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(service_mgr));

        let server_visitor = super::ServerVisitor::new(&app_config, service_mgr);

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
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let mut server_visitor = super::ServerVisitor::new(&app_config, service_mgr);

        server_visitor.set_shutdown_requested(true);
        assert_eq!(server_visitor.shutdown_requested, true);

        server_visitor.set_shutdown_requested(false);
        assert_eq!(server_visitor.shutdown_requested, false);
    }

    #[test]
    fn servervisit_get_shutdown_requested() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let mut server_visitor = super::ServerVisitor::new(&app_config, service_mgr);
        server_visitor.shutdown_requested = true;

        assert!(server_visitor.get_shutdown_requested());
    }

    #[test]
    fn servervisit_create_client_conn_when_alpn_is_control_plane() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();

        let mut server_visitor = crate::gateway::ServerVisitor::new(&app_config, service_mgr);

        let alpn_protocol = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();
        server_visitor
            .testing_data
            .insert("alpn_protocol".to_string(), alpn_protocol.clone());

        let client_conn_result = server_visitor.create_client_conn(StreamOwned::new(
            ServerConnection::new(Arc::new(
                proxy_base::tests::create_tls_server_config(vec![alpn_protocol]).unwrap(),
            ))
            .unwrap(),
            stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0).unwrap(),
        ));

        if let Err(err) = &client_conn_result {
            if err.get_code().unwrap_or(0) != config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE {
                panic!("Unexpected result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn servervisit_create_client_conn_when_alpn_is_service() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();

        let mut proxy_visitor = MockGwSvcProxyVisitor::new();
        proxy_visitor
            .expect_create_client_conn()
            .with(predicate::always())
            .times(1)
            .return_once(|_| {
                Err(AppError::GenWithCodeAndMsg(
                    1,
                    "Work on this later to return successful result".to_string(),
                ))
            });

        let mut service_mgr = service::manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_get_service_proxy()
            .with(predicate::eq(200))
            .times(1)
            .return_once(|_| Some(Arc::new(Mutex::new(proxy_visitor))));
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(service_mgr));

        let mut server_visitor = crate::gateway::ServerVisitor::new(&app_config, service_mgr);

        let alpn_protocol = Protocol::create_service_protocol(200).into_bytes();
        server_visitor
            .testing_data
            .insert("alpn_protocol".to_string(), alpn_protocol.clone());

        let client_conn_result = server_visitor.create_client_conn(StreamOwned::new(
            ServerConnection::new(Arc::new(
                proxy_base::tests::create_tls_server_config(vec![alpn_protocol]).unwrap(),
            ))
            .unwrap(),
            stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0).unwrap(),
        ));

        if let Err(err) = &client_conn_result {
            if err.get_code().unwrap_or(0) != 1 {
                panic!("Unexpected result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn servervisit_on_server_msg_provider() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();

        let mut server_visitor = crate::gateway::ServerVisitor::new(&app_config, service_mgr);

        let server_msg_result = server_visitor.on_server_msg_provider(
            &ServerConnection::new(Arc::new(
                proxy_base::tests::create_tls_server_config(vec![
                    Protocol::create_service_protocol(200).into_bytes(),
                ])
                .unwrap(),
            ))
            .unwrap(),
            &connected_tcp_stream.server_stream.0,
        );

        if let Err(err) = server_msg_result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let server_msg = server_msg_result.unwrap();

        assert!(server_msg.is_some());
        assert_eq!(
            server_msg.unwrap(),
            tls::message::SessionMessage::new(
                &tls::message::DataType::Trust0Connection,
                &Some(
                    serde_json::to_value(tls::message::Trust0Connection::new(
                        &tls::message::Trust0Connection::create_connection_addrs(
                            &connected_tcp_stream.server_stream.0,
                        )
                    ))
                    .unwrap()
                )
            )
        )
    }

    /* Work on later
    #[test]
    fn servervisit_on_conn_accepted_when_alpn_is_control_plane() {
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
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let conn_visitor = MockConnVisit::new();
        let tls_conn = StreamOwned::new(
            ServerConnection::new(Arc::new(
                proxy_base::tests::create_tls_server_config(vec![
                    Protocol::create_service_protocol(200).into_bytes(),
                ])
                    .unwrap(),
            ))
                .unwrap(),
            stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0).unwrap(),
        );
        let alpn_protocol = Protocol::ControlPlane;
        let conn = conn_std::Connection::new(
            Box::new(conn_visitor),
            tls_conn,
            alpn_protocol,
        );

        let mut server_visitor = crate::gateway::ServerVisitor::new(app_config, service_mgr);

        let result = server_visitor .on_conn_accepted(conn);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        ...
    }

    #[test]
    fn servervisit_on_conn_accepted_when_alpn_is_service() {
    }
    */
}
