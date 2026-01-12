use anyhow::Result;
#[cfg(test)]
use mockall::predicate;
use std::sync::{Arc, Mutex};
#[cfg(not(test))]
use trust0_common::client::service::ClientControlServiceMgr;
use trust0_common::control::tls;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::net::tls_client::{client_std, conn_std};

use crate::config::AppConfig;
#[cfg(test)]
use crate::gateway;
#[cfg(not(test))]
use crate::gateway::connection::ServerConnVisitor;
#[cfg(not(test))]
use crate::service::manager::ControllerServiceMgr;
use crate::service::manager::ServiceMgr;

/// The Trust0 Gateway TLS Client
pub struct Client {
    _app_config: Arc<AppConfig>,
    tls_client: client_std::Client,
}

impl Client {
    /// Client constructor
    pub fn new(app_config: &Arc<AppConfig>, service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {
        let mut tls_client_config = app_config.tls_client_config.clone();
        tls_client_config.alpn_protocols =
            vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        Self {
            _app_config: app_config.clone(),
            tls_client: client_std::Client::new(
                Box::new(ClientVisitor::new(app_config, &service_mgr)),
                tls_client_config,
                &app_config.gateway_host,
                app_config.gateway_port,
                false,
            ),
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
    #[allow(dead_code)]
    app_config: Arc<AppConfig>,
    #[allow(dead_code)]
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
}

unsafe impl Send for ClientVisitor {}

impl ClientVisitor {
    /// ClientVisitor constructor
    pub fn new(app_config: &Arc<AppConfig>, service_mgr: &Arc<Mutex<dyn ServiceMgr>>) -> Self {
        Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
        }
    }
}

/// Creates a server connection visitor object for given client visitor
///
/// # Arguments
///
/// * `client_visitor` - Client visitor object
///
/// # Returns
///
/// A [`Result`] containing a [`conn_std::ConnectionVisitor`] object appropriate for given client visitor.
///
#[cfg(not(test))]
fn create_server_conn_visitor(
    client_visitor: &ClientVisitor,
) -> Result<Box<dyn conn_std::ConnectionVisitor>, AppError> {
    let clictl_svc_mgr: Box<dyn ClientControlServiceMgr> = Box::new(ControllerServiceMgr {
        service_mgr: client_visitor.service_mgr.clone(),
    });
    Ok(Box::new(ServerConnVisitor::new(
        &client_visitor.app_config.repl_shell_input,
        &client_visitor.app_config.repl_shell_output,
        &Arc::new(Mutex::new(clictl_svc_mgr)),
    )?))
}
#[cfg(test)]
fn create_server_conn_visitor(
    _client_visitor: &ClientVisitor,
) -> Result<Box<dyn conn_std::ConnectionVisitor>, AppError> {
    let mut visitor = gateway::connection::tests::MockConnVisit::new();
    visitor
        .expect_on_connected()
        .with(predicate::always())
        .times(1)
        .return_once(|_| Ok(()));
    Ok(Box::new(visitor))
}

impl client_std::ClientVisitor for ClientVisitor {
    fn create_server_conn(
        &mut self,
        tls_conn: conn_std::TlsClientConnection,
        server_msg: Option<tls::message::SessionMessage>,
    ) -> Result<conn_std::Connection, AppError> {
        let conn_visitor = create_server_conn_visitor(self)?;

        let session_addrs = match server_msg {
            Some(msg) if msg.data_type == tls::message::DataType::Trust0Connection => {
                let t0_conn =
                    serde_json::from_value::<tls::message::Trust0Connection>(msg.data.unwrap())
                        .map_err(|err| {
                            AppError::General(format!(
                                "Invalid Trust0Connection json: err={:?}",
                                &err
                            ))
                        })?;
                Some(t0_conn.binds)
            }
            _ => None,
        };
        let session_addrs = match session_addrs {
            Some(addrs) => addrs,
            None => tls::message::Trust0Connection::create_connection_addrs(&tls_conn.sock),
        };

        conn_std::Connection::new(conn_visitor, tls_conn, &session_addrs)
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{config, service};
    use pki_types::ServerName;
    use rustls::StreamOwned;
    use trust0_common::net::stream_utils;
    use trust0_common::net::tls_client::client_std::ClientVisitor;

    #[test]
    fn client_new() {
        let app_config = Arc::new(config::tests::create_app_config().unwrap());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let _ = Client::new(&app_config, service_mgr);
    }

    #[test]
    fn clivisit_new() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let _ = super::ClientVisitor::new(
            &Arc::new(config::tests::create_app_config().unwrap()),
            &service_mgr,
        );
    }

    #[test]
    fn clivisit_create_server_conn() {
        let app_config = config::tests::create_app_config().unwrap();
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let session_addrs = ("addr1".to_string(), "addr2".to_string());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));

        let mut client_visitor = super::ClientVisitor::new(&Arc::new(app_config), &service_mgr);

        let result = client_visitor.create_server_conn(
            StreamOwned::new(
                rustls::ClientConnection::new(
                    Arc::new(
                        service::proxy::proxy_client::tests::create_tls_client_config().unwrap(),
                    ),
                    ServerName::try_from("127.0.0.1".to_string()).unwrap(),
                )
                .unwrap(),
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.client_stream.0,
                    "test-tls-client",
                )
                .unwrap(),
            ),
            Some(tls::message::SessionMessage::new(
                &tls::message::DataType::Trust0Connection,
                &Some(
                    serde_json::to_value(tls::message::Trust0Connection::new(&session_addrs))
                        .unwrap(),
                ),
            )),
        );

        assert!(result.is_ok());

        let connection = result.unwrap();

        assert_eq!(connection.get_session_addrs(), &session_addrs);
    }
}
