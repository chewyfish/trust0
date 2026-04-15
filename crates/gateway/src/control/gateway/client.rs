use anyhow::Result;
#[cfg(test)]
use mockall::predicate;
use std::sync::{mpsc, Arc, Mutex};
#[cfg(not(test))]
use trust0_common::client::control::connection::ServerConnVisitor;
use trust0_common::client::replshell_io::{
    ChannelShellInputReader, ChannelShellOutputWriter, ReplShellInputReader, ReplShellOutputWriter,
};
#[cfg(not(test))]
use trust0_common::client::service::ClientControlServiceMgr;
use trust0_common::control::management::request::Request;
use trust0_common::control::tls;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::net::tls_client::{client_std, conn_std};

use crate::config::AppConfig;
use crate::control::client::device::Device;
#[cfg(not(test))]
use crate::control::gateway::service::ControllerServiceMgr;
use crate::service::manager::ServiceMgr;

/// The Trust0 client-gateway TLS client used to connect to the service-gateway
pub struct ControllerClient {
    /// TLS client object
    tls_client: client_std::Client,
    /// Trust0 client device
    _device: Device,
    /// Receiver to retrieve REPL shell output messages (sender used [`ChannelShellOutputWriter`])
    shell_msg_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender used to send new REPL shell messages (receiver used in [`ChannelShellInputReader`])
    shell_msg_sender: mpsc::Sender<Vec<u8>>,
}

impl ControllerClient {
    /// Client constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration
    /// * `service_mgr` - Service manager
    /// * `device` - Trust0 client device
    ///
    /// # Returns
    ///
    /// Newly constructed [`ControllerClient`]
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        device: &Device,
    ) -> Self {
        let mut tls_client_config = app_config
            .as_ref()
            .tls_client_config
            .as_ref()
            .unwrap()
            .clone();
        tls_client_config.alpn_protocols =
            vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        let (shell_writer_sender, shell_writer_receiver) = mpsc::channel();
        let (shell_reader_sender, shell_reader_receiver) = mpsc::channel();

        Self {
            tls_client: client_std::Client::new(
                Box::new(ControllerClientVisitor::new(
                    &service_mgr,
                    device,
                    shell_writer_sender,
                    shell_reader_receiver,
                )),
                tls_client_config,
                app_config
                    .as_ref()
                    .service_gateway_host
                    .as_ref()
                    .unwrap()
                    .as_str(),
                *app_config.as_ref().service_gateway_port.as_ref().unwrap(),
                false,
            ),
            _device: device.clone(),
            shell_msg_receiver: Arc::new(Mutex::new(shell_writer_receiver)),
            shell_msg_sender: shell_reader_sender,
        }
    }

    /// TLS client object accessor
    ///
    pub fn _get_tls_client(&self) -> &client_std::Client {
        &self.tls_client
    }

    /// Trust0 client device
    ///
    pub fn _get_device(&self) -> &Device {
        &self._device
    }

    /// Receiver to retrieve REPL shell output messages (sender used [`ChannelShellOutputWriter`])
    ///
    pub fn get_shell_msg_receiver(&self) -> &Arc<Mutex<mpsc::Receiver<Vec<u8>>>> {
        &self.shell_msg_receiver
    }

    /// Sender used to send new REPL shell messages (receiver used in [`ChannelShellInputReader`])
    ///
    pub fn get_shell_msg_sender(&self) -> &mpsc::Sender<Vec<u8>> {
        &self.shell_msg_sender
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

impl ControllerClient {
    /// Request gateway service startup
    ///
    /// # Arguments
    ///
    /// * `shell_msg_sender` - Shell msg sender ([`mpsc::Sender`]) from a constructed [`ControllerClient`]
    /// * `service_name` - Well-known service name for service to be started
    /// * `local_port` - Local server port for new service connections
    ///
    /// # Returns
    ///
    /// Success or failure of Request
    ///
    pub fn request_start_service(
        shell_msg_sender: &mpsc::Sender<Vec<u8>>,
        service_name: &str,
        local_port: u16,
    ) -> Result<(), AppError> {
        let start_cmd = Request::Start {
            service_name: service_name.to_string(),
            local_port,
        }
        .build_command();
        shell_msg_sender
            .send(start_cmd.as_bytes().to_vec())
            .map_err(|err| {
                AppError::General(format!(
                    "Error sending service-gateway start service command: cmd={}, err={:?}",
                    &start_cmd, &err
                ))
            })
    }
}

unsafe impl Send for ControllerClient {}

/// tls_client::std_client::Client strategy visitor pattern implementation
pub struct ControllerClientVisitor {
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Trust0 client device
    device: Device,
    /// REPL shell command input reader
    repl_shell_input: Arc<Mutex<Box<dyn ReplShellInputReader>>>,
    /// REPL shell response output writer
    repl_shell_output: Arc<Mutex<Box<dyn ReplShellOutputWriter>>>,
}

unsafe impl Send for ControllerClientVisitor {}

impl ControllerClientVisitor {
    /// ClientVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `service_mgr` - Service manager
    /// * `device` - Trust0 client device
    /// * `shell_writer_sender` - Sender to writer REPL shell output messages
    /// * `shell_reader_receiver` - Receiver used to read new REPL shell input messages
    ///
    /// # Returns
    ///
    /// A newly constructed [`ControllerClientVisitor`]
    ///
    pub fn new(
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        device: &Device,
        shell_writer_sender: mpsc::Sender<Vec<u8>>,
        shell_reader_receiver: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        let repl_shell_output: Box<dyn ReplShellOutputWriter> =
            Box::new(ChannelShellOutputWriter::new(shell_writer_sender));
        let repl_shell_input: Box<dyn ReplShellInputReader> =
            Box::new(ChannelShellInputReader::new(
                shell_reader_receiver,
                &[],
                repl_shell_output.prompted_toggle(),
            ));
        Self {
            service_mgr: service_mgr.clone(),
            device: device.clone(),
            repl_shell_input: Arc::new(Mutex::new(repl_shell_input)),
            repl_shell_output: Arc::new(Mutex::new(repl_shell_output)),
        }
    }

    /// Generate client access context session message
    ///
    /// # Returns
    ///
    /// The [`tls::message::SessionMessage`] of a [`tls::message::DataType::ClientAccessContext`]
    /// message type for the given device's [`trust0_common::crypto::ca::CertAccessContext`]
    ///
    fn create_access_session_message(
        &self,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        Ok(Some(tls::message::SessionMessage::new(
            &tls::message::DataType::ClientAccessContext,
            &Some(
                serde_json::to_value(tls::message::ClientAccessContext {
                    access: self.device.get_cert_access_context().clone(),
                })
                .unwrap(),
            ),
        )))
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
    client_visitor: &ControllerClientVisitor,
) -> Result<Box<dyn conn_std::ConnectionVisitor>, AppError> {
    let clictl_svc_mgr: Box<dyn ClientControlServiceMgr> = Box::new(ControllerServiceMgr {
        service_mgr: client_visitor.service_mgr.clone(),
        device_id: client_visitor.device.get_id(),
    });
    Ok(Box::new(ServerConnVisitor::new(
        &client_visitor.repl_shell_input,
        &client_visitor.repl_shell_output,
        &Arc::new(Mutex::new(clictl_svc_mgr)),
    )?))
}
#[cfg(test)]
fn create_server_conn_visitor(
    _client_visitor: &ControllerClientVisitor,
) -> Result<Box<dyn conn_std::ConnectionVisitor>, AppError> {
    let mut visitor = tests::MockConnVisit::new();
    visitor
        .expect_on_connected()
        .with(predicate::always())
        .times(1)
        .return_once(|_| Ok(()));
    Ok(Box::new(visitor))
}

impl client_std::ClientVisitor for ControllerClientVisitor {
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

    fn on_client_msg_provider(
        &mut self,
        _tls_conn: &conn_std::TlsClientConnection,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        self.create_access_session_message()
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::repository::access_repo::{tests::MockAccessRepo, AccessRepository};
    use crate::repository::role_repo::{tests::MockRoleRepo, RoleRepository};
    use crate::repository::service_repo::{tests::MockServiceRepo, ServiceRepository};
    use crate::repository::user_repo::{tests::MockUserRepo, UserRepository};
    use crate::{config, service};
    use mockall::mock;
    use pki_types::ServerName;
    use rustls::StreamOwned;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::mpsc::Sender;
    use trust0_common::control::management::request;
    use trust0_common::crypto::file::load_certificates;
    use trust0_common::net::stream_utils;
    use trust0_common::net::tls_client::client_std::ClientVisitor;

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];

    // utils
    // =====

    fn create_app_config() -> AppConfig {
        let access_repo: Arc<Mutex<dyn AccessRepository>> =
            Arc::new(Mutex::new(MockAccessRepo::new()));
        let role_repo: Arc<Mutex<dyn RoleRepository>> = Arc::new(Mutex::new(MockRoleRepo::new()));
        let service_repo: Arc<Mutex<dyn ServiceRepository>> =
            Arc::new(Mutex::new(MockServiceRepo::new()));
        let user_repo: Arc<Mutex<dyn UserRepository>> = Arc::new(Mutex::new(MockUserRepo::new()));
        config::tests::create_app_config_with_repos(
            config::GatewayType::Client,
            user_repo,
            service_repo,
            role_repo,
            access_repo,
        )
        .unwrap()
    }

    fn create_client_device() -> Device {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        Device::new(certs, None).unwrap()
    }

    // mocks
    // =====

    mock! {
        pub ConnVisit {}
        impl conn_std::ConnectionVisitor for ConnVisit {
            fn on_connected(&mut self, _event_channel_sender: &Sender<conn_std::ConnectionEvent>) -> Result<(), AppError>;
            fn on_connection_read(&mut self, _data: &[u8]) -> Result<(), AppError>;
            fn on_polling_cycle(&mut self) -> Result<(), AppError>;
            fn on_shutdown(&mut self) -> Result<(), AppError>;
            fn send_error_response(&mut self, err: &AppError);
        }
    }

    // tests
    // =====

    #[test]
    fn ctlclient_new() {
        let app_config = Arc::new(create_app_config());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let device = create_client_device();

        let client = ControllerClient::new(&app_config, service_mgr, &device);

        assert_eq!(client._get_device().get_id(), device.get_id());
    }

    #[test]
    fn ctlclient_accessors() {
        let app_config = Arc::new(create_app_config());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let device = create_client_device();

        let client = ControllerClient::new(&app_config, service_mgr, &device);

        let _ = client._get_tls_client();
        let _ = client.get_shell_msg_receiver();
        let _ = client.get_shell_msg_sender();
        assert_eq!(client._get_device().get_id(), device.get_id());
    }

    #[ignore]
    #[test]
    fn ctlclient_request_service_start() {
        let app_config = Arc::new(create_app_config());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let device = create_client_device();
        let expected_cmd = format!("{} -s \"serv200\" -p 2000", request::PROTOCOL_REQUEST_START);

        let client = ControllerClient::new(&app_config, service_mgr, &device);

        let result =
            ControllerClient::request_start_service(client.get_shell_msg_sender(), "serv200", 2000);

        assert!(result.is_ok());

        // TODO - Wrong receiver used, fix
        match client.get_shell_msg_receiver().lock().unwrap().try_recv() {
            Ok(msg) => assert_eq!(msg, expected_cmd.as_bytes().to_vec()),
            Err(err) => panic!("Unexpected channel recv message result: err={:?}", &err),
        };
    }

    #[test]
    fn ctlclivisit_new() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let shell_channel = mpsc::channel();
        let device = create_client_device();

        let client_visitor =
            ControllerClientVisitor::new(&service_mgr, &device, shell_channel.0, shell_channel.1);

        assert_eq!(client_visitor.device.get_id(), device.get_id());
    }

    #[test]
    fn ctlclivisit_create_server_conn() {
        let app_config = create_app_config();
        let tls_client_config = app_config.tls_client_config.as_ref().unwrap().clone();
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let session_addrs = ("addr1".to_string(), "addr2".to_string());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let shell_channel = mpsc::channel();
        let device = create_client_device();

        let mut client_visitor =
            ControllerClientVisitor::new(&service_mgr, &device, shell_channel.0, shell_channel.1);

        let result = client_visitor.create_server_conn(
            StreamOwned::new(
                rustls::ClientConnection::new(
                    Arc::new(tls_client_config),
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

    #[test]
    fn ctlclivisit_create_access_session_message() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> =
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new()));
        let shell_channel = mpsc::channel();
        let device = create_client_device();

        let client_visitor =
            ControllerClientVisitor::new(&service_mgr, &device, shell_channel.0, shell_channel.1);

        match client_visitor.create_access_session_message() {
            Ok(session_msg) => match session_msg {
                Some(session_msg) => {
                    let expected_cli_access_json = Some(
                        json!({"access": {"userId": 100, "entityType": "client", "platform": "Linux"}}),
                    );
                    let expected_session_msg = tls::message::SessionMessage::new(
                        &tls::message::DataType::ClientAccessContext,
                        &expected_cli_access_json,
                    );
                    assert_eq!(session_msg, expected_session_msg);
                }
                None => panic!("Session message not provided"),
            },
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }
}
