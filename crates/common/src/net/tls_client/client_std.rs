use std::collections::VecDeque;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

use crate::control::pdu::{ControlChannel, MessageFrame};
use crate::control::tls;
use anyhow::Result;
use pki_types::ServerName;

use crate::error::AppError;
use crate::logging::info;
use crate::net::tls_client::conn_std::{self, TlsClientConnection};
use crate::target;

const SERVERMSG_READ_LOOP_READ_DELAY_MSECS: u64 = 10;
const SERVERMSG_READ_LOOP_MAX_READS: u16 = 10;

/// TLS client, which will connect to a server and expose IO methods
pub struct Client {
    /// Client visitor pattern object
    visitor: Box<dyn ClientVisitor>,
    /// TLS client configuration used in setting up TLS connections
    tls_client_config: Arc<rustls::ClientConfig>,
    /// Gateway address host
    server_host: String,
    /// Gateway address port
    server_port: u16,
    /// Expect initial server message
    expect_server_msg: bool,
    /// Corresponding [`conn_std::Connection`] object for server connection
    connection: Option<conn_std::Connection>,
}

impl Client {
    /// Client constructor
    ///
    /// # Arguments
    ///
    /// * `visitor` - Client visitor pattern object
    /// * `tls_client_config` - TLS client configuration used in setting up TLS connections
    /// * `server_host` - Gateway address host
    /// * `server_port` - Gateway address port
    /// * `expect_server_msg` - Upon handshake completion, retrieve initial server message (if applicable)
    ///
    /// # Returns
    ///
    /// A newly constructed [`Client`] object.
    ///
    pub fn new(
        visitor: Box<dyn ClientVisitor>,
        tls_client_config: rustls::ClientConfig,
        server_host: String,
        server_port: u16,
        expect_server_msg: bool,
    ) -> Self {
        Self {
            visitor,
            tls_client_config: Arc::new(tls_client_config),
            server_host,
            server_port,
            expect_server_msg,
            connection: None,
        }
    }

    /// Connection accessor
    ///
    /// # Returns
    ///
    /// The corresponding connection's [`conn_std::Connection`].
    ///
    pub fn get_connection(&self) -> &Option<conn_std::Connection> {
        &self.connection
    }

    /// Connect to server
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the connection.
    ///
    pub fn connect(&mut self) -> Result<(), AppError> {
        // Connect to TLS server
        let server_host = ServerName::try_from(self.server_host.to_string()).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to resolve server host: host={}", &self.server_host),
                Box::new(err),
            )
        })?;

        let server_addr = (self.server_host.clone(), self.server_port)
            .to_socket_addrs()?
            .next()
            .ok_or(AppError::General(format!(
                "Unable to create socket addr: host={}, port={}",
                &self.server_host, self.server_port
            )))?;

        let mut tls_client_conn =
            rustls::ClientConnection::new(self.tls_client_config.clone(), server_host.clone())
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        format!(
                            "Error setting up TLS client connection: server={:?}",
                            &server_host
                        ),
                        Box::new(err),
                    )
                })?;

        let mut tcp_stream = TcpStream::connect(server_addr).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Error establishing TCP connection: addr={:?}", &server_addr),
                Box::new(err),
            )
        })?;

        // TLS handshaking
        let _ = tls_client_conn
            .complete_io(&mut tcp_stream)
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error completing TLS client connection".to_string(),
                    Box::new(err),
                )
            })?;

        // Post TLS-established connection processing
        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed making socket non-blocking: addr={}", &server_addr),
                Box::new(err),
            )
        })?;

        let mut tls_conn = rustls::StreamOwned::new(tls_client_conn, tcp_stream);

        let server_msg = self.read_server_msg(&mut tls_conn)?;

        let connection = self.visitor.create_server_conn(tls_conn, server_msg)?;

        info(&target!(), &format!("Connected: addr={:?}", server_addr));

        self.visitor.on_connected()?;

        self.connection = Some(connection);

        Ok(())
    }

    /// If applicable, attempt to read a single [`tls::message::SessionMessage`] server message object.
    ///
    /// # Arguments
    ///
    /// * `conn_reader` : The TLS client connection object (as a [`Read`] object)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing an optional [`tls::message::SessionMessage`] object. If required, will return an error.
    ///
    fn read_server_msg(
        &mut self,
        conn_reader: &mut impl Read,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        if !self.expect_server_msg {
            Ok(None)
        } else {
            let mut buffer = VecDeque::new();
            let mut buff_chunk = [0; conn_std::READ_BLOCK_SIZE];
            let mut read_attempts = 0;
            loop {
                match conn_reader.read(&mut buff_chunk) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        buffer.append(&mut VecDeque::from(buff_chunk[..bytes_read].to_vec()));
                        match MessageFrame::consume_next_pdu(&mut buffer)? {
                            Some(msg_frame) if msg_frame.channel == ControlChannel::TLS => {
                                return Ok(Some(msg_frame.try_into().unwrap()))
                            }
                            Some(msg_frame) => {
                                return Err(AppError::General(format!(
                                    "Invalid server message frame: msg={:?}",
                                    &msg_frame
                                )))
                            }
                            None => {}
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        read_attempts += 1;
                        if read_attempts == SERVERMSG_READ_LOOP_MAX_READS {
                            break;
                        }
                        thread::sleep(Duration::from_millis(SERVERMSG_READ_LOOP_READ_DELAY_MSECS));
                    }
                    Err(err) => {
                        return Err(AppError::GenWithMsgAndErr(
                            "Error reading server message".to_string(),
                            Box::new(err),
                        ))
                    }
                }
            }

            Err(AppError::General(format!(
                "Incomplete/missing server message frame: msg={:?}",
                &buffer
            )))
        }
    }

    /// Poll connection events
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the poller.
    ///
    pub fn poll_connection(&mut self) -> Result<(), AppError> {
        self.assert_connected()?;
        self.connection.as_mut().unwrap().poll_connection()
    }

    fn assert_connected(&self) -> Result<(), AppError> {
        if self.connection.is_none() {
            return Err(AppError::General("Client not connected".to_string()));
        }
        Ok(())
    }
}

unsafe impl Send for Client {}

impl From<Client> for TlsClientConnection {
    fn from(value: Client) -> Self {
        value.connection.unwrap().into()
    }
}

/// Visitor pattern used to customize client implementation strategy.
pub trait ClientVisitor: Send {
    /// TLS server connection factory
    ///
    /// # Arguments
    ///
    /// * `tls_conn`: TLS connection object to use in creating server connection
    /// * `server_msg`: Optional initial message from server
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the newly constructed [`conn_std::Connection`] object.
    ///
    fn create_server_conn(
        &mut self,
        tls_conn: TlsClientConnection,
        server_msg: Option<tls::message::SessionMessage>,
    ) -> Result<conn_std::Connection, AppError>;

    /// TLS handshaking event handler
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the function call.
    ///
    fn on_connected(&mut self) -> Result<(), AppError> {
        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::control::pdu;
    use crate::crypto::file::{load_certificates, load_private_key};
    use crate::net::tls_server;
    use mockall::{mock, predicate};
    use rustls::crypto::CryptoProvider;
    use rustls::server::Acceptor;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::thread;

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "root-ca.local.crt.pem",
    ];
    const CERTFILE_CLIENT0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.crt.pem",
    ];
    const KEYFILE_CLIENT0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.key.pem",
    ];

    // mocks
    // =====

    mock! {
        pub CliVisit {}
        impl ClientVisitor for CliVisit {
            fn create_server_conn(
                &mut self, tls_conn: TlsClientConnection,
                 server_msg: Option<tls::message::SessionMessage>,
            ) -> Result<conn_std::Connection, AppError>;
            fn on_connected(&mut self) -> Result<(), AppError>;
        }
    }

    // utils
    // =====

    pub fn create_tls_client_config() -> Result<rustls::ClientConfig, anyhow::Error> {
        let rootca_cert_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_cert = load_certificates(rootca_cert_file.to_str().unwrap().to_string())?;
        let client_cert_file: PathBuf = CERTFILE_CLIENT0_PATHPARTS.iter().collect();
        let client_cert = load_certificates(client_cert_file.to_str().unwrap().to_string())?;
        let client_key_file: PathBuf = KEYFILE_CLIENT0_PATHPARTS.iter().collect();
        let client_key = load_private_key(client_key_file.to_str().unwrap().to_string())?;

        let mut ca_root_store = rustls::RootCertStore::empty();

        for ca_root_cert in rootca_cert {
            ca_root_store.add(ca_root_cert).map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error adding CA root cert".to_string(),
                    Box::new(err.clone()),
                )
            })?;
        }

        let mut tls_client_config = rustls::ClientConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites: rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec(),
                ..rustls::crypto::ring::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("Inconsistent cipher-suite/versions selected")
        .with_root_certificates(ca_root_store)
        .with_client_auth_cert(client_cert, client_key)
        .expect("Invalid client auth certs/key");

        tls_client_config.key_log = Arc::new(rustls::KeyLogFile::new());
        tls_client_config.alpn_protocols = Vec::new();

        Ok(tls_client_config)
    }

    fn spawn_tls_server_listener(
        tcp_listener: std::net::TcpListener,
        num_connections: usize,
    ) -> Result<(), anyhow::Error> {
        thread::spawn(move || {
            let mut conn_idx = 0;
            for tcp_stream in tcp_listener.incoming() {
                let mut tcp_stream = tcp_stream.unwrap();

                let mut acceptor = Acceptor::default();
                let accepted = loop {
                    acceptor.read_tls(&mut tcp_stream).unwrap();
                    if let Some(accepted) = acceptor.accept().unwrap() {
                        break accepted;
                    }
                };

                let tls_server_config =
                    Arc::new(tls_server::server_std::tests::create_tls_server_config().unwrap());
                let mut server_conn = accepted.into_connection(tls_server_config).unwrap();

                let _ = server_conn.complete_io(&mut tcp_stream);

                let mut tls_conn = rustls::StreamOwned::new(server_conn, tcp_stream);

                let pdu_message_frame: MessageFrame = tls::message::SessionMessage::new(
                    &tls::message::DataType::Trust0Connection,
                    &Some(
                        serde_json::to_value(tls::message::Trust0Connection::new(&(
                            "addr1".to_string(),
                            "addr2".to_string(),
                        )))
                        .unwrap(),
                    ),
                )
                .try_into()
                .unwrap();
                tls_conn
                    .write_all(&*pdu_message_frame.build_pdu().unwrap())
                    .unwrap();

                thread::sleep(Duration::from_millis(100));

                conn_idx += 1;
                if conn_idx == num_connections {
                    break;
                }
            }
        });

        Ok(())
    }

    // tests
    // ====

    #[test]
    fn client_new() {
        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client::new(
            Box::new(MockCliVisit::new()),
            tls_client_config,
            "server1".to_string(),
            1234,
            false,
        );

        assert_eq!(client.server_host, "server1".to_string());
        assert_eq!(client.server_port, 1234);
        assert!(client.connection.is_none());
    }

    #[test]
    fn client_get_connection() {
        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: false,
            connection: Some(conn_std::tests::create_simple_connection()),
        };

        assert!(client.get_connection().is_some());
    }

    #[test]
    fn client_connect() {
        struct TestClientVisitor {
            conn_created: Arc<Mutex<bool>>,
            conn_connected: Arc<Mutex<bool>>,
            server_msg: Arc<Mutex<Option<tls::message::SessionMessage>>>,
        }

        impl ClientVisitor for TestClientVisitor {
            fn create_server_conn(
                &mut self,
                tls_conn: TlsClientConnection,
                server_msg: Option<tls::message::SessionMessage>,
            ) -> Result<conn_std::Connection, AppError> {
                *self.conn_created.lock().unwrap() = true;
                *self.server_msg.lock().unwrap() = server_msg;
                let mut conn_visitor = conn_std::tests::MockConnVisit::new();
                conn_visitor
                    .expect_on_connected()
                    .with(predicate::always())
                    .times(1)
                    .return_once(|_| Ok(()));
                conn_std::Connection::new(
                    Box::new(conn_visitor),
                    tls_conn,
                    &("addr1".to_string(), "addr2".to_string()),
                )
            }

            fn on_connected(&mut self) -> Result<(), AppError> {
                *self.conn_connected.lock().unwrap() = true;
                Ok(())
            }
        }

        let conn_created = Arc::new(Mutex::new(false));
        let conn_connected = Arc::new(Mutex::new(false));
        let server_msg = Arc::new(Mutex::new(None));
        let client_visitor = TestClientVisitor {
            conn_created: conn_created.clone(),
            conn_connected: conn_connected.clone(),
            server_msg: server_msg.clone(),
        };

        let tcp_listener = std::net::TcpListener::bind("localhost:0").unwrap();
        let server_port = tcp_listener.local_addr().unwrap().port();
        spawn_tls_server_listener(tcp_listener, 1).unwrap();

        let mut client = Client {
            visitor: Box::new(client_visitor),
            tls_client_config: Arc::new(create_tls_client_config().unwrap()),
            server_host: "localhost".to_string(),
            server_port,
            expect_server_msg: true,
            connection: None,
        };

        if let Err(err) = client.connect() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server_msg.lock().unwrap().is_some());
        assert_eq!(
            server_msg.lock().unwrap().as_ref().unwrap(),
            &tls::message::SessionMessage::new(
                &tls::message::DataType::Trust0Connection,
                &Some(
                    serde_json::to_value(tls::message::Trust0Connection::new(&(
                        "addr1".to_string(),
                        "addr2".to_string()
                    )))
                    .unwrap()
                ),
            )
        );
        assert!(*conn_created.lock().unwrap());
        assert!(*conn_connected.lock().unwrap());
    }

    #[test]
    fn client_read_server_msg_when_valid_message() {
        let expected_session_msg = tls::message::SessionMessage::new(
            &tls::message::DataType::Trust0Connection,
            &Some(
                serde_json::to_value(tls::message::Trust0Connection::new(&(
                    "addr1".to_string(),
                    "addr2".to_string(),
                )))
                .unwrap(),
            ),
        );

        struct ConnReader {
            session_msg: tls::message::SessionMessage,
        }
        impl Read for ConnReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let msg_frame: MessageFrame = self.session_msg.clone().try_into().unwrap();
                let pdu = msg_frame.build_pdu().unwrap();
                let pdu_len = pdu.len(); // will be lower than conn_std::READ_BLOCK_SIZE
                buf[..pdu_len].copy_from_slice(pdu.as_slice());
                Ok(pdu_len)
            }
        }

        let mut conn_reader = ConnReader {
            session_msg: expected_session_msg.clone(),
        };

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: true,
            connection: None,
        };

        let result = client.read_server_msg(&mut conn_reader);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let session_msg = result.unwrap();

        assert!(session_msg.is_some());
        assert_eq!(session_msg.unwrap(), expected_session_msg);
    }

    #[test]
    fn client_read_server_msg_when_wrong_channel_type() {
        let expected_msg_frame = MessageFrame::new(
            ControlChannel::Management,
            pdu::CODE_OK,
            &None,
            &None,
            &None,
        );

        struct ConnReader {
            msg_frame: MessageFrame,
        }
        impl Read for ConnReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let pdu = self.msg_frame.build_pdu().unwrap();
                let pdu_len = pdu.len(); // will be lower than conn_std::READ_BLOCK_SIZE
                buf[..pdu_len].copy_from_slice(pdu.as_slice());
                Ok(pdu_len)
            }
        }

        let mut conn_reader = ConnReader {
            msg_frame: expected_msg_frame,
        };

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: true,
            connection: None,
        };

        let result = client.read_server_msg(&mut conn_reader);

        if let Ok(session_msg) = result {
            panic!("Unexpected successful result: msg={:?}", &session_msg);
        }
    }

    #[test]
    fn client_read_server_msg_when_no_data_to_read() {
        struct ConnReader {}
        impl Read for ConnReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }

        let mut conn_reader = ConnReader {};

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: true,
            connection: None,
        };

        let result = client.read_server_msg(&mut conn_reader);

        if let Ok(session_msg) = result {
            panic!("Unexpected successful result: msg={:?}", &session_msg);
        }
    }

    #[test]
    fn client_read_server_msg_when_always_would_block() {
        struct ConnReader {}
        impl Read for ConnReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }

        let mut conn_reader = ConnReader {};

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: true,
            connection: None,
        };

        let result = client.read_server_msg(&mut conn_reader);

        if let Ok(session_msg) = result {
            panic!("Unexpected successful result: msg={:?}", &session_msg);
        }
    }

    #[test]
    fn client_read_server_msg_when_non_blockable_error() {
        struct ConnReader {}
        impl Read for ConnReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::UnexpectedEof.into())
            }
        }

        let mut conn_reader = ConnReader {};

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: true,
            connection: None,
        };

        let result = client.read_server_msg(&mut conn_reader);

        if let Ok(session_msg) = result {
            panic!("Unexpected successful result: msg={:?}", &session_msg);
        }
    }

    #[test]
    fn client_poll_connection_when_not_connected() {
        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: false,
            connection: None,
        };

        if let Ok(()) = client.poll_connection() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn client_assert_connected_when_connected() {
        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: false,
            connection: Some(conn_std::tests::create_simple_connection()),
        };

        if let Err(err) = client.assert_connected() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn client_assert_connected_when_not_connected() {
        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            expect_server_msg: false,
            connection: None,
        };

        if let Ok(()) = client.assert_connected() {
            panic!("Unexpected successful result");
        }
    }
}
