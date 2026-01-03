use anyhow::Result;
use pki_types::ServerName;
#[cfg(test)]
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use crate::control::tls;
use crate::error::AppError;
use crate::logging::info;
use crate::net::stream_utils::SessionMsgExchanger;
use crate::net::tls_client::conn_std::{self, TlsClientConnection};
use crate::target;

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
    /// Session message exchanger
    sessmsg_exchanger: SessionMsgExchanger,
    /// Corresponding [`conn_std::Connection`] object for server connection
    connection: Option<conn_std::Connection>,
    #[cfg(test)]
    /// Store information to be scrutinized by tests
    testing_data: Arc<Mutex<HashMap<String, String>>>,
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
        server_host: &str,
        server_port: u16,
        expect_server_msg: bool,
    ) -> Self {
        Self {
            visitor,
            tls_client_config: Arc::new(tls_client_config),
            server_host: server_host.to_string(),
            server_port,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: expect_server_msg,
            },
            connection: None,
            #[cfg(test)]
            testing_data: Arc::new(Mutex::new(HashMap::new())),
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
            AppError::General(format!(
                "Failed to resolve server host: host={}, err={:?}",
                &self.server_host, &err
            ))
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
                    AppError::General(format!(
                        "Error setting up TLS client connection: server={:?}, err={:?}",
                        &server_host, &err
                    ))
                })?;

        let mut tcp_stream = TcpStream::connect(server_addr).map_err(|err| {
            AppError::General(format!(
                "Error establishing TCP connection: addr={:?}, err={:?}",
                &server_addr, &err
            ))
        })?;

        // TLS handshaking
        let _ = tls_client_conn
            .complete_io(&mut tcp_stream)
            .map_err(|err| {
                AppError::General(format!(
                    "Error completing TLS client connection: err={:?}",
                    &err
                ))
            })?;

        // Post TLS-established connection processing
        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::General(format!(
                "Failed making socket non-blocking: addr={}, err={:?}",
                &server_addr, &err
            ))
        })?;

        let mut tls_conn = rustls::StreamOwned::new(tls_client_conn, tcp_stream);

        let server_msg = self.sessmsg_exchanger.read_session_message(&mut tls_conn)?;

        if let Some(client_msg) = self.visitor.on_client_msg_provider(&tls_conn)? {
            #[cfg(test)]
            {
                self.testing_data.lock().unwrap().insert(
                    "CliMsg".to_string(),
                    serde_json::to_string(&client_msg).unwrap(),
                );
            }
            self.sessmsg_exchanger
                .write_session_message(&mut tls_conn, &client_msg)?;
        }

        let connection = self.visitor.create_server_conn(tls_conn, server_msg)?;

        info(&target!(), &format!("Connected: addr={:?}", server_addr));

        self.visitor.on_connected()?;

        self.connection = Some(connection);

        Ok(())
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

    /// Connection client message provider handler
    ///
    /// # Arguments
    ///
    /// * `tls_conn`: TLS connection object to use in creating server connection
    ///
    /// # Returns
    ///
    /// A [`Result`] containing an optional [`tls::message::SessionMessage`] object to be sent immediately after handshaking.
    ///
    fn on_client_msg_provider(
        &mut self,
        _tls_conn: &TlsClientConnection,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        Ok(None)
    }

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
    use crate::control::pdu::MessageFrame;
    use crate::crypto;
    use crate::crypto::file::{load_certificates, load_private_key};
    use crate::net::tls_server;
    use mockall::{mock, predicate};
    use rustls::crypto::CryptoProvider;
    use rustls::server::Acceptor;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

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
        let rootca_cert = load_certificates(rootca_cert_file.to_str().as_ref().unwrap())?;
        let client_cert_file: PathBuf = CERTFILE_CLIENT0_PATHPARTS.iter().collect();
        let client_cert = load_certificates(client_cert_file.to_str().as_ref().unwrap())?;
        let client_key_file: PathBuf = KEYFILE_CLIENT0_PATHPARTS.iter().collect();
        let client_key = load_private_key(client_key_file.to_str().as_ref().unwrap())?;

        let mut ca_root_store = rustls::RootCertStore::empty();

        for ca_root_cert in rootca_cert {
            ca_root_store.add(ca_root_cert).map_err(|err| {
                AppError::General(format!("Error adding CA root cert: err={:?}", &err))
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
                    .write_all(&pdu_message_frame.build_pdu().unwrap())
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
        crypto::setup_crypto_provider();

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client::new(
            Box::new(MockCliVisit::new()),
            tls_client_config,
            "server1",
            1234,
            false,
        );

        assert_eq!(client.server_host, "server1".to_string());
        assert_eq!(client.server_port, 1234);
        assert!(client.connection.is_none());
    }

    #[test]
    fn client_get_connection() {
        crypto::setup_crypto_provider();

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: false,
            },
            connection: Some(conn_std::tests::create_simple_connection()),
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        assert!(client.get_connection().is_some());
    }

    #[test]
    fn client_connect() {
        crypto::setup_crypto_provider();

        let client_msg_provided = Arc::new(Mutex::new(false));
        let testing_data = Arc::new(Mutex::new(HashMap::new()));

        struct TestClientVisitor {
            conn_created: Arc<Mutex<bool>>,
            conn_connected: Arc<Mutex<bool>>,
            client_msg_provided: Arc<Mutex<bool>>,
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

            fn on_client_msg_provider(
                &mut self,
                _tls_conn: &TlsClientConnection,
            ) -> Result<Option<tls::message::SessionMessage>, AppError> {
                *self.client_msg_provided.lock().unwrap() = true;
                Ok(Some(tls::message::SessionMessage::new(
                    &tls::message::DataType::ClientAccessContext,
                    &Some(
                        serde_json::to_value(tls::message::ClientAccessContext {
                            access: crypto::ca::CertAccessContext {
                                user_id: 100,
                                entity_type: crypto::ca::EntityType::Client,
                                platform: "plat1".to_string(),
                            },
                        })
                        .unwrap(),
                    ),
                )))
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
            client_msg_provided: client_msg_provided.clone(),
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
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            connection: None,
            testing_data: testing_data.clone(),
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

        assert!(*client_msg_provided.lock().unwrap());
        assert!(testing_data.lock().unwrap().contains_key("CliMsg"));
        let client_msg_json_result = serde_json::from_str::<tls::message::SessionMessage>(
            testing_data.lock().unwrap().get("CliMsg").unwrap().as_str(),
        );
        if let Err(err) = client_msg_json_result {
            panic!(
                "Unexpected client msg frame JSON parse result: err={:?}",
                &err
            );
        }

        assert_eq!(
            client_msg_json_result.unwrap(),
            tls::message::SessionMessage::new(
                &tls::message::DataType::ClientAccessContext,
                &Some(
                    serde_json::to_value(tls::message::ClientAccessContext {
                        access: crypto::ca::CertAccessContext {
                            user_id: 100,
                            entity_type: crypto::ca::EntityType::Client,
                            platform: "plat1".to_string(),
                        },
                    })
                    .unwrap(),
                ),
            )
        );

        assert!(*conn_created.lock().unwrap());
        assert!(*conn_connected.lock().unwrap());
    }

    #[test]
    fn client_poll_connection_when_not_connected() {
        crypto::setup_crypto_provider();

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: false,
            },
            connection: None,
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Ok(()) = client.poll_connection() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn client_assert_connected_when_connected() {
        crypto::setup_crypto_provider();

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: false,
            },
            connection: Some(conn_std::tests::create_simple_connection()),
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Err(err) = client.assert_connected() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn client_assert_connected_when_not_connected() {
        crypto::setup_crypto_provider();

        let tls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let client = Client {
            visitor: Box::new(MockCliVisit::new()),
            tls_client_config: Arc::new(tls_client_config),
            server_host: "server1".to_string(),
            server_port: 1234,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: false,
            },
            connection: None,
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Ok(()) = client.assert_connected() {
            panic!("Unexpected successful result");
        }
    }
}
