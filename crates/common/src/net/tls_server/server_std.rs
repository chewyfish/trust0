use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

use anyhow::Result;
use rustls::server::{Accepted, Acceptor};

use crate::control::tls;
use crate::error::AppError;
use crate::logging::{error, info};
use crate::net::stream_utils::SessionMsgExchanger;
use crate::net::tls_server::conn_std::{self, TlsServerConnection};
use crate::target;

const CONN_COMPLETION_MAX_ATTEMPTS: usize = 60;
const CONN_COMPLETION_REATTEMPT_DELAY_MSECS: u64 = 30;

/// TLS server, which will listen/accept client connections
pub struct Server {
    /// Server visitor pattern object
    visitor: Arc<Mutex<dyn ServerVisitor>>,
    /// Address (string) used to bind listener
    listen_addr: String,
    /// TCP listener for server
    tcp_listener: Option<TcpListener>,
    /// Indicates whether currently polling new connections
    polling: bool,
    /// Indicates a request to close/shutdown server
    closing: bool,
    /// Indicates that the server has closed/shutdown
    closed: bool,
    /// Session message exchanger
    sessmsg_exchanger: SessionMsgExchanger,
    #[cfg(test)]
    /// Store information to be scrutinized by tests
    testing_data: Arc<Mutex<HashMap<String, String>>>,
}

impl Server {
    /// Server constructor
    ///
    /// # Arguments
    ///
    /// * `visitor` - Server visitor pattern object
    /// * `server_host` - Address host to use in bound socket
    /// * `server_port` - Address port to use in listener socket address
    /// * `expect_client_msg` - Upon handshake completion, retrieve initial client message (if applicable)
    ///
    /// # Returns
    ///
    /// A newly constructed [`Server`] object.
    ///
    pub fn new(
        visitor: Arc<Mutex<dyn ServerVisitor>>,
        server_host: &str,
        server_port: u16,
        expect_client_msg: bool,
    ) -> Self {
        Self {
            visitor,
            listen_addr: format!("{}:{}", server_host, server_port),
            tcp_listener: None,
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: expect_client_msg,
            },
            #[cfg(test)]
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Bind/listen on port
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure to bind listener.
    ///
    pub fn bind_listener(&mut self) -> Result<(), AppError> {
        let server_addr: SocketAddr = self.listen_addr.parse()?;

        let tcp_listener = TcpListener::bind(server_addr).map_err(|err| {
            AppError::General(format!(
                "Error setting up listener: server_addr={:?}, err={:?}",
                &server_addr, &err
            ))
        })?;
        tcp_listener.set_nonblocking(true).map_err(|err| {
            AppError::General(format!(
                "Failed making listener non-blocking: server_addr={:?}, err={:?}",
                &server_addr, &err
            ))
        })?;

        self.tcp_listener = Some(tcp_listener);
        self.listen_addr = format!("{:?}", &server_addr);
        self.closing = false;
        self.closed = false;
        self.polling = false;

        info(
            &target!(),
            &format!("Server started: addr={:?}", &server_addr),
        );

        self.visitor.lock().unwrap().on_listening()
    }

    /// Request shutdown for poller and listener
    pub fn shutdown(&mut self) {
        if !self.polling {
            self.perform_shutdown();
        } else {
            self.polling = false;
        }
    }

    /// Request shutdown for poller
    ///
    pub fn stop_poller(&mut self) {
        self.polling = false;
    }

    /// Poll and dispatch new listener connections
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of poller operation.
    ///
    pub fn poll_new_connections(&mut self) -> Result<(), AppError> {
        self.assert_listening()?;

        if self.polling {
            return Err(AppError::General(format!(
                "Already polling for new connections: server_addr={:?}",
                &self.listen_addr
            )));
        }

        self.polling = true;

        info(
            &target!(),
            &format!(
                "Polling connections started: server_addr={:?}",
                &self.listen_addr
            ),
        );

        loop {
            // Accept new connection (non-blocking)
            if let Err(err) = self.accept() {
                match err {
                    AppError::WouldBlock => {}
                    _ => error(&target!(), &format!("{:?}", err)),
                }
            }

            // Check if shutdown requested
            if self.visitor.lock().unwrap().get_shutdown_requested() {
                self.polling = false;
                self.closing = true;
            }

            if !self.polling {
                break;
            }

            // Add delay between accepts
            thread::sleep(Duration::from_millis(30));
        }

        info(
            &target!(),
            &format!(
                "Polling connections ended: server_addr={:?}",
                &self.listen_addr
            ),
        );

        if self.closing {
            self.perform_shutdown();
        }

        Ok(())
    }

    /// Spawn a thread to handle connection processing
    ///
    /// # Arguments
    ///
    /// * `connection` - A [`conn_std::Connection] object to use for processing
    ///
    pub fn spawn_connection_processor(mut connection: conn_std::Connection) {
        thread::spawn(move || {
            let result = {
                let mut result: Option<Result<(), AppError>> = None;

                let peer_addr: String;
                if let Ok(socket_addr) = connection.get_tcp_stream().peer_addr() {
                    peer_addr = format!("{:?}", socket_addr);
                } else {
                    peer_addr = "(unknown)".to_string();
                }

                // Poll connection events
                if let Err(err) = connection.poll_connection() {
                    result = Some(Err(err));
                }

                // Shutdown connection (if needed)
                if let Err(err) = connection.shutdown() {
                    if result.is_none() {
                        result = Some(Err(err));
                    }
                }

                info(
                    &target!(),
                    &format!("Client disconnected: peer_addr={}", &peer_addr),
                );

                result.unwrap_or(Ok(()))
            };

            if let Err(err) = result {
                error(&target!(), &format!("{:?}", err));
            }
        });
    }

    /// shutdown for poller and listener
    fn perform_shutdown(&mut self) {
        self.closing = true;
        self.closed = true;
        self.polling = false;
        self.tcp_listener = None;

        info(
            &target!(),
            &format!("Server shutdown: server_addr={:?}", &self.listen_addr),
        );
    }

    /// New connection acceptance processor
    fn accept(&mut self) -> Result<(), AppError> {
        // Accept new connection
        let (mut tcp_stream, peer_addr) =
            self.tcp_listener
                .as_ref()
                .unwrap()
                .accept()
                .map_err(|err| {
                    if err.kind() == io::ErrorKind::WouldBlock {
                        AppError::WouldBlock
                    } else {
                        AppError::General(format!(
                            "Error accepting connection: server_addr={:?}, err={:?}",
                            &self.listen_addr, &err
                        ))
                    }
                })?;

        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut tcp_stream).unwrap();
            if let Some(accepted) = acceptor.accept().map_err(|err| {
                AppError::General(format!(
                    "Error reading TLS client hello: server_addr={:?}, peer_addr={:?}, err={:?}",
                    &self.listen_addr, &peer_addr, &err
                ))
            })? {
                break accepted;
            }
        };

        let tls_server_config =
            Arc::new(self.visitor.lock().unwrap().on_tls_handshaking(&accepted)?);

        let mut tls_srv_conn = accepted.into_connection(tls_server_config).map_err(|err| {
            AppError::General(format!(
                "Error creating TLS server connection: server_addr={:?}, peer_addr={:?}, err={:?}",
                &self.listen_addr, &peer_addr, &err
            ))
        })?;

        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::General(format!(
                "Failed making socket non-blocking: server_addr={:?}, peer_addr={:?}, err={:?}",
                &self.listen_addr, &peer_addr, &err
            ))
        })?;

        // Complete TLS connection in separate thread
        let server_msg = self
            .visitor
            .lock()
            .unwrap()
            .on_server_msg_provider(&tls_srv_conn, &tcp_stream)?;

        let listen_addr = self.listen_addr.clone();
        let visitor = self.visitor.clone();
        let sessmsg_exchanger = self.sessmsg_exchanger.clone();

        #[allow(clippy::type_complexity)]
        let testing_data: Option<Arc<Mutex<HashMap<String, String>>>>;
        #[cfg(test)]
        {
            testing_data = Some(self.testing_data.clone());
        }
        #[cfg(not(test))]
        {
            testing_data = None;
        }

        let _ = thread::spawn(move || {
            let conn_context_log =
                format!("server_addr={:?}, peer_addr={:?}", &listen_addr, &peer_addr);
            let reattempt_delay = Duration::from_millis(CONN_COMPLETION_REATTEMPT_DELAY_MSECS);
            for attempt in 0..CONN_COMPLETION_MAX_ATTEMPTS {
                match tls_srv_conn.complete_io(&mut tcp_stream) {
                    Ok(_) => break,
                    Err(err) if io::ErrorKind::WouldBlock == err.kind() => {}
                    Err(err) => {
                        error(
                            &target!(),
                            &format!(
                                "Error completing TLS connection: {}, err={:?}",
                                &conn_context_log, &err
                            ),
                        );
                        return;
                    }
                }
                if attempt == (CONN_COMPLETION_MAX_ATTEMPTS - 1) {
                    error(
                        &target!(),
                        &format!(
                            "Exhausted attempting to complete TLS connection: {}",
                            &conn_context_log
                        ),
                    );
                    return;
                }
                thread::sleep(reattempt_delay);
            }

            let mut tls_conn = rustls::StreamOwned::new(tls_srv_conn, tcp_stream);
            if let Some(server_msg) = server_msg {
                if let Some(testing_data) = &testing_data {
                    testing_data.lock().unwrap().insert(
                        "SvrMsg".to_string(),
                        serde_json::to_string(&server_msg).unwrap(),
                    );
                }
                if let Err(err) =
                    sessmsg_exchanger.write_session_message(&mut tls_conn, &server_msg)
                {
                    error(
                        &target!(),
                        &format!(
                            "Error writing server session messages: {}, err={:?}",
                            &conn_context_log, &err
                        ),
                    );
                    return;
                }
            }

            let client_msg = match sessmsg_exchanger.read_session_message(&mut tls_conn) {
                Ok(client_msg) => client_msg,
                Err(err) => {
                    error(
                        &target!(),
                        &format!(
                            "Error reading client session message: {}, err={:?}",
                            &conn_context_log, &err
                        ),
                    );
                    return;
                }
            };

            let connection = match visitor
                .lock()
                .unwrap()
                .create_client_conn(tls_conn, client_msg)
            {
                Ok(connection) => connection,
                Err(err) => {
                    error(
                        &target!(),
                        &format!(
                            "Error creating TLS connection: {}, err={:?}",
                            &conn_context_log, &err
                        ),
                    );
                    return;
                }
            };

            info(
                &target!(),
                &format!("Client connected: peer_addr={:?}", &peer_addr),
            );

            if let Err(err) = visitor.lock().unwrap().on_conn_accepted(connection) {
                error(
                    &target!(),
                    &format!(
                        "Error invoking TLS connection accepted hook: server_addr={:?}, peer_addr={:?}, err={:?}",
                        &listen_addr, &peer_addr, &err
                    ),
                );
            }
        });

        Ok(())
    }

    fn assert_listening(&self) -> Result<(), AppError> {
        if self.tcp_listener.is_none() {
            return Err(AppError::General("Gateway not listening".to_string()));
        }
        Ok(())
    }
}

unsafe impl Send for Server {}

/// Visitor pattern used to customize server implementation strategy.
pub trait ServerVisitor: Send {
    /// TLS client connection factory
    ///
    /// # Arguments
    ///
    /// * `tls_conn` - TLS connection
    /// * `client_msg`: Optional initial message from client
    ///
    /// # Returns
    ///
    /// A [`Result`] of the [`conn_std::Connection`] for this client connection.
    ///
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
        client_msg: Option<tls::message::SessionMessage>,
    ) -> Result<conn_std::Connection, AppError>;

    /// Server listener bound event handler
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of function call.
    ///
    fn on_listening(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Connection TLS handshaking event handler
    ///
    /// # Arguments
    ///
    /// * `accepted` - A TLS accepted object for newly created TLS connection
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`rustls::ServerConfig`] for the TLS connection.
    ///
    fn on_tls_handshaking(
        &mut self,
        _accepted: &Accepted,
    ) -> Result<rustls::ServerConfig, AppError>;

    /// Connection server message provider handler
    ///
    /// # Arguments
    ///
    /// * `server_conn` - TLS server connection object
    /// * `tcp_stream` - TCP connection socket stream
    ///
    /// # Returns
    ///
    /// A [`Result`] containing an optional [`tls::message::SessionMessage`] object to be sent immediately after handshaking.
    ///
    fn on_server_msg_provider(
        &mut self,
        _server_conn: &rustls::ServerConnection,
        _tcp_stream: &TcpStream,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        Ok(None)
    }

    /// Connection accepted event handler
    ///
    /// # Arguments
    ///
    /// * `connection` - [`conn_std::Connection`] object which was successfully accepted.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of function call.
    //
    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        Server::spawn_connection_processor(connection);
        Ok(())
    }

    /// Returns whether listener shutdown is required
    ///
    /// # Returns
    ///
    /// Whether or not a shutdown should be performed.
    ///
    fn get_shutdown_requested(&self) -> bool {
        false
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::file::{load_certificates, load_private_key};
    use crate::crypto::{self, alpn};
    use crate::net::stream_utils;
    use crate::net::tls_client::client_std;
    use crate::net::tls_server::conn_std::ConnectionEvent;
    use log::error;
    use mockall::{mock, predicate};
    use pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer, ServerName,
    };
    use rustls::crypto::CryptoProvider;
    use rustls::server::WebPkiClientVerifier;
    use std::net::{TcpStream, ToSocketAddrs};
    use std::path::PathBuf;
    use std::sync::mpsc;

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "root-ca.local.crt.pem",
    ];
    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "gateway.local.crt.pem",
    ];
    const KEYFILE_GATEWAY_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "gateway.local.key.pem",
    ];

    // mocks
    // =====

    mock! {
        pub ServerVisit {}
        impl ServerVisitor for ServerVisit {
            fn create_client_conn(&mut self, tls_conn: TlsServerConnection, client_msg: Option<tls::message::SessionMessage>,
            ) -> Result<conn_std::Connection, AppError>;
            fn on_listening(&mut self) -> Result<(), AppError>;
            fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<rustls::ServerConfig, AppError>;
            fn on_server_msg_provider(
                &mut self,
                _server_conn: &rustls::ServerConnection,
                _tcp_stream: &TcpStream,
            ) -> Result<Option<tls::message::SessionMessage>, AppError>;
            fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError>;
            fn get_shutdown_requested(&self) -> bool;
        }
    }

    // utils
    // =====

    pub fn create_tls_server_config() -> Result<rustls::ServerConfig, anyhow::Error> {
        let rootca_cert_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_cert = load_certificates(rootca_cert_file.to_str().as_ref().unwrap())?;
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert = load_certificates(gateway_cert_file.to_str().as_ref().unwrap())?;
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key = load_private_key(gateway_key_file.to_str().as_ref().unwrap())?;
        let cipher_suites: Vec<rustls::SupportedCipherSuite> =
            rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
        let alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        let mut auth_root_certs = rustls::RootCertStore::empty();
        for auth_root_cert in rootca_cert {
            auth_root_certs.add(auth_root_cert).unwrap();
        }

        let mut tls_server_config = rustls::ServerConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites,
                ..rustls::crypto::ring::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("Inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(auth_root_certs.clone()))
                .with_crls(vec![])
                .build()
                .unwrap(),
        )
        .with_single_cert(
            gateway_cert.clone(),
            match &gateway_key {
                PrivateKeyDer::Pkcs1(key_der) => {
                    Ok(PrivatePkcs1KeyDer::from(key_der.secret_pkcs1_der().to_vec()).into())
                }
                PrivateKeyDer::Pkcs8(key_der) => {
                    Ok(PrivatePkcs8KeyDer::from(key_der.secret_pkcs8_der().to_vec()).into())
                }
                PrivateKeyDer::Sec1(key_der) => {
                    Ok(PrivateSec1KeyDer::from(key_der.secret_sec1_der().to_vec()).into())
                }
                _ => Err(AppError::General(format!(
                    "Unsupported key type: key={:?}",
                    &gateway_key
                ))),
            }?,
        )
        .expect("Bad certificates/private key");

        tls_server_config.key_log = Arc::new(rustls::KeyLogFile::new());
        tls_server_config.alpn_protocols = alpn_protocols;

        Ok(tls_server_config)
    }

    fn connect_to_tls_server(
        tls_client_config: rustls::ClientConfig,
        server_host: &str,
        server_port: u16,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
        let server_name = ServerName::try_from(server_host.to_string())?;
        let server_addr = (server_host, server_port)
            .to_socket_addrs()?
            .next()
            .unwrap();
        let mut tls_cli_conn =
            rustls::ClientConnection::new(Arc::new(tls_client_config), server_name)?;
        let mut tcp_stream = TcpStream::connect(server_addr)?;
        let _ = tls_cli_conn.complete_io(&mut tcp_stream)?;
        let mut tls_conn = rustls::StreamOwned::new(tls_cli_conn, tcp_stream);

        let sessmsg_exchanger = SessionMsgExchanger {
            expect_inbound_msg: true,
        };

        let _server_msg = sessmsg_exchanger.read_session_message(&mut tls_conn)?;
        sessmsg_exchanger.write_session_message(
            &mut tls_conn,
            &tls::message::SessionMessage::new(
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
            ),
        )?;

        Ok(tls_conn)
    }

    // tests
    // ====
    #[test]
    fn server_new() {
        let server_visitor: Arc<Mutex<dyn ServerVisitor>> =
            Arc::new(Mutex::new(MockServerVisit::new()));
        let server = Server::new(server_visitor, "127.0.0.1", 1234, true);

        assert!(server.tcp_listener.is_none());
        assert_eq!(server.listen_addr, "127.0.0.1:1234");
        assert_eq!(
            server.sessmsg_exchanger,
            SessionMsgExchanger {
                expect_inbound_msg: true
            }
        );
        assert!(!server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_bind_listener() {
        let mut visitor = MockServerVisit::new();
        visitor
            .expect_on_listening()
            .times(1)
            .return_once(|| Ok(()));
        let mut server = Server {
            visitor: Arc::new(Mutex::new(visitor)),
            listen_addr: "127.0.0.1:0".to_string(),
            tcp_listener: None,
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Err(err) = server.bind_listener() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server.tcp_listener.is_some());
        assert!(!server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_not_listening() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            listen_addr: "127.0.0.1:0".to_string(),
            tcp_listener: None,
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: false,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Ok(()) = server.poll_new_connections() {
            panic!("Unexpected successful result");
        }

        assert!(server.tcp_listener.is_none());
        assert!(!server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_already_polling() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            listen_addr: "127.0.0.1:0".to_string(),
            tcp_listener: Some(tcp_listener),
            polling: true,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Ok(()) = server.poll_new_connections() {
            panic!("Unexpected successful result");
        }

        assert!(server.tcp_listener.is_some());
        assert!(server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_2nd_iteration_shutdown_request() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let mut visitor = MockServerVisit::new();
        visitor
            .expect_get_shutdown_requested()
            .times(1)
            .return_once(|| false);
        visitor
            .expect_get_shutdown_requested()
            .times(1)
            .return_once(|| true);
        let mut server = Server {
            visitor: Arc::new(Mutex::new(visitor)),
            listen_addr: "127.0.0.1:0".to_string(),
            tcp_listener: Some(tcp_listener),
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Err(err) = server.poll_new_connections() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server.tcp_listener.is_none());
        assert!(!server.polling);
        assert!(server.closing);
        assert!(server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_connection_request() {
        crypto::setup_crypto_provider();

        let tcp_listener = TcpListener::bind("localhost:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let server_port = tcp_listener.local_addr().unwrap().port();
        let conn_created = Arc::new(Mutex::new(false));
        let conn_handshaking = Arc::new(Mutex::new(false));
        let server_msg_provided = Arc::new(Mutex::new(false));
        let client_msg = Arc::new(Mutex::new(None));
        let conn_accepted = Arc::new(Mutex::new(false));
        let shutdown = Arc::new(Mutex::new(false));
        let testing_data = Arc::new(Mutex::new(HashMap::new()));

        struct TestServerVisitor {
            conn_created: Arc<Mutex<bool>>,
            conn_handshaking: Arc<Mutex<bool>>,
            server_msg_provided: Arc<Mutex<bool>>,
            client_msg: Arc<Mutex<Option<tls::message::SessionMessage>>>,
            conn_accepted: Arc<Mutex<bool>>,
            shutdown: Arc<Mutex<bool>>,
            connection_event_sender: Option<mpsc::Sender<ConnectionEvent>>,
        }
        impl ServerVisitor for TestServerVisitor {
            fn create_client_conn(
                &mut self,
                tls_conn: TlsServerConnection,
                client_msg: Option<tls::message::SessionMessage>,
            ) -> Result<conn_std::Connection, AppError> {
                let mut conn_visitor = conn_std::tests::MockConnVisit::new();
                conn_visitor
                    .expect_on_connected()
                    .with(predicate::always())
                    .return_once(|_| Ok(()));
                conn_visitor.expect_on_polling_cycle().returning(|| Ok(()));
                conn_visitor.expect_on_shutdown().return_once(|| Ok(()));
                let tcp_stream =
                    stream_utils::clone_std_tcp_stream(&tls_conn.sock, "net-tls-server")?;
                let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
                stream_rw
                    .expect_read()
                    .with(predicate::always())
                    .returning(|_| Ok(0));
                stream_rw
                    .expect_write_all()
                    .with(predicate::always())
                    .returning(|_| Ok(()));
                let conn = conn_std::tests::create_connection(
                    Box::new(conn_visitor),
                    Some(tls_conn),
                    Some(Box::new(stream_rw)),
                    Some(tcp_stream),
                    mpsc::channel(),
                    alpn::Protocol::ControlPlane,
                    false,
                );
                *self.conn_created.lock().unwrap() = true;
                *self.client_msg.lock().unwrap() = client_msg;
                Ok(conn)
            }

            fn on_tls_handshaking(
                &mut self,
                _accepted: &Accepted,
            ) -> Result<rustls::ServerConfig, AppError> {
                let config = create_tls_server_config().map_err(|err| {
                    AppError::General(format!("TLS handshaking error: err={:?}", &err))
                })?;
                *self.conn_handshaking.lock().unwrap() = true;
                Ok(config)
            }

            fn on_server_msg_provider(
                &mut self,
                _server_conn: &rustls::ServerConnection,
                _tcp_stream: &TcpStream,
            ) -> Result<Option<tls::message::SessionMessage>, AppError> {
                *self.server_msg_provided.lock().unwrap() = true;
                Ok(Some(tls::message::SessionMessage::new(
                    &tls::message::DataType::Trust0Connection,
                    &Some(
                        serde_json::to_value(tls::message::Trust0Connection::new(&(
                            "addr1".to_string(),
                            "addr2".to_string(),
                        )))
                        .unwrap(),
                    ),
                )))
            }

            fn on_conn_accepted(
                &mut self,
                connection: conn_std::Connection,
            ) -> Result<(), AppError> {
                self.connection_event_sender = Some(connection.clone_event_channel_sender());
                Server::spawn_connection_processor(connection);
                *self.conn_accepted.lock().unwrap() = true;
                Ok(())
            }

            fn get_shutdown_requested(&self) -> bool {
                *self.shutdown.lock().unwrap()
            }
        }

        let visitor = Arc::new(Mutex::new(TestServerVisitor {
            conn_created: conn_created.clone(),
            conn_handshaking: conn_handshaking.clone(),
            server_msg_provided: server_msg_provided.clone(),
            client_msg: client_msg.clone(),
            conn_accepted: conn_accepted.clone(),
            shutdown: shutdown.clone(),
            connection_event_sender: None,
        }));

        let server = Arc::new(Mutex::new(Server {
            visitor: visitor.clone(),
            listen_addr: "127.0.0.1:0".to_string(),
            tcp_listener: Some(tcp_listener),
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: testing_data.clone(),
        }));
        let server_copy = server.clone();

        let _ = thread::spawn(move || {
            if let Err(err) = server_copy.lock().unwrap().poll_new_connections() {
                error!("Unexpected result: err={:?}", &err);
            }
        });

        thread::sleep(Duration::from_millis(100));
        let _ = connect_to_tls_server(
            client_std::tests::create_tls_client_config().unwrap(),
            "localhost",
            server_port,
        )
        .unwrap();
        thread::sleep(Duration::from_millis(100));

        assert!(*conn_created.lock().unwrap());
        assert!(*conn_handshaking.lock().unwrap());
        assert!(*server_msg_provided.lock().unwrap());
        assert!(*conn_accepted.lock().unwrap());

        assert!(testing_data.lock().unwrap().contains_key("SvrMsg"));
        let server_msg_json_result = serde_json::from_str::<tls::message::SessionMessage>(
            testing_data.lock().unwrap().get("SvrMsg").unwrap().as_str(),
        );
        if let Err(err) = server_msg_json_result {
            panic!(
                "Unexpected server msg frame JSON parse result: err={:?}",
                &err
            );
        }

        assert_eq!(
            server_msg_json_result.unwrap(),
            tls::message::SessionMessage::new(
                &tls::message::DataType::Trust0Connection,
                &Some(
                    serde_json::to_value(tls::message::Trust0Connection::new(&(
                        "addr1".to_string(),
                        "addr2".to_string(),
                    )))
                    .unwrap(),
                ),
            )
        );

        assert!(client_msg.lock().unwrap().is_some());
        assert_eq!(
            client_msg.lock().unwrap().as_ref().unwrap(),
            &tls::message::SessionMessage::new(
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

        visitor
            .lock()
            .unwrap()
            .connection_event_sender
            .as_ref()
            .unwrap()
            .send(ConnectionEvent::Closing)
            .unwrap();
        *shutdown.lock().unwrap() = true;
        thread::sleep(Duration::from_millis(100));

        assert!(server.lock().unwrap().tcp_listener.is_none());
        assert!(!server.lock().unwrap().polling);
        assert!(server.lock().unwrap().closing);
        assert!(server.lock().unwrap().closed);
    }

    #[test]
    fn server_assert_listening_when_not_listening() {
        let server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            listen_addr: "addr1".to_string(),
            tcp_listener: None,
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Ok(()) = server.assert_listening() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn server_shutdown_when_not_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            listen_addr: "addr1".to_string(),
            tcp_listener: None,
            polling: false,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        server.shutdown();

        assert!(server.closing);
        assert!(server.closed);
        assert!(!server.polling);
        assert!(server.tcp_listener.is_none());
    }

    #[test]
    fn server_shutdown_when_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            listen_addr: "addr1".to_string(),
            tcp_listener: None,
            polling: true,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        server.shutdown();

        assert!(!server.closing);
        assert!(!server.closed);
        assert!(!server.polling);
        assert!(server.tcp_listener.is_none());
    }

    #[test]
    fn server_stop_poller_when_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            listen_addr: "addr1".to_string(),
            tcp_listener: None,
            polling: true,
            closing: false,
            closed: false,
            sessmsg_exchanger: SessionMsgExchanger {
                expect_inbound_msg: true,
            },
            testing_data: Arc::new(Mutex::new(HashMap::new())),
        };

        server.stop_poller();

        assert!(!server.polling);
    }

    #[test]
    fn srvvisit_trait_defaults() {
        crypto::setup_crypto_provider();

        struct ServerVisitorImpl {}
        impl ServerVisitor for ServerVisitorImpl {
            fn create_client_conn(
                &mut self,
                _tls_conn: TlsServerConnection,
                _client_msg: Option<tls::message::SessionMessage>,
            ) -> Result<conn_std::Connection, AppError> {
                Err(AppError::General("Not to be tested".to_string()))
            }
            fn on_tls_handshaking(
                &mut self,
                _accepted: &Accepted,
            ) -> Result<rustls::ServerConfig, AppError> {
                Err(AppError::General("Not to be tested".to_string()))
            }
        }

        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();

        let mut server_visitor = ServerVisitorImpl {};

        if let Err(err) = server_visitor.on_listening() {
            panic!("Unexpected 'on_listening' result: err={:?}", &err);
        }
        if let Err(err) = server_visitor.on_server_msg_provider(
            &rustls::ServerConnection::new(Arc::new(create_tls_server_config().unwrap())).unwrap(),
            &connected_tcp_stream.server_stream.0,
        ) {
            panic!("Unexpected 'on_server_msg_provider' result: err={:?}", &err);
        }
        if let Err(err) = server_visitor.on_conn_accepted(conn_std::tests::create_connection(
            Box::new(conn_std::tests::MockConnVisit::new()),
            None,
            Some(Box::new(stream_utils::tests::MockStreamReadWrite::new())),
            None,
            mpsc::channel(),
            alpn::Protocol::ControlPlane,
            false,
        )) {
            panic!("Unexpected 'on_onn_accepted' result: err={:?}", &err);
        }
        assert!(!server_visitor.get_shutdown_requested());
    }
}
