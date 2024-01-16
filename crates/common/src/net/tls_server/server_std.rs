use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

use anyhow::Result;
use rustls::server::{Accepted, Acceptor};

use crate::error::AppError;
use crate::logging::{error, info};
use crate::net::tls_server::conn_std::{self, TlsServerConnection};
use crate::target;

/// This is a TLS server, which will listen/accept client connections
///
/// It has a TCP-level stream, a TLS-level connection state, and some other state/metadata.
pub struct Server {
    visitor: Arc<Mutex<dyn ServerVisitor>>,
    _server_port: u16,
    tcp_listener: Option<TcpListener>,
    listen_addr: String,
    polling: bool,
    closing: bool,
    closed: bool,
}

impl Server {
    /// Server constructor
    pub fn new(visitor: Arc<Mutex<dyn ServerVisitor>>, server_port: u16) -> Self {
        Self {
            visitor,
            _server_port: server_port,
            tcp_listener: None,
            listen_addr: format!("[::]:{}", server_port),
            polling: false,
            closing: false,
            closed: false,
        }
    }

    /// Bind/listen on port
    pub fn bind_listener(&mut self) -> Result<(), AppError> {
        let server_addr: SocketAddr = self.listen_addr.parse()?;

        let tcp_listener = TcpListener::bind(server_addr).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Error setting up listener: server_addr={:?}", &server_addr),
                Box::new(err),
            )
        })?;
        tcp_listener.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making listener non-blocking: server_addr={:?}",
                    &server_addr
                ),
                Box::new(err),
            )
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
    pub fn stop_poller(&mut self) {
        self.polling = false;
    }

    /// Poll and dispatch new listener connections
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
            // Accept new connection (non-blocking
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
                        AppError::GenWithMsgAndErr(
                            format!(
                                "Error accepting connection: server_addr={:?}",
                                &self.listen_addr
                            ),
                            Box::new(err),
                        )
                    }
                })?;

        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut tcp_stream).unwrap();
            if let Some(accepted) = acceptor.accept().map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error reading TLS client hello: server_addr={:?}, peer_addr={:?}",
                        &self.listen_addr, &peer_addr
                    ),
                    Box::new(err.clone()),
                )
            })? {
                break accepted;
            }
        };

        let tls_server_config =
            Arc::new(self.visitor.lock().unwrap().on_tls_handshaking(&accepted)?);

        let mut tls_srv_conn = accepted.into_connection(tls_server_config).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Error creating TLS server connection: server_addr={:?}, peer_addr={:?}",
                    &self.listen_addr, &peer_addr
                ),
                Box::new(err),
            )
        })?;

        let _ = tls_srv_conn.complete_io(&mut tcp_stream).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Error completing TLS server connection: server_addr={:?}, peer_addr={:?}",
                    &self.listen_addr, &peer_addr
                ),
                Box::new(err),
            )
        })?;

        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making socket non-blocking: server_addr={:?}, peer_addr={:?}",
                    &self.listen_addr, &peer_addr
                ),
                Box::new(err),
            )
        })?;

        let tls_conn = rustls::StreamOwned::new(tls_srv_conn, tcp_stream);

        let connection = self.visitor.lock().unwrap().create_client_conn(tls_conn)?;

        info(
            &target!(),
            &format!("Client connected: peer_addr={:?}", &peer_addr),
        );

        self.visitor.lock().unwrap().on_conn_accepted(connection)?;

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
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
    ) -> Result<conn_std::Connection, AppError>;

    /// Server listener bound
    fn on_listening(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Connection TLS handshaking
    fn on_tls_handshaking(
        &mut self,
        _accepted: &Accepted,
    ) -> Result<rustls::ServerConfig, AppError>;

    /// Connection accepted
    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        Server::spawn_connection_processor(connection);
        Ok(())
    }

    /// Returns whether listener shutdown is required
    fn get_shutdown_requested(&self) -> bool {
        false
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::alpn;
    use crate::crypto::file::{load_certificates, load_private_key};
    use crate::net::tls_client::client_std;
    use crate::net::tls_server::conn_std::Connection;
    use log::error;
    use mockall::{mock, predicate};
    use pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer, ServerName,
    };
    use rustls::crypto::CryptoProvider;
    use rustls::server::WebPkiClientVerifier;
    use rustls::{ClientConfig, ServerConfig};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::path::PathBuf;

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
            fn create_client_conn(&mut self, tls_conn: TlsServerConnection) -> Result<conn_std::Connection, AppError>;
            fn on_listening(&mut self) -> Result<(), AppError>;
            fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<rustls::ServerConfig, AppError>;
            fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError>;
            fn get_shutdown_requested(&self) -> bool;
        }
    }

    // utils
    // =====

    pub fn create_tls_server_config() -> Result<ServerConfig, anyhow::Error> {
        let rootca_cert_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_cert = load_certificates(rootca_cert_file.to_str().unwrap().to_string())?;
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert = load_certificates(gateway_cert_file.to_str().unwrap().to_string())?;
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key = load_private_key(gateway_key_file.to_str().unwrap().to_string())?;
        let cipher_suites: Vec<rustls::SupportedCipherSuite> =
            rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
        let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> =
            rustls::ALL_VERSIONS.to_vec();
        let alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        let mut auth_root_certs = rustls::RootCertStore::empty();
        for auth_root_cert in rootca_cert {
            auth_root_certs.add(auth_root_cert).unwrap();
        }

        let mut tls_server_config = ServerConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites,
                ..rustls::crypto::ring::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(protocol_versions.as_slice())
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
        tls_client_config: ClientConfig,
        server_host: &str,
        server_port: u16,
    ) -> Result<(), anyhow::Error> {
        let server_name = ServerName::try_from(server_host.to_string())?;
        let server_addr = (server_host, server_port)
            .to_socket_addrs()?
            .next()
            .unwrap();
        let mut tls_cli_conn =
            rustls::ClientConnection::new(Arc::new(tls_client_config), server_name)?;
        let mut tcp_stream = TcpStream::connect(server_addr)?;
        let _ = tls_cli_conn.complete_io(&mut tcp_stream)?;
        Ok(())
    }

    // tests
    // ====
    #[test]
    fn server_new() {
        let server = Server::new(Arc::new(Mutex::new(MockServerVisit::new())), 1234);

        assert_eq!(server._server_port, 1234);
        assert!(server.tcp_listener.is_none());
        assert_eq!(server.listen_addr, "[::]:1234");
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
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
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
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
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
            _server_port: 1234,
            tcp_listener: Some(tcp_listener),
            listen_addr: "127.0.0.1:0".to_string(),
            polling: true,
            closing: false,
            closed: false,
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
            _server_port: 1234,
            tcp_listener: Some(tcp_listener),
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
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
        let tcp_listener = TcpListener::bind("localhost:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let server_port = tcp_listener.local_addr().unwrap().port();
        let conn_created = Arc::new(Mutex::new(false));
        let conn_handshaking = Arc::new(Mutex::new(false));
        let conn_accepted = Arc::new(Mutex::new(false));
        let shutdown = Arc::new(Mutex::new(false));

        struct TestServerVisitor {
            conn_created: Arc<Mutex<bool>>,
            conn_handshaking: Arc<Mutex<bool>>,
            conn_accepted: Arc<Mutex<bool>>,
            shutdown: Arc<Mutex<bool>>,
        }
        impl ServerVisitor for TestServerVisitor {
            fn create_client_conn(
                &mut self,
                tls_conn: TlsServerConnection,
            ) -> Result<Connection, AppError> {
                let mut conn_visitor = conn_std::tests::MockConnVisit::new();
                conn_visitor
                    .expect_set_event_channel_sender()
                    .with(predicate::always())
                    .return_once(|_| Ok(()));
                conn_visitor.expect_on_connected().return_once(|| Ok(()));
                let conn = Connection::new(
                    Box::new(conn_visitor),
                    tls_conn,
                    alpn::Protocol::ControlPlane,
                )?;
                *self.conn_created.lock().unwrap() = true;
                Ok(conn)
            }
            fn on_tls_handshaking(
                &mut self,
                _accepted: &Accepted,
            ) -> Result<ServerConfig, AppError> {
                let config = create_tls_server_config().map_err(|err| {
                    AppError::General(format!("TLS handshaking error: err={:?}", &err))
                })?;
                *self.conn_handshaking.lock().unwrap() = true;
                Ok(config)
            }
            fn on_conn_accepted(&mut self, connection: Connection) -> Result<(), AppError> {
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
            conn_accepted: conn_accepted.clone(),
            shutdown: shutdown.clone(),
        }));

        let server = Arc::new(Mutex::new(Server {
            visitor: visitor.clone(),
            _server_port: 1234,
            tcp_listener: Some(tcp_listener),
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
        }));
        let server_copy = server.clone();

        let _ = thread::spawn(move || {
            if let Err(err) = server_copy.lock().unwrap().poll_new_connections() {
                error!("Unexpected result: err={:?}", &err);
            }
        });

        thread::sleep(Duration::from_millis(100));
        connect_to_tls_server(
            client_std::tests::create_tls_client_config().unwrap(),
            "localhost",
            server_port,
        )
        .unwrap();
        thread::sleep(Duration::from_millis(100));

        assert!(*conn_created.lock().unwrap());
        assert!(*conn_handshaking.lock().unwrap());
        assert!(*conn_accepted.lock().unwrap());

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
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        if let Ok(()) = server.assert_listening() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn server_shutdown_when_not_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        server.shutdown();

        assert_eq!(server.closing, true);
        assert_eq!(server.closed, true);
        assert_eq!(server.polling, false);
        assert!(server.tcp_listener.is_none());
    }

    #[test]
    fn server_shutdown_when_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: true,
            closing: false,
            closed: false,
        };

        server.shutdown();

        assert_eq!(server.closing, false);
        assert_eq!(server.closed, false);
        assert_eq!(server.polling, false);
        assert!(server.tcp_listener.is_none());
    }

    #[test]
    fn server_stop_poller_when_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: true,
            closing: false,
            closed: false,
        };

        server.stop_poller();

        assert_eq!(server.polling, false);
    }
}
