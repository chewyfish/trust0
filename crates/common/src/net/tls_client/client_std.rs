use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use anyhow::Result;
use pki_types::ServerName;

use crate::error::AppError;
use crate::logging::info;
use crate::net::tls_client::conn_std;
use crate::net::tls_client::conn_std::TlsClientConnection;
use crate::target;

/// This is a TLS client, which will connect to a server and expose IO methods
///
/// It has a TCP-level stream, a TLS-level connection state, and some other state/metadata.
pub struct Client {
    visitor: Box<dyn ClientVisitor>,
    tls_client_config: Arc<rustls::ClientConfig>,
    server_host: String,
    server_port: u16,
    connection: Option<conn_std::Connection>,
}

impl Client {
    /// Client constructor
    pub fn new(
        visitor: Box<dyn ClientVisitor>,
        tls_client_config: rustls::ClientConfig,
        server_host: String,
        server_port: u16,
    ) -> Self {
        Self {
            visitor,
            tls_client_config: Arc::new(tls_client_config),
            server_host,
            server_port,
            connection: None,
        }
    }

    /// Connection accessor
    pub fn get_connection(&self) -> &Option<conn_std::Connection> {
        &self.connection
    }

    /// Connect to server
    pub fn connect(&mut self) -> Result<(), AppError> {
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

        let mut tls_cli_conn =
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

        let _ = tls_cli_conn.complete_io(&mut tcp_stream).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error completing TLS client connection".to_string(),
                Box::new(err),
            )
        })?;

        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed making socket non-blocking: addr={}", &server_addr),
                Box::new(err),
            )
        })?;

        let tls_conn = rustls::StreamOwned::new(tls_cli_conn, tcp_stream);

        let connection = self.visitor.create_server_conn(tls_conn)?;

        info(&target!(), &format!("Connected: addr={:?}", server_addr));

        self.visitor.on_connected()?;

        self.connection = Some(connection);

        Ok(())
    }

    /// Poll connection events
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
    fn create_server_conn(
        &mut self,
        tls_conn: TlsClientConnection,
    ) -> Result<conn_std::Connection, AppError>;

    /// Session connected
    fn on_connected(&mut self) -> Result<(), AppError> {
        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::file::{load_certificates, load_private_key};
    use crate::net::tls_client::conn_std::Connection;
    use crate::net::tls_server;
    use mockall::{mock, predicate};
    use rustls::crypto::CryptoProvider;
    use rustls::server::Acceptor;
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
            fn create_server_conn(&mut self, tls_conn: TlsClientConnection) -> Result<conn_std::Connection, AppError>;
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
        .with_protocol_versions(&rustls::ALL_VERSIONS.to_vec())
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
            connection: Some(conn_std::tests::create_simple_connection()),
        };

        assert!(client.get_connection().is_some());
    }

    #[test]
    fn client_connect() {
        struct TestClientVisitor {
            conn_created: Arc<Mutex<bool>>,
            conn_connected: Arc<Mutex<bool>>,
        }
        impl ClientVisitor for TestClientVisitor {
            fn create_server_conn(
                &mut self,
                tls_conn: TlsClientConnection,
            ) -> Result<Connection, AppError> {
                *self.conn_created.lock().unwrap() = true;
                let mut conn_visitor = conn_std::tests::MockConnVisit::new();
                conn_visitor
                    .expect_set_event_channel_sender()
                    .with(predicate::always())
                    .return_once(|_| ());
                conn_visitor.expect_on_connected().return_once(|| Ok(()));
                Connection::new(Box::new(conn_visitor), tls_conn)
            }
            fn on_connected(&mut self) -> Result<(), AppError> {
                *self.conn_connected.lock().unwrap() = true;
                Ok(())
            }
        }

        let conn_created = Arc::new(Mutex::new(false));
        let conn_connected = Arc::new(Mutex::new(false));
        let client_visitor = TestClientVisitor {
            conn_created: conn_created.clone(),
            conn_connected: conn_connected.clone(),
        };

        let tcp_listener = std::net::TcpListener::bind("localhost:0").unwrap();
        let server_port = tcp_listener.local_addr().unwrap().port();
        spawn_tls_server_listener(tcp_listener, 1).unwrap();

        let mut client = Client {
            visitor: Box::new(client_visitor),
            tls_client_config: Arc::new(create_tls_client_config().unwrap()),
            server_host: "localhost".to_string(),
            server_port: server_port,
            connection: None,
        };

        if let Err(err) = client.connect() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(*conn_created.lock().unwrap());
        assert!(*conn_connected.lock().unwrap());
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
            connection: None,
        };

        if let Ok(()) = client.assert_connected() {
            panic!("Unexpected successful result");
        }
    }
}
