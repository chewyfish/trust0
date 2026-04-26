use anyhow::Result;
use std::sync::mpsc::Sender;
use trust0_common::control::tls::message::ConnectionAddrs;
use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::net::tls_server::server_std;
use trust0_common::proxy::executor::ProxyExecutorEvent;

/// Service proxy trait for the gateway end of the proxy (implementations are transport-layer,... specific)
pub trait GatewayServiceProxy: Send {
    /// Startup service proxy (for clients to connect to desired service)
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of startup.
    ///
    fn startup(&mut self) -> Result<(), AppError>;

    /// Shutdown service proxy
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of shutdown.
    ///
    #[allow(dead_code)]
    fn shutdown(&mut self);
}

/// Gateway service proxy visitor trait (implementations are transport-layer,... specific)
pub trait GatewayServiceProxyVisitor: server_std::ServerVisitor + Send {
    /// Service accessor
    ///
    /// # Returns
    ///
    /// [`Service`] associated to proxy
    ///
    fn get_service(&self) -> Service;

    /// Gateway host for service proxy
    ///
    /// # Returns
    ///
    /// Proxy server host
    ///
    fn get_proxy_host(&self) -> Option<String>;

    /// Gateway port for service proxy
    ///
    /// # Returns
    ///
    /// Proxy server port
    ///
    fn get_proxy_port(&self) -> u16;

    /// Client and gateway proxy key and stream addresses list for proxy connections (else None if no proxy active)
    /// Returns list of tuple of (proxy key, (client address, gateway address))
    ///
    /// # Arguments
    ///
    /// * `device_id` - Device ID for proxy keys request
    ///
    /// # Returns
    ///
    /// A list of (proxy key, (client address, gateway address)) for device.
    ///
    fn get_proxy_keys_for_device(&self, device_id: &str) -> Vec<(String, ConnectionAddrs)>;

    /// Shutdown the active service proxy connections. Consider either all connections or for given device ID.
    ///
    /// # Arguments
    ///
    /// * `proxy_tasks_sender` - A channel sender to send events to the proxy executor
    /// * `device_id` - Device ID of proxy connections, else all connections if not supplied
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of shutdown operation.
    ///
    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        device_id: Option<String>,
    ) -> Result<(), AppError>;

    /// Shutdown service proxy connection.
    ///
    /// # Arguments
    ///
    /// * `proxy_tasks_sender` - A channel sender to send events to the proxy executor
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of shutdown operation.
    ///
    fn shutdown_connection(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        proxy_key: &str,
    ) -> Result<(), AppError>;

    /// Remove proxy for given proxy key. Returns true if service proxy contained proxy key (and removed)
    ///
    /// # Arguments
    ///
    /// * `proxy_key` - Proxy key to use for removal operation
    ///
    /// # Returns
    ///
    /// Whether the removal occurred for given proxy key.
    ///
    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::mock;
    use pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
    use rustls::crypto::CryptoProvider;
    use rustls::server::{Accepted, Acceptor, WebPkiClientVerifier};
    use rustls::ServerConfig;
    use std::io::Write;
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use trust0_common::control::pdu::MessageFrame;
    use trust0_common::control::tls;
    use trust0_common::crypto;
    use trust0_common::crypto::file::{load_certificates, load_private_key};
    use trust0_common::net::tls_server::{conn_std, server_std};

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "root-ca.crt.pem"];
    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.crt.pem"];
    const KEYFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.key.pem"];
    const CERTFILE_CLIENT100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];
    const KEYFILE_CLIENT100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.key.pem",
    ];

    // mocks
    // =====

    mock! {
        pub GwSvcProxyVisitor {}
        impl server_std::ServerVisitor for GwSvcProxyVisitor {
            fn create_client_conn(&mut self, tls_conn: conn_std::TlsServerConnection, client_msg: Option<tls::message::SessionMessage>) -> Result<conn_std::Connection, AppError>;
            fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError>;
            fn on_server_msg_provider(
                &mut self,
                _server_conn: &rustls::ServerConnection,
                _tcp_stream: &TcpStream,
            ) -> Result<Option<tls::message::SessionMessage>, AppError>;
            fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError>;
        }
        impl GatewayServiceProxyVisitor for GwSvcProxyVisitor {
            fn get_service(&self) -> Service;
            fn get_proxy_host(&self) -> Option<String>;
            fn get_proxy_port(&self) -> u16;
            fn get_proxy_keys_for_device(&self, device_id: &str) -> Vec<(String, ConnectionAddrs)>;
            fn shutdown_connections(&mut self, proxy_tasks_sender: &Sender<ProxyExecutorEvent>, device_id: Option<String>) -> Result<(), AppError>;
            fn shutdown_connection(&mut self, proxy_tasks_sender: &Sender<ProxyExecutorEvent>, proxy_key: &str) -> Result<(), AppError>;
            fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
        }
    }

    // utils
    // =====

    pub fn create_tls_server_config(
        use_certkey_gateway_else_client: bool,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<ServerConfig, anyhow::Error> {
        crypto::setup_crypto_provider();

        let rootca_cert_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_cert = load_certificates(rootca_cert_file.to_str().as_ref().unwrap())?;
        let (cert, key) = match use_certkey_gateway_else_client {
            false => {
                let client100_cert_file: PathBuf = CERTFILE_CLIENT100_PATHPARTS.iter().collect();
                let client100_cert =
                    load_certificates(client100_cert_file.to_str().as_ref().unwrap())?;
                let client100_key_file: PathBuf = KEYFILE_CLIENT100_PATHPARTS.iter().collect();
                let client100_key =
                    load_private_key(client100_key_file.to_str().as_ref().unwrap())?;
                (client100_cert, client100_key)
            }
            true => {
                let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
                let gateway_cert = load_certificates(gateway_cert_file.to_str().as_ref().unwrap())?;
                let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
                let gateway_key = load_private_key(gateway_key_file.to_str().as_ref().unwrap())?;
                (gateway_cert, gateway_key)
            }
        };

        let cipher_suites: Vec<rustls::SupportedCipherSuite> =
            rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
        let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> =
            rustls::ALL_VERSIONS.to_vec();

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
            cert.clone(),
            match &key {
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
                    &key
                ))),
            }?,
        )
        .expect("Bad certificates/private key");
        tls_server_config.key_log = Arc::new(rustls::KeyLogFile::new());
        tls_server_config.alpn_protocols = alpn_protocols;

        Ok(tls_server_config)
    }

    pub fn spawn_tls_server_listener(
        tcp_listener: std::net::TcpListener,
        tls_server_config: Arc<ServerConfig>,
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

                let mut server_conn = accepted.into_connection(tls_server_config.clone()).unwrap();

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
}
