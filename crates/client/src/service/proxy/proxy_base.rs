use anyhow::Result;
use std::sync::mpsc::Sender;

use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::proxy::executor::ProxyExecutorEvent;

/// Service proxy trait for the client end of the proxy (implementations are transport-layer,... specific)
pub trait ClientServiceProxy: Send {
    /// Startup proxy listener (for clients to connect to gateway proxy for service)
    fn startup(&mut self) -> Result<(), AppError>;
}

/// Client service proxy visitor trait (implementations are transport-layer,... specific)
pub trait ClientServiceProxyVisitor: Send {
    /// Service accessor
    fn get_service(&self) -> &Service;

    /// Client port for service proxy
    fn get_client_proxy_port(&self) -> u16;

    /// Gateway host for service proxy
    fn get_gateway_proxy_host(&self) -> &str;

    /// Gateway port for service proxy
    fn get_gateway_proxy_port(&self) -> u16;

    /// Request a server shutdown
    fn set_shutdown_requested(&mut self);

    /// Shutdown proxy connection for service
    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    ) -> Result<(), AppError>;

    /// Remove proxy for given proxy key. Returns whether removed else not found
    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::mock;
    use pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
    use rustls::crypto::CryptoProvider;
    use rustls::server::{Acceptor, WebPkiClientVerifier};
    use rustls::ServerConfig;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
    use trust0_common::crypto::file::{load_certificates, load_private_key};

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "root-ca.crt.pem"];
    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.crt.pem"];
    const KEYFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.key.pem"];

    // mocks
    // =====

    mock! {
        pub CliSvcProxyVisitor {}
        impl ClientServiceProxyVisitor for CliSvcProxyVisitor {
            fn get_service(&self) -> &Service;
            fn get_client_proxy_port(&self) -> u16;
            fn get_gateway_proxy_host(&self) -> &str;
            fn get_gateway_proxy_port(&self) -> u16;
            fn set_shutdown_requested(&mut self);
            fn shutdown_connections(&mut self, proxy_tasks_sender: Sender<ProxyExecutorEvent>) -> Result<(), AppError>;
            fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
        }
    }

    // utils
    // =====

    pub fn create_tls_server_config(
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<ServerConfig, anyhow::Error> {
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

    pub(crate) fn spawn_tls_server_listener(
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

                conn_idx += 1;
                if conn_idx == num_connections {
                    break;
                }
            }
        });

        Ok(())
    }
}
