use std::sync::mpsc::Sender;

use anyhow::Result;

use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::net::tls_server::server_std;
use trust0_common::proxy::executor::ProxyExecutorEvent;

/// Represents the client and gateway proxy stream addresses respectively for a connected proxy
pub type ProxyAddrs = (String, String);

/// Service proxy trait for the gateway end of the proxy (implementations are transport-layer,... specific)
pub trait GatewayServiceProxy: Send {
    /// Startup service proxy (for clients to connect to desired service)
    fn startup(&mut self) -> Result<(), AppError>;

    /// Shutdown service proxy
    fn shutdown(&mut self);
}

/// Gateway service proxy visitor trait (implementations are transport-layer,... specific)
pub trait GatewayServiceProxyVisitor: server_std::ServerVisitor + Send {
    /// Service accessor
    fn get_service(&self) -> Service;

    /// Gateway host for service proxy
    fn get_proxy_host(&self) -> Option<String>;

    /// Gateway port for service proxy
    fn get_proxy_port(&self) -> u16;

    /// Client and gateway proxy key and stream addresses list for proxy connections (else None if no proxy active)
    /// Returns list of tuple of (proxy key, (client address, gateway address))
    fn get_proxy_keys_for_user(&self, user_id: u64) -> Vec<(String, ProxyAddrs)>;

    /// Shutdown the active service proxy connections. Consider either all connections or for given user ID.
    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        user_id: Option<u64>,
    ) -> Result<(), AppError>;

    /// Shutdown service proxy connection.
    fn shutdown_connection(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        proxy_key: &str,
    ) -> Result<(), AppError>;

    /// Remove proxy for given proxy key. Returns true if service proxy contained proxy key (and removed)
    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::mock;
    use pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
    use rustls::crypto::CryptoProvider;
    use rustls::server::{Accepted, WebPkiClientVerifier};
    use rustls::ServerConfig;
    use std::path::PathBuf;
    use std::sync::Arc;
    use trust0_common::crypto::file::{load_certificates, load_private_key};
    use trust0_common::net::tls_server::{conn_std, server_std};

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "root-ca.crt.pem"];
    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.crt.pem"];
    const KEYFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.key.pem"];

    // mocks
    // =====

    mock! {
        pub GwSvcProxyVisitor {}
        impl server_std::ServerVisitor for GwSvcProxyVisitor {
            fn create_client_conn(&mut self, tls_conn: conn_std::TlsServerConnection) -> Result<conn_std::Connection, AppError>;
            fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError>;
            fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError>;
        }
        impl GatewayServiceProxyVisitor for GwSvcProxyVisitor {
            fn get_service(&self) -> Service;
            fn get_proxy_host(&self) -> Option<String>;
            fn get_proxy_port(&self) -> u16;
            fn get_proxy_keys_for_user(&self, user_id: u64) -> Vec<(String, ProxyAddrs)>;
            fn shutdown_connections(&mut self, proxy_tasks_sender: &Sender<ProxyExecutorEvent>, user_id: Option<u64>) -> Result<(), AppError>;
            fn shutdown_connection(&mut self, proxy_tasks_sender: &Sender<ProxyExecutorEvent>, proxy_key: &str) -> Result<(), AppError>;
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
}
