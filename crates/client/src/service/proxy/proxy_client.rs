use trust0_common::error::AppError;
use trust0_common::net::tls_client::{client_std, conn_std};

/// tls_client::std_client::Client strategy visitor pattern implementation
pub struct ClientVisitor {}

impl ClientVisitor {
    /// ClientVisitor constructor
    pub fn new() -> Self {
        Self {}
    }
}

impl client_std::ClientVisitor for ClientVisitor {
    fn create_server_conn(
        &mut self,
        tls_conn: conn_std::TlsClientConnection,
    ) -> Result<conn_std::Connection, AppError> {
        let conn_visitor = ServerConnVisitor::new()?;
        let connection = conn_std::Connection::new(Box::new(conn_visitor), tls_conn)?;

        Ok(connection)
    }
}

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {}

impl ServerConnVisitor {
    /// ServerConnVisitor constructor
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {})
    }
}

impl conn_std::ConnectionVisitor for ServerConnVisitor {
    fn send_error_response(&mut self, _err: &AppError) {}
}

unsafe impl Send for ServerConnVisitor {}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use pki_types::ServerName;
    use rustls::crypto::CryptoProvider;
    use rustls::StreamOwned;
    use std::path::PathBuf;
    use std::sync::Arc;
    use trust0_common::crypto::file::{load_certificates, load_private_key};
    use trust0_common::net::stream_utils;
    use trust0_common::net::tls_client::client_std::ClientVisitor;
    use trust0_common::net::tls_client::conn_std::ConnectionVisitor;

    const CERTFILE_ROOT_CA_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "root-ca.crt.pem"];
    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];
    const KEYFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.key.pem",
    ];

    // utils
    // =====

    pub fn create_tls_client_config() -> anyhow::Result<rustls::ClientConfig, anyhow::Error> {
        let rootca_cert_file: PathBuf = CERTFILE_ROOT_CA_PATHPARTS.iter().collect();
        let rootca_cert = load_certificates(rootca_cert_file.to_str().unwrap().to_string())?;
        let client_cert_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let client_cert = load_certificates(client_cert_file.to_str().unwrap().to_string())?;
        let client_key_file: PathBuf = KEYFILE_CLIENT_UID100_PATHPARTS.iter().collect();
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

    #[test]
    fn clivisit_create_server_conn() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let mut client_visitor = super::ClientVisitor::new();

        let result = client_visitor.create_server_conn(StreamOwned::new(
            rustls::ClientConnection::new(
                Arc::new(create_tls_client_config().unwrap()),
                ServerName::try_from("127.0.0.1".to_string()).unwrap(),
            )
            .unwrap(),
            stream_utils::clone_std_tcp_stream(&connected_tcp_stream.client_stream.0).unwrap(),
        ));

        assert!(result.is_ok());
    }

    #[test]
    fn svrconnvisit_new() {
        let visitor = ServerConnVisitor::new();
        assert!(visitor.is_ok());
    }

    #[test]
    fn svrconnvisit_send_error_response() {
        let mut visitor = ServerConnVisitor {};
        visitor.send_error_response(&AppError::StreamEOF);
    }
}
