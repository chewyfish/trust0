/// Unit tests
use mockall::mock;
use pki_types::CertificateDer;
use trust0_common::net::tls_server::conn_std::TlsConnection;

// mocks
// =====

mock! {
    pub TlsSvrConn {}
    impl TlsConnection for TlsSvrConn {
        fn peer_certificates(&self) -> Option<Vec<CertificateDer<'static>>>;
        fn alpn_protocol(&self) -> Option<Vec<u8>>;
    }
}
