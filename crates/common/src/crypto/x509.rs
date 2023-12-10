use pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// Create DER certificate
pub fn create_der_certificate(der_cert_bytes: Vec<u8>) -> CertificateDer<'static> {
    CertificateDer::from(der_cert_bytes)
}
/// Create DER PKCS8 private key
pub fn create_der_pkcs8_private_key(der_key_bytes: Vec<u8>) -> PrivatePkcs8KeyDer<'static> {
    PrivatePkcs8KeyDer::from(der_key_bytes)
}
