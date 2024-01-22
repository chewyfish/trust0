use pki_types::{CertificateDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

/// Create DER certificate
///
/// # Arguments
///
/// * `der_cert_bytes` - DER certificate byte vector
///
/// # Returns
///
/// A [`CertificateDer`] object for the representative given byte vector.
///
pub fn create_der_certificate(der_cert_bytes: Vec<u8>) -> CertificateDer<'static> {
    CertificateDer::from(der_cert_bytes)
}

/// Create DER PKCS1 private key
///
/// # Arguments
///
/// * `der_key_bytes` - PKCS1 DER private key byte vector
///
/// # Returns
///
/// A [`PrivatePkcs1KeyDer`] object for the representative given byte vector.
///
pub fn create_der_pkcs1_private_key(der_key_bytes: Vec<u8>) -> PrivatePkcs1KeyDer<'static> {
    PrivatePkcs1KeyDer::from(der_key_bytes)
}

/// Create DER PKCS8 private key
///
/// # Arguments
///
/// * `der_key_bytes` - PKCS8 DER private key byte vector
///
/// # Returns
///
/// A [`PrivatePkcs8KeyDer`] object for the representative given byte vector.
///
pub fn create_der_pkcs8_private_key(der_key_bytes: Vec<u8>) -> PrivatePkcs8KeyDer<'static> {
    PrivatePkcs8KeyDer::from(der_key_bytes)
}

/// Create DER Sec1 private key
///
/// # Arguments
///
/// * `der_key_bytes` - SEC1 DER certificate byte vector
///
/// # Returns
///
/// A [`PrivateSec1KeyDer`] object for the representative given byte vector.
///
pub fn create_der_sec1_private_key(der_key_bytes: Vec<u8>) -> PrivateSec1KeyDer<'static> {
    PrivateSec1KeyDer::from(der_key_bytes)
}
