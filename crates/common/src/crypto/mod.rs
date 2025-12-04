pub mod alpn;
pub mod asn;
pub mod ca;
pub mod crl;
pub mod file;
pub mod tls;
pub mod x509;

/// Configure the default crypto provider. Currently using `ring`.
///
pub fn setup_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}
