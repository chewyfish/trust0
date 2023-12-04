use std::sync::Arc;

use clap::Parser;
use rustls::{OwnedTrustAnchor, RootCertStore, SupportedCipherSuite};

use trust0_common::crypto::file::{load_certificates, load_private_key};

/// Connects to the TLS server at HOSTNAME:PORT.  The default PORT
/// is 443.  By default, this reads a request from stdin (to EOF)
/// before making the connection.
#[derive(Parser, Debug)]
#[command(author, version, long_about)]
pub struct AppConfigArgs {

    /// Connect to <GATEWAY_HOST>
    #[arg(required=true, short='g', long="gateway_host", env)]
    pub gateway_host: String,

    /// Connect to <GATEWAY_PORT>
    #[arg(required=true, short='p', long="gateway-port", env, default_value_t = 443)]
    pub gateway_port: u16,

    /// Read client authentication key from <AUTH_KEY_FILE>
    #[arg(required=true, short='k', long="auth-key-file", env, value_parser=trust0_common::crypto::file::verify_private_key_file)]
    pub auth_key_file: String,

    /// Read client authentication certificates from <AUTH_CERT_FILE> (must match up with auth key)
    #[arg(required=true, short='c', long="auth-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub auth_cert_file: String,

    /// Read root certificates from <CA_ROOT_CERT_FILE> (otherwise default CA certificates will be used)
    #[arg(required=false, short='r', long="ca-root-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub ca_root_cert_file: Option<String>,

    /// Disable default TLS version list, and use <PROTOCOL_VERSION(s)> instead
    #[arg(required=false, long="protocol-version", env, value_parser=trust0_common::crypto::tls::lookup_version)]
    pub protocol_version: Option<Vec<&'static rustls::SupportedProtocolVersion>>,

    /// Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead
    #[arg(required=false, long="cipher-suite", env, value_parser=trust0_common::crypto::tls::lookup_suite)]
    pub cipher_suite: Option<Vec<SupportedCipherSuite>>,

    /// Limit outgoing messages to <MAX_FRAG_SIZE> bytes
    #[arg(required=false, long="max-frag-size", env)]
    pub max_frag_size: Option<usize>,

    /// Support session resumption
    #[arg(required=false, long="session-resumption", env)]
    pub session_resumption: bool,

    /// Disable session ticket support
    #[arg(required=false, long="no-tickets", env)]
    pub no_tickets: bool,

    /// Disable server name indication support
    #[arg(required=false, long="no-sni", env)]
    pub no_sni: bool,

    /// Disable certificate verification
    #[arg(required=false, long="insecure", env)]
    pub insecure: bool,

    /// Enable verbose logging
    #[arg(required=false, long="verbose", env)]
    pub verbose: bool
}

pub struct AppConfig {
    pub gateway_host: String,
    pub gateway_port: u16,
    pub tls_client_config: rustls::ClientConfig,
    pub verbose_logging: bool
}

impl AppConfig {

    // load config

    pub fn new() -> Self {

        // parse process arguments

        let config_args = AppConfigArgs::parse();

        // create TLS client configuration

        let auth_certs = load_certificates(&config_args.auth_cert_file).unwrap();
        let ca_root_certs = match config_args.ca_root_cert_file {
            Some(ca_root_cert_file) => Some(load_certificates(&ca_root_cert_file).unwrap()),
            None => None
        };

        let mut ca_root_store = RootCertStore::empty();

        if ca_root_certs.is_some() {
            for ca_root_cert in ca_root_certs.unwrap() {
                ca_root_store
                    .add(&ca_root_cert)
                    .expect("Error adding CA root cert");
            }
        } else {
            ca_root_store.add_trust_anchors(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints
                        )
                    }),
            );
        }

        let auth_key = load_private_key(&config_args.auth_key_file).unwrap();

        let mut tls_client_config= rustls::ClientConfig::builder()
            .with_cipher_suites(&*config_args.cipher_suite.unwrap_or(rustls::ALL_CIPHER_SUITES.to_vec()))
            .with_safe_default_kx_groups()
            .with_protocol_versions(&*config_args.protocol_version.unwrap_or(rustls::ALL_VERSIONS.to_vec()))
            .expect("Inconsistent cipher-suite/versions selected")
            .with_root_certificates(ca_root_store)
            .with_client_auth_cert(auth_certs, auth_key)
            .expect("Invalid client auth certs/key");

        tls_client_config.key_log = Arc::new(rustls::KeyLogFile::new());

        if config_args.no_tickets {
            tls_client_config.resumption = tls_client_config
                .resumption
                .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOnly);
        }

        if config_args.no_sni {
            tls_client_config.enable_sni = false;
        }

        tls_client_config.alpn_protocols = Vec::new();
        tls_client_config.max_fragment_size = config_args.max_frag_size;

        if config_args.insecure {
            tls_client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
        }

        // instantiate AppConfig

        AppConfig {
            gateway_host: config_args.gateway_host.clone(),
            gateway_port: config_args.gateway_port,
            tls_client_config,
            verbose_logging: config_args.verbose
        }

    }
}

mod danger {
    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}
