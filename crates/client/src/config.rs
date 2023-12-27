use std::env;
use std::sync::{Arc, Mutex};

use clap::Parser;
use rustls::crypto::CryptoProvider;
use rustls::{RootCertStore, SupportedCipherSuite};

use crate::console::ShellOutputWriter;
use trust0_common::crypto::file::{load_certificates, load_private_key};
use trust0_common::error::AppError;

/// Connects to the Trust0 gateway server at HOSTNAME:PORT (default PORT is 443).
/// An control plane REPL shell allows service proxies to be opened (among other features).
#[derive(Parser, Debug)]
#[command(author, version, long_about)]
pub struct AppConfigArgs {
    /// Config file (as a shell environment file), using program's environment variable naming (see below).
    /// Note - Each config file variable entry may be overriden via their respective command-line arguments
    /// Note - Must be first argument (if provided)
    #[arg(
        required = false,
        short = 'f',
        long = "config-file",
        env,
        verbatim_doc_comment
    )]
    pub config_file: Option<String>,

    /// Connect to <GATEWAY_HOST>
    #[arg(required = true, short = 'g', long = "gateway-host", env)]
    pub gateway_host: String,

    /// Connect to <GATEWAY_PORT>
    #[arg(
        required = true,
        short = 'p',
        long = "gateway-port",
        env,
        default_value_t = 443
    )]
    pub gateway_port: u16,

    /// Read client authentication key from <AUTH_KEY_FILE> This should be an ECDSA, EdDSA or RSA private key encoded as PKCS1, PKCS8 or Sec1 in a PEM file.
    /// Note - For ECDSA keys, curves 'prime256v1' and 'secp384r1' have been tested (others may be supported as well)
    /// Note - For EdDSA keys, currently only 'Ed25519' is supported
    #[arg(required=true, short='k', long="auth-key-file", env, value_parser=trust0_common::crypto::file::verify_private_key_file, verbatim_doc_comment)]
    pub auth_key_file: String,

    /// Read client authentication certificates from <AUTH_CERT_FILE> (must match up with auth key)
    #[arg(required=true, short='c', long="auth-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub auth_cert_file: String,

    /// Read root certificates from <CA_ROOT_CERT_FILE>
    #[arg(required=true, short='r', long="ca-root-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub ca_root_cert_file: String,

    /// Disable default TLS version list, and use <PROTOCOL_VERSION(s)> instead
    #[arg(required=false, long="protocol-version", env, value_parser=trust0_common::crypto::tls::lookup_version)]
    pub protocol_version: Option<Vec<&'static rustls::SupportedProtocolVersion>>,

    /// Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead
    #[arg(required=false, long="cipher-suite", env, value_parser=trust0_common::crypto::tls::lookup_suite)]
    pub cipher_suite: Option<Vec<SupportedCipherSuite>>,

    /// Limit outgoing messages to <MAX_FRAG_SIZE> bytes
    #[arg(required = false, long = "max-frag-size", env)]
    pub max_frag_size: Option<usize>,

    /// Support session resumption
    #[arg(required = false, long = "session-resumption", env)]
    pub session_resumption: bool,

    /// Disable session ticket support
    #[arg(required = false, long = "no-tickets", env)]
    pub no_tickets: bool,

    /// Disable server name indication support
    #[arg(required = false, long = "no-sni", env)]
    pub no_sni: bool,

    /// Disable certificate verification
    #[arg(required = false, long = "insecure", env)]
    pub insecure: bool,

    /// Enable verbose logging
    #[arg(required = false, long = "verbose", env)]
    pub verbose: bool,
}

pub struct AppConfig {
    pub gateway_host: String,
    pub gateway_port: u16,
    pub tls_client_config: rustls::ClientConfig,
    pub verbose_logging: bool,
    pub console_shell_output: Arc<Mutex<ShellOutputWriter>>,
}

impl AppConfig {
    // load config
    pub fn new() -> Result<Self, AppError> {
        // Populate environment w/given config file (if provided)
        let mut config_file = env::var_os("CONFIG_FILE");
        if config_file.is_none()
            && (env::args_os().len() >= 3)
            && env::args_os().nth(1).unwrap().eq("-f")
        {
            config_file = env::args_os().nth(2);
        }

        if let Some(config_filename) = config_file {
            dotenvy::from_filename(config_filename).ok();
        }

        // Parse process arguments
        let config_args = Self::parse_config();

        // Create TLS client configuration
        let auth_certs = load_certificates(config_args.auth_cert_file.clone())?;
        let ca_root_certs = load_certificates(config_args.ca_root_cert_file.clone())?;

        let mut ca_root_store = RootCertStore::empty();

        for ca_root_cert in ca_root_certs {
            ca_root_store.add(ca_root_cert).map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error adding CA root cert".to_string(),
                    Box::new(err.clone()),
                )
            })?;
        }

        let auth_key = load_private_key(config_args.auth_key_file.clone()).unwrap();

        let cipher_suites: Vec<SupportedCipherSuite> = config_args
            .cipher_suite
            .unwrap_or(rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec());

        let mut tls_client_config = rustls::ClientConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites,
                ..rustls::crypto::ring::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(
            &config_args
                .protocol_version
                .unwrap_or(rustls::ALL_VERSIONS.to_vec()),
        )
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

        // Instantiate AppConfig
        Ok(AppConfig {
            gateway_host: config_args.gateway_host.clone(),
            gateway_port: config_args.gateway_port,
            tls_client_config,
            verbose_logging: config_args.verbose,
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(None))),
        })
    }

    #[cfg(not(test))]
    #[inline(always)]
    fn parse_config() -> AppConfigArgs {
        AppConfigArgs::parse()
    }

    #[cfg(test)]
    #[inline(always)]
    fn parse_config() -> AppConfigArgs {
        AppConfigArgs::parse_from::<Vec<_>, String>(vec![])
    }
}

mod danger {
    use pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct NoCertificateVerification {}

    impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config::danger::NoCertificateVerification;
    use pki_types::{ServerName, UnixTime};
    use rustls::client::danger::ServerCertVerifier;
    use std::env;
    use std::path::PathBuf;

    const CONFIG_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "config-file.rc"];
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
    pub fn create_app_config(
        shell_output_writer: Option<ShellOutputWriter>,
    ) -> Result<AppConfig, AppError> {
        let client_pki_files: (PathBuf, PathBuf) = (
            CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect(),
            KEYFILE_CLIENT_UID100_PATHPARTS.iter().collect(),
        );
        let client_cert = load_certificates(client_pki_files.0.to_str().unwrap().to_string())?;
        let client_key = load_private_key(client_pki_files.1.to_str().unwrap().to_string())?;
        let auth_root_certs = RootCertStore::empty();
        let cipher_suites: Vec<SupportedCipherSuite> =
            rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
        let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> =
            rustls::ALL_VERSIONS.to_vec();

        let tls_client_config = rustls::ClientConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites,
                ..rustls::crypto::ring::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(&protocol_versions)
        .expect("Inconsistent cipher-suite/versions selected")
        .with_root_certificates(auth_root_certs)
        .with_client_auth_cert(client_cert, client_key)
        .expect("Invalid client auth certs/key");

        let shell_output_writer = shell_output_writer.unwrap_or(ShellOutputWriter::new(None));

        Ok(AppConfig {
            gateway_host: "gwhost1".to_string(),
            gateway_port: 2000,
            tls_client_config,
            verbose_logging: false,
            console_shell_output: Arc::new(Mutex::new(shell_output_writer)),
        })
    }

    // tests
    // =====

    // Environment contention for the tests utilizing env vars. Disabling this test for now.
    #[test]
    #[ignore]
    fn appcfg_new_when_all_supplied_and_valid() {
        let ca_root_cert_file: PathBuf = CERTFILE_ROOT_CA_PATHPARTS.iter().collect();
        let ca_root_cert_file_str = ca_root_cert_file.to_str().unwrap();
        let client_key_file: PathBuf = KEYFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let client_key_file_str = client_key_file.to_str().unwrap();
        let client_cert_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let client_cert_file_str = client_cert_file.to_str().unwrap();
        env::set_var("GATEWAY_HOST", "gwhost1");
        env::set_var("GATEWAY_PORT", "8000");
        env::set_var("AUTH_KEY_FILE", client_key_file_str);
        env::set_var("AUTH_CERT_FILE", client_cert_file_str);
        env::set_var("CA_ROOT_CERT_FILE", ca_root_cert_file_str);
        env::set_var("PROTOCOL_VERSION", "1.3");
        env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
        env::set_var("MAX_FRAG_SIZE", "1024");
        env::set_var("SESSION_RESUMPTION", "true");
        env::set_var("NO_TICKETS", "true");
        env::set_var("NO_SNI", "true");
        env::set_var("INSECURE", "true");
        env::set_var("VERBOSE", "true");

        let result = AppConfig::new();
        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.gateway_host, "gwhost1".to_string());
        assert_eq!(config.gateway_port, 8000);
        assert!(config
            .tls_client_config
            .client_auth_cert_resolver
            .has_certs());
        assert!(!config.tls_client_config.enable_sni);
        let expected_alpn_protocols: Vec<Vec<u8>> = vec![];
        assert_eq!(
            config.tls_client_config.alpn_protocols,
            expected_alpn_protocols
        );
        assert!(config.tls_client_config.max_fragment_size.is_some());
        assert_eq!(config.tls_client_config.max_fragment_size.unwrap(), 1024);
        assert!(config.verbose_logging);
    }

    #[test]
    fn appcfg_new_when_mixed_configfile_and_env_supplied() {
        let config_file: PathBuf = CONFIG_FILE_PATHPARTS.iter().collect();
        let config_file_str = config_file.to_str().unwrap();
        let ca_root_cert_file: PathBuf = CERTFILE_ROOT_CA_PATHPARTS.iter().collect();
        let ca_root_cert_file_str = ca_root_cert_file.to_str().unwrap();
        let client_key_file: PathBuf = KEYFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let client_key_file_str = client_key_file.to_str().unwrap();
        let client_cert_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let client_cert_file_str = client_cert_file.to_str().unwrap();
        env::set_var("CONFIG_FILE", config_file_str);
        env::set_var("GATEWAY_HOST", "gwhost1");
        env::set_var("AUTH_KEY_FILE", client_key_file_str);
        env::set_var("AUTH_CERT_FILE", client_cert_file_str);
        env::set_var("CA_ROOT_CERT_FILE", ca_root_cert_file_str);
        env::set_var("PROTOCOL_VERSION", "1.3");
        env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
        env::set_var("SESSION_RESUMPTION", "true");
        env::set_var("NO_TICKETS", "true");
        env::set_var("NO_SNI", "true");
        env::set_var("INSECURE", "true");
        env::set_var("VERBOSE", "true");

        let result = AppConfig::new();
        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.gateway_host, "gwhost1".to_string());
        assert_eq!(config.gateway_port, 8888);
        assert!(config
            .tls_client_config
            .client_auth_cert_resolver
            .has_certs());
        assert!(!config.tls_client_config.enable_sni);
        let expected_alpn_protocols: Vec<Vec<u8>> = vec![];
        assert_eq!(
            config.tls_client_config.alpn_protocols,
            expected_alpn_protocols
        );
        assert!(config.tls_client_config.max_fragment_size.is_some());
        assert_eq!(config.tls_client_config.max_fragment_size.unwrap(), 128);
        assert!(config.verbose_logging);
    }

    #[test]
    fn nocertverify_verify_server_cert() {
        let ca_root_cert_file: PathBuf = CERTFILE_ROOT_CA_PATHPARTS.iter().collect();
        let ca_root_cert_file_str = ca_root_cert_file.to_str().unwrap();
        let client_cert_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let client_cert_file_str = client_cert_file.to_str().unwrap();
        let ca_root_cert = load_certificates(ca_root_cert_file_str.to_string()).unwrap();
        let client_cert = load_certificates(client_cert_file_str.to_string()).unwrap();

        let no_cert_verification = NoCertificateVerification {};
        match no_cert_verification.verify_server_cert(
            client_cert.get(0).unwrap(),
            ca_root_cert.as_slice(),
            &ServerName::try_from("server1").unwrap(),
            &vec![],
            UnixTime::now(),
        ) {
            Ok(_) => {}
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn nocertverify_supported_verify_schemes() {
        let no_cert_verification = NoCertificateVerification {};
        assert!(no_cert_verification.supported_verify_schemes().len() > 0);
    }
}
