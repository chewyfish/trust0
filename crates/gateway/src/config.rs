use std::collections::HashMap;
use std::sync::Arc;

use clap::*;
use dnsclient::sync::DNSClient;
use lazy_static::lazy_static;
use rustls::{RootCertStore, SupportedCipherSuite};
use rustls::server::AllowAnyAuthenticatedClient;

use trust0_common::crypto::alpn;
use trust0_common::crypto::file::{load_certificates, load_crl_list, load_private_key};
use trust0_common::error::AppError;
use regex::Regex;
use crate::repository::access_repo::AccessRepository;
use crate::repository::access_repo::in_memory_repo::InMemAccessRepo;
use crate::repository::service_repo::in_memory_repo::InMemServiceRepo;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::in_memory_repo::InMemUserRepo;
use crate::repository::user_repo::UserRepository;

/// Client response messages
pub const RESPCODE_0403_FORBIDDEN: u16 = 403;
pub const RESPCODE_0420_INVALID_CLIENT_CERTIFICATE: u16 = 420;
pub const RESPCODE_0421_UNKNOWN_USER: u16 = 421;
pub const RESPCODE_0422_INACTIVE_USER: u16 = 422;
pub const RESPCODE_0423_INVALID_REQUEST: u16 = 423;
pub const RESPCODE_0424_INVALID_ALPN_PROTOCOL: u16 = 424;
pub const RESPCODE_0425_INACTIVE_SERVICE_PROXY: u16 = 425;
pub const RESPCODE_0500_SYSTEM_ERROR: u16 = 500;
pub const RESPCODE_0520_UNKNOWN_CODE: u16 = 520;
const RESPMSG_0403_FORBIDDEN: &str = "[E0403] Access is forbidden";
const RESPMSG_0420_INVALID_CLIENT_CERTIFICATE: &str = "[E0420] Invalid client certificate";
const RESPMSG_0421_UNKNOWN_USER: &str = "[E0421] Unknown user is inactive";
const RESPMSG_0422_INACTIVE_USER: &str = "[E0422] User account is inactive";
const RESPMSG_0423_INVALID_REQUEST: &str = "[E0423] Invalid request";
const RESPMSG_0424_INVALID_ALPN_PROTOCOL: &str = "[E0424] Invalid ALPN protocol";
const RESPMSG_0425_INACTIVE_SERVICE_PROXY: &str = "[E0425] Inactive service proxy";
const RESPMSG_0500_SYSTEM_ERROR: &str = "[E0500] System error occurred";
const RESPMSG_0520_UNKNOWN_CODE: &str = "[E0520] System error occurred";

lazy_static! {
    pub static ref RESPONSE_MSGS: HashMap<u16, &'static str> = {
        HashMap::from([
            (RESPCODE_0403_FORBIDDEN, RESPMSG_0403_FORBIDDEN),
            (RESPCODE_0420_INVALID_CLIENT_CERTIFICATE, RESPMSG_0420_INVALID_CLIENT_CERTIFICATE),
            (RESPCODE_0421_UNKNOWN_USER, RESPMSG_0421_UNKNOWN_USER),
            (RESPCODE_0422_INACTIVE_USER, RESPMSG_0422_INACTIVE_USER),
            (RESPCODE_0423_INVALID_REQUEST, RESPMSG_0423_INVALID_REQUEST),
            (RESPCODE_0424_INVALID_ALPN_PROTOCOL, RESPMSG_0424_INVALID_ALPN_PROTOCOL),
            (RESPCODE_0425_INACTIVE_SERVICE_PROXY, RESPMSG_0425_INACTIVE_SERVICE_PROXY),
            (RESPCODE_0500_SYSTEM_ERROR, RESPMSG_0500_SYSTEM_ERROR),
            (RESPCODE_0520_UNKNOWN_CODE, RESPMSG_0520_UNKNOWN_CODE)
        ])
    };
}

/// Which mode the server operates in.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ServerMode {

    /// Control-plane for service gateway management
    #[default]
    ControlPlane,

    /// Forward traffic to respective service
    Proxy
}

/// Datasource configuration for the trust framework entities
#[derive(Subcommand, Clone)]
pub enum DataSource {

    /// No DB configured, used in testing
    NoDB,

    /// In-memory DB, with a simple backing persistence store
    InMemoryDb(InMemoryDb),
}

#[derive(Args, Clone)]
pub struct InMemoryDb {

    /// (Service) Access entity store JSON file path
    #[arg(required=true, short='a', long="access-db-file", env)]
    pub access_db_file: String,

    /// Service entity store JSON file path
    #[arg(required=true, short='s', long="service-db-file", env)]
    pub service_db_file: String,

    /// User entity store JSON file path
    #[arg(required=true, short='u', long="user-db-file", env)]
    pub user_db_file: String,
}

/// Runs a trust0 gateway server on :PORT.  The default PORT is 443.
#[derive(Parser)]
#[command(author, version, long_about)]
pub struct AppConfigArgs {

    /// Listen on PORT
    #[arg(required=true, short='p', long="port", env, default_value_t = 443)]
    pub port: u16,

    /// Read server certificates from <CERT_FILE>. This should contain PEM-format certificates
    /// in the right order (first certificate should certify <KEY_FILE>, last should be a root CA)
    #[arg(required=true, short='c', long="cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub cert_file: String,

    /// Read private key from <KEY_FILE>.  This should be a RSA private key or PKCS8-encoded
    /// private key, in PEM format
    #[arg(required=true, short='k', long="key-file", env, value_parser=trust0_common::crypto::file::verify_private_key_file)]
    pub key_file: String,

    /// Read DER-encoded OCSP response from <OCSP_FILE> and staple to certificate
    #[arg(required=false, short='o', long="ocsp-file", env, value_parser=trust0_common::crypto::file::load_ocsp_response)]
    pub ocsp_file: Option<Vec<u8>>,

    /// Accept client authentication certificates signed by those roots provided in <AUTH_CERT_FILE>
    #[arg(required=true, short='a', long="auth-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub auth_cert_file: String,

    /// Perform client certificate revocation checking using the DER-encoded <CRL_FILE(s)>
    #[arg(required=false, long="crl-file", env, value_parser=trust0_common::crypto::file::verify_crl_list)]
    pub crl_file: Option<String>,

    /// Disable default TLS version list, and use <PROTOCOL_VERSION(s)> instead
    #[arg(required=false, long="protocol-version", env, value_parser=trust0_common::crypto::tls::lookup_version)]
    pub protocol_version: Option<Vec<&'static rustls::SupportedProtocolVersion>>,

    /// Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead
    #[arg(required=false, long="cipher-suite", env, value_parser=trust0_common::crypto::tls::lookup_suite)]
    pub cipher_suite: Option<Vec<SupportedCipherSuite>>,

    /// Negotiate ALPN using <ALPN_PROTOCOL(s)>
    #[arg(required=false, long="alpn-protocol", env, value_parser=trust0_common::crypto::tls::parse_alpn_protocol)]
    pub alpn_protocol: Option<Vec<Vec<u8>>>,

    /// Support session resumption
    #[arg(required=false, long="session-resumption", env)]
    pub session_resumption: bool,

    /// Support tickets
    #[arg(required=false, long="tickets", env)]
    pub tickets: bool,

    /// Hostname/ip of this gateway given to clients, used in service proxy connections (if not supplied, clients will determine that on their own)
    #[arg(required=true, long="gateway-service-host", env)]
    pub gateway_service_host: Option<String>,

    /// Service proxy port range. If this is omitted, service connections can be made to the primary gateway port (in addition to the control plane connection). ALPN protocol configuration is used to specify the service ID.
    #[arg(required=false, long="gateway-service-ports", env, value_parser=crate::config::AppConfig::parse_gateway_service_ports)]
    pub gateway_service_ports: Option<(u16, u16)>,

    /// Hostname/ip of this gateway, which is routable by UDP services, used in UDP socket replies. If not supplied, then "127.0.0.1" will be used (if necessary)
    #[arg(required=false, long="gateway-service-reply-host", env)]
    pub gateway_service_reply_host: Option<String>,

    /// Enable verbose logging
    #[arg(required=false, long="verbose", env)]
    pub verbose: bool,

    /// Show all gateway and service addresses (in REPL shell responses)
    #[arg(required=false, long="no-mask-addrs", default_value_t=false, env)]
    pub no_mask_addresses: bool,

    /// Server mode: startup server as control-plane, or as a stand-alone service gateway node
    #[arg(required=false, value_enum, long="mode", env)]
    pub mode: Option<ServerMode>,

    /// DB datasource configuration
    #[command(subcommand)]
    pub datasource: DataSource,
}

pub struct AppConfig {
    pub server_mode: ServerMode,
    pub server_port: u16,
    pub tls_server_config: Arc<rustls::ServerConfig>,
    pub verbose_logging: bool,
    pub access_repo: Arc<dyn AccessRepository>,
    pub service_repo: Arc<dyn ServiceRepository>,
    pub user_repo: Arc<dyn UserRepository>,
    pub gateway_service_host: Option<String>,
    pub gateway_service_ports: Option<(u16, u16)>,
    pub gateway_service_reply_host: String,
    pub mask_addresses: bool,
    pub dns_client: DNSClient
}

impl AppConfig {

    /// Load config
    pub fn new() -> Result<Self, AppError> {

        // parse process arguments

        let config_args = AppConfigArgs::parse();

        // create TLS server configuration

        let auth_certs = load_certificates(&config_args.auth_cert_file).unwrap();
        let certs = load_certificates(&config_args.cert_file).unwrap();
        let key = load_private_key(&config_args.key_file).unwrap();
        let crl_list = match &config_args.crl_file {
            Some(crl_file) => vec![load_crl_list(crl_file).unwrap()],
            None => vec![]
        };

        let mut auth_root_certs = RootCertStore::empty();
        for auth_root_cert in auth_certs {
            auth_root_certs.add(&auth_root_cert).unwrap();
        }

        let client_verifier = AllowAnyAuthenticatedClient::new(auth_root_certs)
            .with_crls(crl_list)
            .map_err(|err| AppError::General(format!("Invalid CRLs: err={:?}", err)))?
            .boxed();

        let mut tls_server_config= rustls::ServerConfig::builder()
            //.with_cipher_suites(&*config_args.cipher_suite.unwrap_or(rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec()))
            .with_cipher_suites(&*config_args.cipher_suite.unwrap_or(rustls::ALL_CIPHER_SUITES.to_vec()))
            .with_safe_default_kx_groups()
            .with_protocol_versions(&*config_args.protocol_version.unwrap_or(rustls::ALL_VERSIONS.to_vec()))
            .expect("inconsistent cipher-suites/versions specified")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert_with_ocsp_and_sct(certs, key, config_args.ocsp_file.unwrap_or(Vec::new()), vec![])
            .expect("bad certificates/private key");

        tls_server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        if config_args.session_resumption {
            tls_server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
        }

        /*
        if config_args.tickets {
            tls_server_config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        }
         */

        // Datasource repositories

        let repositories: (Arc<dyn AccessRepository>, Arc<dyn ServiceRepository>, Arc<dyn UserRepository>)
            = match config_args.datasource {

            DataSource::NoDB => (
                Arc::new(InMemAccessRepo::new()),
                Arc::new(InMemServiceRepo::new()),
                Arc::new(InMemUserRepo::new())
            ),
            DataSource::InMemoryDb(args) => (
                AppConfig::parse_access_db_file(&args.access_db_file)?,
                AppConfig::parse_service_db_file(&args.service_db_file)?,
                AppConfig::parse_user_db_file(&args.user_db_file)?,
            )
        };

        // Setup ALPN protocols for connection type negotiation

        let mut alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        for service in repositories.1.as_ref().get_all()? {
            alpn_protocols.push(alpn::Protocol::create_service_protocol(service.service_id).into_bytes())
        }

        tls_server_config.alpn_protocols = alpn_protocols;

        // Miscellaneous

        let dns_client = DNSClient::new_with_system_resolvers().map_err(|err|
            AppError::GenWithMsgAndErr("Error instantiating DNSClient".to_string(), Box::new(err)))?;

        // Instantiate AppConfig

        Ok(AppConfig {
            server_mode: config_args.mode.unwrap_or_default(),
            server_port: config_args.port,
            tls_server_config: Arc::new(tls_server_config),
            verbose_logging: config_args.verbose,
            access_repo: repositories.0,
            service_repo: repositories.1,
            user_repo: repositories.2,
            gateway_service_host: config_args.gateway_service_host,
            gateway_service_ports: config_args.gateway_service_ports,
            gateway_service_reply_host: config_args.gateway_service_reply_host.unwrap_or("127.0.0.1".to_string()),
            mask_addresses: !config_args.no_mask_addresses,
            dns_client
        })
    }

    /// Parse/load service access entity JSON file and return repository (else error is returned)
    fn parse_access_db_file(filepath: &str) -> Result<Arc<dyn AccessRepository>, AppError> {
        let mut repo = InMemAccessRepo::new();
        repo.load_from_file(filepath)?;
        Ok(Arc::new(repo))

    }

    /// Parse/load service entity JSON file and return repository (else error is returned)
    fn parse_service_db_file(filepath: &str) -> Result<Arc<dyn ServiceRepository>, AppError> {
        let mut repo = InMemServiceRepo::new();
        repo.load_from_file(filepath)?;
        Ok(Arc::new(repo))
    }

    /// Parse/load user entity JSON file and return repository (else error is returned)
    fn parse_user_db_file(filepath: &str) -> Result<Arc<dyn UserRepository>, AppError> {
        let mut repo = InMemUserRepo::new();
        repo.load_from_file(filepath)?;
        Ok(Arc::new(repo))
    }

    /// Parse service port range (format "{port_start:u16}-{port_end:u16}")
    fn parse_gateway_service_ports(gateway_service_ports_str: &str) -> Result<(u16,u16), AppError> {

        let number_range_re = Regex::new(r"(\d+)-(\d+)").unwrap();

        let number_captures = number_range_re.captures(gateway_service_ports_str).ok_or(
            AppError::General(format!("Invalid gateway service port range: val={}", gateway_service_ports_str)))?;

        let port_start: u16 = number_captures[1].parse().unwrap_or(0);
        let port_end: u16 = number_captures[2].parse().unwrap_or(0);

        if (port_start == 0) || (port_end == 0) {
            return Err(AppError::General(format!("Invalid gateway service port range (u16 vals required): val={}", gateway_service_ports_str)));
        }

        Ok((port_start, port_end))
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use std::path::PathBuf;
    use crate::repository::access_repo::AccessRepository;
    use crate::repository::service_repo::ServiceRepository;
    use crate::repository::user_repo::UserRepository;
    use super::*;

    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.crt.pem"];
    const KEYFILE_GATEWAY_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.key.pem"];

    // Utilities

    pub fn create_app_config_with_repos(user_repo: Arc<dyn UserRepository>,
                                        service_repo: Arc<dyn ServiceRepository>,
                                        access_repo: Arc<dyn AccessRepository>)
        -> Result<AppConfig, AppError> {

        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert = load_certificates(gateway_cert_file.to_str().unwrap())?;

        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key = load_private_key(gateway_key_file.to_str().unwrap())?;

        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(gateway_cert, gateway_key)
            .expect("bad certificates/private key");

        Ok(AppConfig {
            server_mode: ServerMode::ControlPlane,
            server_port: 2000,
            tls_server_config: Arc::new(server_config),
            verbose_logging: false,
            access_repo,
            service_repo,
            user_repo,
            gateway_service_host: None,
            gateway_service_ports: None,
            gateway_service_reply_host: "".to_string(),
            mask_addresses: false,
            dns_client: DNSClient::new_with_system_resolvers().map_err(|err|
                AppError::GenWithMsgAndErr("Error instantiating DNSClient".to_string(), Box::new(err)))?
        })
    }
}
