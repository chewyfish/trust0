use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use clap::*;
use dnsclient::sync::DNSClient;
use lazy_static::lazy_static;
use pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs1KeyDer,
    PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

use crate::repository::access_repo::in_memory_repo::InMemAccessRepo;
use crate::repository::access_repo::AccessRepository;
use crate::repository::role_repo::in_memory_repo::InMemRoleRepo;
use crate::repository::role_repo::RoleRepository;
use crate::repository::service_repo::in_memory_repo::InMemServiceRepo;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::in_memory_repo::InMemUserRepo;
use crate::repository::user_repo::UserRepository;
use regex::Regex;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use trust0_common::crypto::alpn;
use trust0_common::crypto::file::CRLFile;
use trust0_common::crypto::file::{load_certificates, load_private_key};
use trust0_common::error::AppError;
use trust0_common::file::ReloadableFile;

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
            (
                RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                RESPMSG_0420_INVALID_CLIENT_CERTIFICATE,
            ),
            (RESPCODE_0421_UNKNOWN_USER, RESPMSG_0421_UNKNOWN_USER),
            (RESPCODE_0422_INACTIVE_USER, RESPMSG_0422_INACTIVE_USER),
            (RESPCODE_0423_INVALID_REQUEST, RESPMSG_0423_INVALID_REQUEST),
            (
                RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                RESPMSG_0424_INVALID_ALPN_PROTOCOL,
            ),
            (
                RESPCODE_0425_INACTIVE_SERVICE_PROXY,
                RESPMSG_0425_INACTIVE_SERVICE_PROXY,
            ),
            (RESPCODE_0500_SYSTEM_ERROR, RESPMSG_0500_SYSTEM_ERROR),
            (RESPCODE_0520_UNKNOWN_CODE, RESPMSG_0520_UNKNOWN_CODE),
        ])
    };
}

/// Datasource configuration for the trust framework entities
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DataSource {
    /// In-memory DB, with a simple backing persistence store. Entity store connect strings file paths to JSON record files.
    InMemoryDb,

    /// No DB configured, used in testing (internally empty in-memory DB structures are used)
    #[default]
    NoDb,
}

impl DataSource {
    #[allow(clippy::type_complexity)]
    /// Return tuple of repository factory closures (respectively for access, service and user repositories)
    pub fn repository_factories(
        &self,
    ) -> (
        Box<dyn Fn() -> Arc<Mutex<dyn AccessRepository>>>,
        Box<dyn Fn() -> Arc<Mutex<dyn ServiceRepository>>>,
        Box<dyn Fn() -> Arc<Mutex<dyn RoleRepository>>>,
        Box<dyn Fn() -> Arc<Mutex<dyn UserRepository>>>,
    ) {
        (
            Box::new(|| Arc::new(Mutex::new(InMemAccessRepo::new()))),
            Box::new(|| Arc::new(Mutex::new(InMemServiceRepo::new()))),
            Box::new(|| Arc::new(Mutex::new(InMemRoleRepo::new()))),
            Box::new(|| Arc::new(Mutex::new(InMemUserRepo::new()))),
        )
    }
}

/// Runs a Trust0 gateway server on :PORT.  The default PORT is 443.
#[derive(Parser)]
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

    /// Listen on PORT
    #[arg(
        required = true,
        short = 'p',
        long = "port",
        env,
        default_value_t = 443
    )]
    pub port: u16,

    /// Read server certificates from <CERT_FILE>. This should contain PEM-format certificates
    /// in the right order (first certificate should certify <KEY_FILE>, last should be a root CA)
    #[arg(required=true, short='c', long="cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub cert_file: String,

    /// Read private key from <KEY_FILE>. This should be an ECDSA, EdDSA or RSA private key encoded as PKCS1, PKCS8 or Sec1 in a PEM file.
    /// Note - For ECDSA keys, curves 'prime256v1' and 'secp384r1' have been tested (others may be supported as well)
    /// Note - For EdDSA keys, currently only 'Ed25519' is supported
    #[arg(required=true, short='k', long="key-file", env, value_parser=trust0_common::crypto::file::verify_private_key_file, verbatim_doc_comment)]
    pub key_file: String,

    /// Accept client authentication certificates signed by those roots provided in <AUTH_CERT_FILE>
    #[arg(required=true, short='a', long="auth-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub auth_cert_file: String,

    /// Perform client certificate revocation checking using the DER-encoded <CRL_FILE(s)>. Will update list during runtime, if file has changed.
    #[arg(required=false, long="crl-file", env, value_parser=trust0_common::crypto::file::verify_crl_list)]
    pub crl_file: Option<String>,

    /// Disable default TLS version list, and use <PROTOCOL_VERSION(s)> instead. Provided value is a comma-separated list of versions.
    #[arg(required=false, long="protocol-version", env, value_parser=trust0_common::crypto::tls::lookup_version, value_delimiter=',')]
    pub protocol_version: Option<Vec<&'static rustls::SupportedProtocolVersion>>,

    /// Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead. Provided value is a comma-separated list of suites.
    #[arg(required=false, long="cipher-suite", env, value_parser=trust0_common::crypto::tls::lookup_suite, value_delimiter=',')]
    pub cipher_suite: Option<Vec<rustls::SupportedCipherSuite>>,

    /// Negotiate ALPN using <ALPN_PROTOCOL(s)>. Provided value is a comma-separated list of protocols.
    #[arg(required=false, long="alpn-protocol", env, value_parser=trust0_common::crypto::tls::parse_alpn_protocol, value_delimiter=',')]
    pub alpn_protocol: Option<Vec<Vec<u8>>>,

    /// Support session resumption
    #[arg(required = false, long = "session-resumption", env)]
    pub session_resumption: bool,

    /// Support tickets
    #[arg(required = false, long = "tickets", env)]
    pub tickets: bool,

    /// Hostname/ip of this gateway given to clients, used in service proxy connections (if not supplied, clients will determine that on their own)
    #[arg(required = true, long = "gateway-service-host", env)]
    pub gateway_service_host: Option<String>,

    /// Service proxy port range. If this is omitted, service connections can be made to the primary gateway port (in addition to the control plane connection). ALPN protocol configuration is used to specify the service ID.
    #[arg(required=false, long="gateway-service-ports", env, value_parser=crate::config::AppConfig::parse_gateway_service_ports)]
    pub gateway_service_ports: Option<(u16, u16)>,

    /// Hostname/ip of this gateway, which is routable by UDP services, used in UDP socket replies. If not supplied, then "127.0.0.1" will be used (if necessary)
    #[arg(required = false, long = "gateway-service-reply-host", env)]
    pub gateway_service_reply_host: Option<String>,

    /// Enable verbose logging
    #[arg(required = false, long = "verbose", env)]
    pub verbose: bool,

    /// Show all gateway and service addresses (in REPL shell responses)
    #[arg(required = false, long = "no-mask-addrs", default_value_t = false, env)]
    pub no_mask_addresses: bool,

    /// DB datasource type
    #[arg(required = false, value_enum, long = "datasource", default_value_t = crate::config::DataSource::InMemoryDb, env)]
    pub datasource: DataSource,

    /// (Service) Access entity store connect specifier string
    #[arg(required = false, long = "access-db-connect", env)]
    pub access_db_connect: Option<String>,

    /// Service entity store connect specifier string
    #[arg(required = false, long = "service-db-connect", env)]
    pub service_db_connect: Option<String>,

    /// Role entity store connect specifier string
    #[arg(required = false, long = "role-db-connect", env)]
    pub role_db_connect: Option<String>,

    /// User entity store connect specifier string
    #[arg(required = false, long = "user-db-connect", env)]
    pub user_db_connect: Option<String>,
}

/// TLS server configuration builder
pub struct TlsServerConfigBuilder {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub cipher_suites: Vec<rustls::SupportedCipherSuite>,
    pub protocol_versions: Vec<&'static rustls::SupportedProtocolVersion>,
    pub auth_root_certs: rustls::RootCertStore,
    pub crl_list: Option<Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>>>,
    pub session_resumption: bool,
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl TlsServerConfigBuilder {
    /// Create TLS server configuration
    pub fn build(&self) -> Result<rustls::ServerConfig, AppError> {
        let mut tls_server_config = rustls::ServerConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites: self.cipher_suites.to_vec(),
                ..rustls::crypto::ring::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(self.protocol_versions.as_slice())
        .expect("Inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(self.build_client_cert_verifier()?)
        .with_single_cert(
            self.certs.clone(),
            match &self.key {
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
                    &self.key
                ))),
            }?,
        )
        .expect("Bad certificates/private key");

        tls_server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        if self.session_resumption {
            tls_server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
        }

        tls_server_config.alpn_protocols = self.alpn_protocols.clone();

        Ok(tls_server_config)
    }

    /// Build a TLS client verifier
    fn build_client_cert_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, AppError> {
        let crl_list: Vec<CertificateRevocationListDer<'static>> = match &self.crl_list {
            Some(crl_list) => crl_list.clone().lock().unwrap().to_vec(),
            None => vec![],
        };

        Ok(
            WebPkiClientVerifier::builder(Arc::new(self.auth_root_certs.clone()))
                .with_crls(crl_list)
                .build()
                .unwrap(),
        )
    }
}

/// Main application configuration/context struct
pub struct AppConfig {
    pub server_port: u16,
    pub tls_server_config_builder: TlsServerConfigBuilder,
    pub crl_reloader_loading: Arc<Mutex<bool>>,
    pub verbose_logging: bool,
    pub access_repo: Arc<Mutex<dyn AccessRepository>>,
    pub service_repo: Arc<Mutex<dyn ServiceRepository>>,
    pub role_repo: Arc<Mutex<dyn RoleRepository>>,
    pub user_repo: Arc<Mutex<dyn UserRepository>>,
    pub gateway_service_host: Option<String>,
    pub gateway_service_ports: Option<(u16, u16)>,
    pub gateway_service_reply_host: String,
    pub mask_addresses: bool,
    pub dns_client: DNSClient,
}

impl AppConfig {
    /// Load config
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

        // Datasource repositories
        let repositories = Self::create_datasource_repositories(
            &config_args.datasource,
            &config_args.access_db_connect,
            &config_args.service_db_connect,
            &config_args.role_db_connect,
            &config_args.user_db_connect,
            &config_args.datasource.repository_factories(),
        )?;

        // Create TLS server configuration builder
        let auth_certs = load_certificates(config_args.auth_cert_file.clone()).unwrap();
        let certs = load_certificates(config_args.cert_file.clone()).unwrap();
        let key = load_private_key(config_args.key_file.clone()).unwrap();

        let crl_reloader_loading = Arc::new(Mutex::new(false));
        let crl_list = match &config_args.crl_file {
            Some(filepath) => {
                let crl_list = Arc::new(Mutex::new(vec![]));
                let crl_file = CRLFile::new(filepath.as_str(), &crl_list, &crl_reloader_loading)?;
                <CRLFile as ReloadableFile>::spawn_reloader(crl_file, None);
                Some(crl_list)
            }
            None => None,
        };

        let mut auth_root_certs = rustls::RootCertStore::empty();
        for auth_root_cert in auth_certs {
            auth_root_certs.add(auth_root_cert).unwrap();
        }

        let cipher_suites: Vec<rustls::SupportedCipherSuite> = config_args
            .cipher_suite
            .unwrap_or(rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec());
        let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> = config_args
            .protocol_version
            .unwrap_or(rustls::ALL_VERSIONS.to_vec());
        let session_resumption = config_args.session_resumption;

        let mut alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];
        for service in repositories.1.as_ref().lock().unwrap().get_all()? {
            alpn_protocols
                .push(alpn::Protocol::create_service_protocol(service.service_id).into_bytes())
        }

        let tls_server_config_builder = TlsServerConfigBuilder {
            certs,
            key,
            cipher_suites,
            protocol_versions,
            auth_root_certs,
            crl_list,
            session_resumption,
            alpn_protocols,
        };

        // Miscellaneous
        let dns_client;
        #[cfg(unix)]
        {
            dns_client = DNSClient::new_with_system_resolvers().map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error instantiating DNSClient".to_string(),
                    Box::new(err),
                )
            })?;
        }
        #[cfg(windows)]
        {
            dns_client = DNSClient::new(vec![]);
        }

        // Instantiate AppConfig
        Ok(AppConfig {
            server_port: config_args.port,
            tls_server_config_builder,
            crl_reloader_loading,
            verbose_logging: config_args.verbose,
            access_repo: repositories.0,
            service_repo: repositories.1,
            role_repo: repositories.2,
            user_repo: repositories.3,
            gateway_service_host: config_args.gateway_service_host,
            gateway_service_ports: config_args.gateway_service_ports,
            gateway_service_reply_host: config_args
                .gateway_service_reply_host
                .unwrap_or("127.0.0.1".to_string()),
            mask_addresses: !config_args.no_mask_addresses,
            dns_client,
        })
    }

    #[allow(clippy::type_complexity)]
    /// Instantiate main repositories based on datasource config. Returns tuple of access, service, role and user repositories.
    fn create_datasource_repositories(
        datasource: &DataSource,
        access_db_connect: &Option<String>,
        service_db_connect: &Option<String>,
        role_db_connect: &Option<String>,
        user_db_connect: &Option<String>,
        repo_factories: &(
            Box<dyn Fn() -> Arc<Mutex<dyn AccessRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn ServiceRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn RoleRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn UserRepository>>>,
        ),
    ) -> Result<
        (
            Arc<Mutex<dyn AccessRepository>>,
            Arc<Mutex<dyn ServiceRepository>>,
            Arc<Mutex<dyn RoleRepository>>,
            Arc<Mutex<dyn UserRepository>>,
        ),
        AppError,
    > {
        let access_repository = repo_factories.0();
        let service_repository = repo_factories.1();
        let role_repository = repo_factories.2();
        let user_repository = repo_factories.3();

        if let DataSource::InMemoryDb = datasource {
            if access_db_connect.is_some() {
                access_repository
                    .lock()
                    .unwrap()
                    .connect_to_datasource(access_db_connect.as_ref().unwrap().as_str())?;
            }
            if service_db_connect.is_some() {
                service_repository
                    .lock()
                    .unwrap()
                    .connect_to_datasource(service_db_connect.as_ref().unwrap().as_str())?;
            }
            if role_db_connect.is_some() {
                role_repository
                    .lock()
                    .unwrap()
                    .connect_to_datasource(role_db_connect.as_ref().unwrap().as_str())?;
            }
            if user_db_connect.is_some() {
                user_repository
                    .lock()
                    .unwrap()
                    .connect_to_datasource(user_db_connect.as_ref().unwrap().as_str())?;
            }
        }

        Ok((
            access_repository,
            service_repository,
            role_repository,
            user_repository,
        ))
    }

    /// Parse service port range (format "{port_start:u16}-{port_end:u16}")
    fn parse_gateway_service_ports(
        gateway_service_ports_str: &str,
    ) -> Result<(u16, u16), AppError> {
        let number_range_re = Regex::new(r"(\d+)-(\d+)").unwrap();

        let number_captures =
            number_range_re
                .captures(gateway_service_ports_str)
                .ok_or(AppError::General(format!(
                    "Invalid gateway service port range: val={}",
                    gateway_service_ports_str
                )))?;

        let port_start: u16 = number_captures[1].parse().unwrap_or(0);
        let port_end: u16 = number_captures[2].parse().unwrap_or(0);

        if (port_start == 0) || (port_end == 0) {
            return Err(AppError::General(format!(
                "Invalid gateway service port range (u16 vals required): val={}",
                gateway_service_ports_str
            )));
        }

        Ok((port_start, port_end))
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

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::access_repo::AccessRepository;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::role_repo::RoleRepository;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::service_repo::ServiceRepository;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::repository::user_repo::UserRepository;
    use mockall::predicate;
    use once_cell::sync::Lazy;
    use std::env;
    use std::path::PathBuf;

    const CONFIG_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "config-file.rc"];
    const _CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];
    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.crt.pem"];
    const KEYFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.key.pem"];
    const DB_ACCESS_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "db-access.json"];
    const DB_SERVICE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "db-service.json"];
    const DB_ROLE_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "db-role.json"];
    const DB_USER_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "db-user.json"];

    static TEST_MUTEX: Lazy<Arc<Mutex<bool>>> = Lazy::new(|| Arc::new(Mutex::new(true)));

    // utils
    // =====

    pub fn create_app_config_with_repos(
        user_repo: Arc<Mutex<dyn UserRepository>>,
        service_repo: Arc<Mutex<dyn ServiceRepository>>,
        role_repo: Arc<Mutex<dyn RoleRepository>>,
        access_repo: Arc<Mutex<dyn AccessRepository>>,
    ) -> Result<AppConfig, AppError> {
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert = load_certificates(gateway_cert_file.to_str().unwrap().to_string())?;
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key = load_private_key(gateway_key_file.to_str().unwrap().to_string())?;
        let auth_root_certs = rustls::RootCertStore::empty();
        let cipher_suites: Vec<rustls::SupportedCipherSuite> =
            rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
        let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> =
            rustls::ALL_VERSIONS.to_vec();
        let session_resumption = false;
        let alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        let tls_server_config_builder = TlsServerConfigBuilder {
            certs: gateway_cert,
            key: gateway_key,
            cipher_suites,
            protocol_versions,
            auth_root_certs,
            crl_list: None,
            session_resumption,
            alpn_protocols,
        };

        let dns_client;
        #[cfg(unix)]
        {
            dns_client = DNSClient::new_with_system_resolvers().map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error instantiating DNSClient".to_string(),
                    Box::new(err),
                )
            })?;
        }
        #[cfg(windows)]
        {
            dns_client = DNSClient::new(vec![]);
        }

        Ok(AppConfig {
            server_port: 2000,
            tls_server_config_builder,
            crl_reloader_loading: Arc::new(Mutex::new(false)),
            verbose_logging: false,
            access_repo,
            service_repo,
            role_repo,
            user_repo,
            gateway_service_host: None,
            gateway_service_ports: None,
            gateway_service_reply_host: "".to_string(),
            mask_addresses: false,
            dns_client,
        })
    }

    fn clear_env_vars() {
        env::remove_var("CONFIG_FILE");
        env::remove_var("PORT");
        env::remove_var("KEY_FILE");
        env::remove_var("CERT_FILE");
        env::remove_var("AUTH_CERT_FILE");
        env::remove_var("PROTOCOL_VERSION");
        env::remove_var("CIPHER_SUITE");
        env::remove_var("SESSION_RESUMPTION");
        env::remove_var("ICKETS");
        env::remove_var("GATEWAY_SERVICE_HOST");
        env::remove_var("GATEWAY_SERVICE_PORTS");
        env::remove_var("GATEWAY_SERVICE_REPLY_HOST");
        env::remove_var("NO_MASK_ADDRESSES");
        env::remove_var("MODE");
        env::remove_var("DATASOURCE");
        env::remove_var("ACCESS_DB_CONNECT");
        env::remove_var("SERVICE_DB_CONNECT");
        env::remove_var("ROLE_DB_CONNECT");
        env::remove_var("USER_DB_CONNECT");
        env::remove_var("VERBOSE");
    }

    // tests
    // =====

    #[test]
    fn appcfg_new_when_all_supplied_and_valid() {
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key_file_str = gateway_key_file.to_str().unwrap();
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert_file_str = gateway_cert_file.to_str().unwrap();
        let access_db_file: PathBuf = DB_ACCESS_PATHPARTS.iter().collect();
        let access_db_file_str = access_db_file.to_str().unwrap();
        let service_db_file: PathBuf = DB_SERVICE_PATHPARTS.iter().collect();
        let service_db_file_str = service_db_file.to_str().unwrap();
        let role_db_file: PathBuf = DB_ROLE_PATHPARTS.iter().collect();
        let role_db_file_str = role_db_file.to_str().unwrap();
        let user_db_file: PathBuf = DB_USER_PATHPARTS.iter().collect();
        let user_db_file_str = user_db_file.to_str().unwrap();
        let result;
        {
            let mutex = TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            clear_env_vars();
            env::set_var("PORT", "8000");
            env::set_var("KEY_FILE", gateway_key_file_str);
            env::set_var("CERT_FILE", gateway_cert_file_str);
            env::set_var("AUTH_CERT_FILE", gateway_cert_file_str);
            env::set_var("PROTOCOL_VERSION", "1.3");
            env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
            env::set_var("SESSION_RESUMPTION", "true");
            env::set_var("ICKETS", "true");
            env::set_var("GATEWAY_SERVICE_HOST", "gwhost1");
            env::set_var("GATEWAY_SERVICE_PORTS", "8000-8010");
            env::set_var("GATEWAY_SERVICE_REPLY_HOST", "gwhost2");
            env::set_var("NO_MASK_ADDRESSES", "true");
            env::set_var("MODE", "control-plane");
            env::set_var("DATASOURCE", "in-memory-db");
            env::set_var("ACCESS_DB_CONNECT", access_db_file_str);
            env::set_var("SERVICE_DB_CONNECT", service_db_file_str);
            env::set_var("ROLE_DB_CONNECT", role_db_file_str);
            env::set_var("USER_DB_CONNECT", user_db_file_str);
            env::set_var("VERBOSE", "true");

            result = AppConfig::new();
        }

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.server_port, 8000);
        assert!(config.gateway_service_host.is_some());
        assert_eq!(config.gateway_service_host.unwrap(), "gwhost1".to_string());
        assert!(config.gateway_service_ports.is_some());
        assert_eq!(config.gateway_service_ports.unwrap(), (8000, 8010));
        assert!(!config.mask_addresses);
        assert_eq!(config.gateway_service_reply_host, "gwhost2".to_string());
        assert!(config.verbose_logging);
    }

    #[test]
    fn appcfg_new_when_mixed_configfile_and_env_supplied() {
        let config_file: PathBuf = CONFIG_FILE_PATHPARTS.iter().collect();
        let config_file_str = config_file.to_str().unwrap();
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key_file_str = gateway_key_file.to_str().unwrap();
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert_file_str = gateway_cert_file.to_str().unwrap();
        let access_db_file: PathBuf = DB_ACCESS_PATHPARTS.iter().collect();
        let access_db_file_str = access_db_file.to_str().unwrap();
        let service_db_file: PathBuf = DB_SERVICE_PATHPARTS.iter().collect();
        let service_db_file_str = service_db_file.to_str().unwrap();
        let role_db_file: PathBuf = DB_ROLE_PATHPARTS.iter().collect();
        let role_db_file_str = role_db_file.to_str().unwrap();
        let user_db_file: PathBuf = DB_USER_PATHPARTS.iter().collect();
        let user_db_file_str = user_db_file.to_str().unwrap();
        let result;
        {
            let mutex = TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            clear_env_vars();
            env::set_var("CONFIG_FILE", config_file_str);
            env::set_var("KEY_FILE", gateway_key_file_str);
            env::set_var("CERT_FILE", gateway_cert_file_str);
            env::set_var("AUTH_CERT_FILE", gateway_cert_file_str);
            env::set_var("PROTOCOL_VERSION", "1.3");
            env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
            env::set_var("SESSION_RESUMPTION", "true");
            env::set_var("ICKETS", "true");
            env::set_var("GATEWAY_SERVICE_PORTS", "8000-8010");
            env::set_var("GATEWAY_SERVICE_REPLY_HOST", "gwhost2");
            env::set_var("NO_MASK_ADDRESSES", "true");
            env::set_var("MODE", "control-plane");
            env::set_var("DATASOURCE", "in-memory-db");
            env::set_var("ACCESS_DB_CONNECT", access_db_file_str);
            env::set_var("SERVICE_DB_CONNECT", service_db_file_str);
            env::set_var("ROLE_DB_CONNECT", role_db_file_str);
            env::set_var("USER_DB_CONNECT", user_db_file_str);
            env::set_var("VERBOSE", "true");

            result = AppConfig::new();
        }
        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.server_port, 8888);
        assert!(config.gateway_service_host.is_some());
        assert_eq!(config.gateway_service_host.unwrap(), "gwhost1a".to_string());
        assert!(config.gateway_service_ports.is_some());
        assert_eq!(config.gateway_service_ports.unwrap(), (8000, 8010));
        assert!(!config.mask_addresses);
        assert_eq!(config.gateway_service_reply_host, "gwhost2".to_string());
        assert!(config.verbose_logging);
    }

    #[test]
    fn tlsservercfgbld_build() {
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key_file_str = gateway_key_file.to_str().unwrap();
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert_file_str = gateway_cert_file.to_str().unwrap();
        let mut auth_root_certs = rustls::RootCertStore::empty();
        for auth_root_cert in load_certificates(gateway_cert_file_str.to_string()).unwrap() {
            auth_root_certs.add(auth_root_cert).unwrap();
        }

        let config_builder = TlsServerConfigBuilder {
            certs: load_certificates(gateway_cert_file_str.to_string()).unwrap(),
            key: load_private_key(gateway_key_file_str.to_string()).unwrap(),
            cipher_suites: rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec(),
            protocol_versions: rustls::ALL_VERSIONS.to_vec(),
            auth_root_certs,
            crl_list: None,
            session_resumption: true,
            alpn_protocols: vec![alpn::Protocol::ControlPlane.to_string().into_bytes()],
        };

        if let Err(err) = config_builder.build() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn appconfig_parse_gateway_service_ports_when_invalid_range() {
        if let Ok(range) = AppConfig::parse_gateway_service_ports("20-NAN") {
            panic!("Unexpected result: val={:?}", &range);
        }
    }

    #[test]
    fn appconfig_parse_gateway_service_ports_when_valid_range() {
        let result = AppConfig::parse_gateway_service_ports("20-40");
        if let Ok(range) = result {
            assert_eq!(range, (20, 40));
            return;
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn appconfig_create_datasource_repositories_when_inmemdb_ds() {
        let datasource = DataSource::InMemoryDb;
        let access_db_file: PathBuf = DB_ACCESS_PATHPARTS.iter().collect();
        let access_db_file_str = access_db_file.to_str().unwrap().to_string();
        let service_db_file: PathBuf = DB_SERVICE_PATHPARTS.iter().collect();
        let service_db_file_str = service_db_file.to_str().unwrap().to_string();
        let role_db_file: PathBuf = DB_ROLE_PATHPARTS.iter().collect();
        let role_db_file_str = role_db_file.to_str().unwrap().to_string();
        let user_db_file: PathBuf = DB_USER_PATHPARTS.iter().collect();
        let user_db_file_str = user_db_file.to_str().unwrap().to_string();

        let access_db_file_str_copy = access_db_file_str.clone();
        let service_db_file_str_copy = service_db_file_str.clone();
        let role_db_file_str_copy = role_db_file_str.clone();
        let user_db_file_str_copy = user_db_file_str.clone();
        let repo_factories: (
            Box<dyn Fn() -> Arc<Mutex<dyn AccessRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn ServiceRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn RoleRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn UserRepository>>>,
        ) = (
            Box::new(move || {
                let mut access_repo = MockAccessRepo::new();
                access_repo
                    .expect_connect_to_datasource()
                    .with(predicate::eq(access_db_file_str_copy.to_owned()))
                    .times(1)
                    .return_once(move |_| Ok(()));
                Arc::new(Mutex::new(access_repo))
            }),
            Box::new(move || {
                let mut service_repo = MockServiceRepo::new();
                service_repo
                    .expect_connect_to_datasource()
                    .with(predicate::eq(service_db_file_str_copy.to_owned()))
                    .times(1)
                    .return_once(move |_| Ok(()));
                Arc::new(Mutex::new(service_repo))
            }),
            Box::new(move || {
                let mut role_repo = MockRoleRepo::new();
                role_repo
                    .expect_connect_to_datasource()
                    .with(predicate::eq(role_db_file_str_copy.to_owned()))
                    .times(1)
                    .return_once(move |_| Ok(()));
                Arc::new(Mutex::new(role_repo))
            }),
            Box::new(move || {
                let mut user_repo = MockUserRepo::new();
                user_repo
                    .expect_connect_to_datasource()
                    .with(predicate::eq(user_db_file_str_copy.to_owned()))
                    .times(1)
                    .return_once(move |_| Ok(()));
                Arc::new(Mutex::new(user_repo))
            }),
        );

        let result = AppConfig::create_datasource_repositories(
            &datasource,
            &Some(access_db_file_str),
            &Some(service_db_file_str),
            &Some(role_db_file_str),
            &Some(user_db_file_str),
            &repo_factories,
        );

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", err);
        }
    }

    #[test]
    fn appconfig_create_datasource_repositories_when_nodb_ds() {
        let repo_factories: (
            Box<dyn Fn() -> Arc<Mutex<dyn AccessRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn ServiceRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn RoleRepository>>>,
            Box<dyn Fn() -> Arc<Mutex<dyn UserRepository>>>,
        ) = (
            Box::new(move || {
                let mut access_repo = MockAccessRepo::new();
                access_repo.expect_connect_to_datasource().never();
                Arc::new(Mutex::new(access_repo))
            }),
            Box::new(move || {
                let mut service_repo = MockServiceRepo::new();
                service_repo.expect_connect_to_datasource().never();
                Arc::new(Mutex::new(service_repo))
            }),
            Box::new(move || {
                let mut role_repo = MockRoleRepo::new();
                role_repo.expect_connect_to_datasource().never();
                Arc::new(Mutex::new(role_repo))
            }),
            Box::new(move || {
                let mut user_repo = MockUserRepo::new();
                user_repo.expect_connect_to_datasource().never();
                Arc::new(Mutex::new(user_repo))
            }),
        );

        let datasource = DataSource::NoDb;

        let result = AppConfig::create_datasource_repositories(
            &datasource,
            &None,
            &None,
            &None,
            &None,
            &repo_factories,
        );

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", err);
        }
    }
}
