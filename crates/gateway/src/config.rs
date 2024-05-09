use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{env, fmt};

use clap::*;
use hickory_resolver::Resolver;
use lazy_static::lazy_static;
use pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs1KeyDer,
    PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

use crate::repository::access_repo::AccessRepository;
use crate::repository::in_memory_db::access_repo::InMemAccessRepo;
use crate::repository::in_memory_db::role_repo::InMemRoleRepo;
use crate::repository::in_memory_db::service_repo::InMemServiceRepo;
use crate::repository::in_memory_db::user_repo::InMemUserRepo;
#[cfg(feature = "mysql_db")]
use crate::repository::mysql_db::access_repo::MysqlServiceAccessRepo;
#[cfg(feature = "mysql_db")]
use crate::repository::mysql_db::role_repo::MysqlRoleRepo;
#[cfg(feature = "mysql_db")]
use crate::repository::mysql_db::service_repo::MysqlServiceRepo;
#[cfg(feature = "mysql_db")]
use crate::repository::mysql_db::user_repo::MysqlUserRepo;
#[cfg(feature = "postgres_db")]
use crate::repository::postgres_db::access_repo::PostgresServiceAccessRepo;
#[cfg(feature = "postgres_db")]
use crate::repository::postgres_db::role_repo::PostgresRoleRepo;
#[cfg(feature = "postgres_db")]
use crate::repository::postgres_db::service_repo::PostgresServiceRepo;
#[cfg(feature = "postgres_db")]
use crate::repository::postgres_db::user_repo::PostgresUserRepo;
use crate::repository::role_repo::RoleRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use regex::Regex;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use trust0_common::authn::authenticator::AuthnType;
use trust0_common::crypto::crl::CRLFile;
use trust0_common::crypto::file::{load_certificates, load_private_key};
use trust0_common::crypto::{alpn, ca};
use trust0_common::error::AppError;
use trust0_common::file::ReloadableFile;

#[cfg(windows)]
pub const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
pub const LINE_ENDING: &str = "\n";

pub const DEFAULT_CA_CERTIFICATE_VALIDITY_PERIOD_DAYS: u16 = 365;
pub const DEFAULT_CA_CERTIFICATE_REISSUANCE_THRESHOLD_DAYS: u16 = 20;
pub const DEFAULT_CA_KEY_ALGORITHM: KeyAlgorithm = KeyAlgorithm::Ed25519;

/// Client response messages
pub const RESPCODE_0403_FORBIDDEN: u16 = 403;
pub const RESPCODE_0420_INVALID_CLIENT_CERTIFICATE: u16 = 420;
pub const RESPCODE_0421_UNKNOWN_USER: u16 = 421;
pub const RESPCODE_0422_INACTIVE_USER: u16 = 422;
pub const RESPCODE_0423_INVALID_REQUEST: u16 = 423;
pub const RESPCODE_0424_INVALID_ALPN_PROTOCOL: u16 = 424;
pub const RESPCODE_0425_INACTIVE_SERVICE_PROXY: u16 = 425;
pub const RESPCODE_0426_CONTROL_PLANE_ALREADY_CONNECTED: u16 = 426;
pub const RESPCODE_0427_CONTROL_PLANE_NOT_AUTHENTICATED: u16 = 427;
pub const RESPCODE_0500_SYSTEM_ERROR: u16 = 500;
pub const RESPCODE_0520_UNKNOWN_CODE: u16 = 520;
const RESPMSG_0403_FORBIDDEN: &str = "[E0403] Access is forbidden";
const RESPMSG_0420_INVALID_CLIENT_CERTIFICATE: &str = "[E0420] Invalid client certificate";
const RESPMSG_0421_UNKNOWN_USER: &str = "[E0421] Unknown user is inactive";
const RESPMSG_0422_INACTIVE_USER: &str = "[E0422] User account is inactive";
const RESPMSG_0423_INVALID_REQUEST: &str = "[E0423] Invalid request";
const RESPMSG_0424_INVALID_ALPN_PROTOCOL: &str = "[E0424] Invalid ALPN protocol";
const RESPMSG_0425_INACTIVE_SERVICE_PROXY: &str = "[E0425] Inactive service proxy";
const RESPMSG_0426_CONTROL_PLANE_ALREADY_CONNECTED: &str =
    "[E0426] Control plane already connected";
const RESPMSG_0427_CONTROL_PLANE_NOT_AUTHENTICATED: &str =
    "[E0427] Control plane not authenticated";
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
            (
                RESPCODE_0426_CONTROL_PLANE_ALREADY_CONNECTED,
                RESPMSG_0426_CONTROL_PLANE_ALREADY_CONNECTED,
            ),
            (
                RESPCODE_0427_CONTROL_PLANE_NOT_AUTHENTICATED,
                RESPMSG_0427_CONTROL_PLANE_NOT_AUTHENTICATED,
            ),
            (RESPCODE_0500_SYSTEM_ERROR, RESPMSG_0500_SYSTEM_ERROR),
            (RESPCODE_0520_UNKNOWN_CODE, RESPMSG_0520_UNKNOWN_CODE),
        ])
    };
}

const INMEMDB_ACCESS_FILENAME: &str = "trust0-db-access.json";
const INMEMDB_ROLE_FILENAME: &str = "trust0-db-role.json";
const INMEMDB_SERVICE_FILENAME: &str = "trust0-db-service.json";
const INMEMDB_USER_FILENAME: &str = "trust0-db-user.json";

/// Datasource configuration for the trust framework entities
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[allow(clippy::enum_variant_names)]
pub enum DataSource {
    /// In-memory DB, with a simple backing persistence store. Entity store connect string is file path to directory holding JSON record files.
    InMemoryDb,

    /// MySQL DB
    #[cfg(feature = "mysql_db")]
    MysqlDb,

    /// Postgres DB
    #[cfg(feature = "postgres_db")]
    PostgresDb,

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
        match self {
            #[cfg(feature = "mysql_db")]
            DataSource::MysqlDb => (
                Box::new(|| Arc::new(Mutex::new(MysqlServiceAccessRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(MysqlServiceRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(MysqlRoleRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(MysqlUserRepo::new()))),
            ),
            #[cfg(feature = "postgres_db")]
            DataSource::PostgresDb => (
                Box::new(|| Arc::new(Mutex::new(PostgresServiceAccessRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(PostgresServiceRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(PostgresRoleRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(PostgresUserRepo::new()))),
            ),
            _ => (
                Box::new(|| Arc::new(Mutex::new(InMemAccessRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(InMemServiceRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(InMemRoleRepo::new()))),
                Box::new(|| Arc::new(Mutex::new(InMemUserRepo::new()))),
            ),
        }
    }
}

/// Supported public key algorithms
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum KeyAlgorithm {
    /// Elliptic curve P-256
    #[default]
    EcdsaP256,
    /// Elliptic curve P-384
    EcdsaP384,
    /// Edwards curve DSA Ed25519
    Ed25519,
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match self {
                KeyAlgorithm::EcdsaP256 => "ecdsa-p256",
                KeyAlgorithm::EcdsaP384 => "ecdsa-p384",
                KeyAlgorithm::Ed25519 => "ed25519",
            }
        )
    }
}

impl From<KeyAlgorithm> for ca::KeyAlgorithm {
    fn from(key_algorithm: KeyAlgorithm) -> Self {
        Self::from(&key_algorithm)
    }
}

impl From<&KeyAlgorithm> for ca::KeyAlgorithm {
    fn from(key_algorithm: &KeyAlgorithm) -> Self {
        match key_algorithm {
            KeyAlgorithm::EcdsaP256 => ca::KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384 => ca::KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::Ed25519 => ca::KeyAlgorithm::Ed25519,
        }
    }
}

/// Runs a Trust0 gateway server on <HOST>:<PORT>
#[derive(Parser)]
#[command(author, version, long_about, disable_help_flag = true)]
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

    /// The <HOST> address used by the gateway's listener binds for Trust0 client connections
    #[arg(required = true, short = 'h', long = "host", env)]
    pub host: String,

    /// The <PORT> used by the gateway's listener binds for Trust0 client connections
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
    /// Note - For ECDSA keys, curves 'NIST P-256' and 'NIST P-384' have been tested
    /// Note - For EdDSA keys, currently only 'Ed25519' is supported
    #[arg(required=true, short='k', long="key-file", env, value_parser=trust0_common::crypto::file::verify_private_key_file, verbatim_doc_comment)]
    pub key_file: String,

    /// Accept client authentication certificates signed by those roots provided in <AUTH_CERT_FILE>
    #[arg(required=true, short='a', long="auth-cert-file", env, value_parser=trust0_common::crypto::file::verify_certificates)]
    pub auth_cert_file: String,

    /// Public key pair corresponding to <AUTH_CERT_FILE> certificates, used to sign client authentication certificates.
    /// This is not required, is CA is not enabled (<CA_ENABLED>)
    #[arg(required=false, long="auth-key-file", env, value_parser=trust0_common::crypto::file::verify_private_key_file, verbatim_doc_comment)]
    pub auth_key_file: Option<String>,

    /// Perform client certificate revocation checking using the DER-encoded <CRL_FILE(s)>. Will update list during runtime, if file has changed.
    #[arg(required=false, long="crl-file", env, value_parser=trust0_common::crypto::file::verify_crl_list)]
    pub crl_file: Option<String>,

    /// Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead. Provided value is a comma-separated list of suites.
    #[arg(required=false, long="cipher-suite", env, value_parser=trust0_common::crypto::tls::lookup_suite, value_delimiter=',')]
    pub cipher_suite: Option<Vec<rustls::SupportedCipherSuite>>,

    /// Negotiate ALPN using <ALPN_PROTOCOL(s)>. Provided value is a comma-separated list of protocols.
    #[arg(required=false, long="alpn-protocol", env, value_parser=trust0_common::crypto::tls::parse_alpn_protocol, value_delimiter=',')]
    pub alpn_protocol: Option<Vec<Vec<u8>>>,

    /// Hostname/ip of this gateway given to clients, used in service proxy connections (if not supplied, clients will determine that on their own)
    #[arg(required = true, long = "gateway-service-host", env)]
    pub gateway_service_host: Option<String>,

    /// Service proxy port range. If this is omitted, service connections can be made to the primary gateway port (in addition to the control plane connection). ALPN protocol configuration is used to specify the service ID.
    #[arg(required=false, long="gateway-service-ports", env, value_parser=crate::config::AppConfig::parse_gateway_service_ports)]
    pub gateway_service_ports: Option<(u16, u16)>,

    /// Hostname/ip of this gateway, which is routable by UDP services, used in UDP socket replies. If not supplied, then "127.0.0.1" will be used (if necessary)
    #[arg(required = false, long = "gateway-service-reply-host", env)]
    pub gateway_service_reply_host: Option<String>,

    /// Secondary authentication mechanism (in addition to client certificate authentication)
    /// Current schemes: 'insecure': No authentication, all privileged actions allowed
    ///                  'scram-sha256': SCRAM SHA256 using credentials stored in user repository
    #[arg(required = false, long = "mfa-scheme", default_value_t = trust0_common::authn::authenticator::AuthnType::Insecure, env, verbatim_doc_comment)]
    pub mfa_scheme: AuthnType,

    /// Enable verbose logging
    #[arg(required = false, long = "verbose", env)]
    pub verbose: bool,

    /// Show all gateway and service addresses (in REPL shell responses)
    #[arg(required = false, long = "no-mask-addrs", default_value_t = false, env)]
    pub no_mask_addresses: bool,

    /// DB datasource type
    #[arg(required = false, value_enum, long = "datasource", default_value_t = crate::config::DataSource::InMemoryDb, env)]
    pub datasource: DataSource,

    /// DB entity store connect specifier string. Specification format is dependent on <DATASOURCE> type.
    /// For 'in-memory-db' datasource: Directory holding JSON files named 'trust0-db-access.json', 'trust0-db-role.json', 'trust0-db-service.json', 'trust0-db-user.json'
    /// For 'mysql-db' datasource: Connection URL detailed in diesel documentation - https://docs.rs/diesel/2.1.4/diesel/mysql/struct.MysqlConnection.html
    /// For 'postgres-db' datasource: Standard Postgres connect string specification - https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
    #[arg(required = false, long = "db-connect", env, verbatim_doc_comment)]
    pub db_connect: Option<String>,

    /// [CA] Enable certificate authority. This will dynamically issue expiring certificates to clients.
    #[arg(required = false, long = "ca-enabled", default_value_t = false, env)]
    pub ca_enabled: bool,

    /// [CA] Public key algorithm used by certificate authority for new client certificates. (Requires CA to be enabled)
    #[arg(
        required = false,
        long = "ca-key-algorithm",
        default_value_t = crate::config::DEFAULT_CA_KEY_ALGORITHM,
        env,
    )]
    pub ca_key_algorithm: KeyAlgorithm,

    /// [CA] Client certificate validity period as expressed in number of days (Requires CA to be enabled)
    #[arg(
        required = false,
        long = "ca-validity-period-days",
        default_value_t = crate::config::DEFAULT_CA_CERTIFICATE_VALIDITY_PERIOD_DAYS,
        env,
    )]
    pub ca_validity_period_days: u16,

    /// [CA] Certificate re-issuance time period (before certificate expiry) threshold in days (Requires CA to be enabled)
    #[arg(
        required = false,
        long = "ca-reissuance-threshold-days",
        default_value_t = crate::config::DEFAULT_CA_CERTIFICATE_REISSUANCE_THRESHOLD_DAYS,
        env,
    )]
    pub ca_reissuance_threshold_days: u16,

    /// Print help
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,
}

/// TLS server configuration builder
pub struct TlsServerConfigBuilder {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub cipher_suites: Vec<rustls::SupportedCipherSuite>,
    pub auth_root_certs: rustls::RootCertStore,
    pub crl_list: Option<Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>>>,
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
        .with_protocol_versions(&[&rustls::version::TLS13])
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
        tls_server_config.alpn_protocols.clone_from(&self.alpn_protocols);

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
    pub server_host: String,
    pub server_port: u16,
    pub tls_server_config_builder: TlsServerConfigBuilder,
    pub crl_reloader_loading: Arc<Mutex<bool>>,
    pub mfa_scheme: AuthnType,
    pub verbose_logging: bool,
    pub access_repo: Arc<Mutex<dyn AccessRepository>>,
    pub service_repo: Arc<Mutex<dyn ServiceRepository>>,
    pub role_repo: Arc<Mutex<dyn RoleRepository>>,
    pub user_repo: Arc<Mutex<dyn UserRepository>>,
    pub gateway_service_host: Option<String>,
    pub gateway_service_ports: Option<(u16, u16)>,
    pub gateway_service_reply_host: String,
    pub mask_addresses: bool,
    pub ca_enabled: bool,
    pub ca_signer_cert_file: String,
    pub ca_signer_key_file: Option<String>,
    pub ca_key_algorithm: KeyAlgorithm,
    pub ca_validity_period_days: u16,
    pub ca_reissuance_threshold_days: u16,
    pub dns_client: Resolver,
}

impl AppConfig {
    /// Load config
    pub fn new() -> Result<Self, AppError> {
        // Populate environment w/given config file (if provided)
        let mut config_file = env::var_os("CONFIG_FILE");
        if config_file.is_none()
            && (env::args_os().len() >= 3)
            && (env::args_os().nth(1).unwrap().eq("-f")
                || env::args_os().nth(1).unwrap().eq("--config-file"))
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
            &config_args.db_connect,
            &config_args.datasource.repository_factories(),
        )?;

        // Create TLS server configuration builder
        let auth_certs = load_certificates(&config_args.auth_cert_file).unwrap();
        let certs = load_certificates(&config_args.cert_file).unwrap();
        let key = load_private_key(&config_args.key_file).unwrap();

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

        let mut alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];
        for service in repositories.1.as_ref().lock().unwrap().get_all()? {
            alpn_protocols
                .push(alpn::Protocol::create_service_protocol(service.service_id).into_bytes())
        }

        let tls_server_config_builder = TlsServerConfigBuilder {
            certs,
            key,
            cipher_suites,
            auth_root_certs,
            crl_list,
            alpn_protocols,
        };

        // Miscellaneous
        let dns_client = Resolver::from_system_conf().map_err(|err| {
            AppError::General(format!("Error instantiating DNS resolver: err={:?}", &err))
        })?;

        // Instantiate AppConfig
        Ok(AppConfig {
            server_host: config_args.host,
            server_port: config_args.port,
            tls_server_config_builder,
            crl_reloader_loading,
            mfa_scheme: config_args.mfa_scheme,
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
            ca_enabled: config_args.ca_enabled,
            ca_signer_cert_file: config_args.auth_cert_file.clone(),
            ca_signer_key_file: config_args.auth_key_file.clone(),
            ca_key_algorithm: config_args.ca_key_algorithm,
            ca_validity_period_days: config_args.ca_validity_period_days,
            ca_reissuance_threshold_days: config_args.ca_reissuance_threshold_days,
            dns_client,
        })
    }

    #[allow(clippy::type_complexity)]
    /// Instantiate main repositories based on datasource config. Returns tuple of access, service, role and user repositories.
    fn create_datasource_repositories(
        datasource: &DataSource,
        db_connect: &Option<String>,
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

        if let Some(db_connect_str) = db_connect {
            match datasource {
                DataSource::InMemoryDb => {
                    let db_dir = PathBuf::from_str(db_connect_str).unwrap();
                    access_repository.lock().unwrap().connect_to_datasource(
                        db_dir.join(INMEMDB_ACCESS_FILENAME).to_str().unwrap(),
                    )?;
                    role_repository.lock().unwrap().connect_to_datasource(
                        db_dir.join(INMEMDB_ROLE_FILENAME).to_str().unwrap(),
                    )?;
                    service_repository.lock().unwrap().connect_to_datasource(
                        db_dir.join(INMEMDB_SERVICE_FILENAME).to_str().unwrap(),
                    )?;
                    user_repository.lock().unwrap().connect_to_datasource(
                        db_dir.join(INMEMDB_USER_FILENAME).to_str().unwrap(),
                    )?;
                }
                #[cfg(feature = "mysql_db")]
                DataSource::MysqlDb => {
                    access_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                    role_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                    service_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                    user_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                }
                #[cfg(feature = "postgres_db")]
                DataSource::PostgresDb => {
                    access_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                    role_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                    service_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                    user_repository
                        .lock()
                        .unwrap()
                        .connect_to_datasource(db_connect_str)?;
                }
                _ => {}
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
    #[cfg(feature = "postgres_db")]
    use trust0_common::model;

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
    const DB_DIR_PATHPARTS: [&str; 2] = [env!("CARGO_MANIFEST_DIR"), "testdata"];

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
        let gateway_cert = load_certificates(gateway_cert_file.to_str().as_ref().unwrap())?;
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key = load_private_key(gateway_key_file.to_str().as_ref().unwrap())?;
        let auth_root_certs = rustls::RootCertStore::empty();
        let cipher_suites: Vec<rustls::SupportedCipherSuite> =
            rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
        let alpn_protocols = vec![alpn::Protocol::ControlPlane.to_string().into_bytes()];

        let tls_server_config_builder = TlsServerConfigBuilder {
            certs: gateway_cert,
            key: gateway_key,
            cipher_suites,
            auth_root_certs,
            crl_list: None,
            alpn_protocols,
        };

        let dns_client = Resolver::from_system_conf().map_err(|err| {
            AppError::General(format!("Error instantiating DNS resolver: err={:?}", &err))
        })?;

        Ok(AppConfig {
            server_host: "127.0.0.1".to_string(),
            server_port: 2000,
            tls_server_config_builder,
            crl_reloader_loading: Arc::new(Mutex::new(false)),
            mfa_scheme: AuthnType::Insecure,
            verbose_logging: false,
            access_repo,
            service_repo,
            role_repo,
            user_repo,
            gateway_service_host: None,
            gateway_service_ports: None,
            gateway_service_reply_host: "127.0.0.1".to_string(),
            mask_addresses: false,
            ca_enabled: false,
            ca_signer_cert_file: "".to_string(),
            ca_signer_key_file: None,
            ca_key_algorithm: Default::default(),
            ca_validity_period_days: 0,
            ca_reissuance_threshold_days: 0,
            dns_client,
        })
    }

    fn clear_env_vars() {
        env::remove_var("CONFIG_FILE");
        env::remove_var("HOST");
        env::remove_var("PORT");
        env::remove_var("KEY_FILE");
        env::remove_var("CERT_FILE");
        env::remove_var("AUTH_CERT_FILE");
        env::remove_var("AUTH_KEY_FILE");
        env::remove_var("PROTOCOL_VERSION");
        env::remove_var("CIPHER_SUITE");
        env::remove_var("ICKETS");
        env::remove_var("GATEWAY_SERVICE_HOST");
        env::remove_var("GATEWAY_SERVICE_PORTS");
        env::remove_var("GATEWAY_SERVICE_REPLY_HOST");
        env::remove_var("NO_MASK_ADDRESSES");
        env::remove_var("MODE");
        env::remove_var("DATASOURCE");
        env::remove_var("DB_CONNECT");
        env::remove_var("CA_ENABLED");
        env::remove_var("CA_KEY_ALGORITHM");
        env::remove_var("CA_VALIDITY_PERIOD_DAYS");
        env::remove_var("CA_REISSUANCE_THRESHOLD_DAYS");
        env::remove_var("VERBOSE");
    }

    // tests
    // =====

    #[test]
    fn keyalg_into_ca_key_algorithm() {
        let key_algorithm: ca::KeyAlgorithm = KeyAlgorithm::EcdsaP256.into();
        assert_eq!(key_algorithm, ca::KeyAlgorithm::EcdsaP256);
        let key_algorithm: ca::KeyAlgorithm = KeyAlgorithm::EcdsaP384.into();
        assert_eq!(key_algorithm, ca::KeyAlgorithm::EcdsaP384);
        let key_algorithm: ca::KeyAlgorithm = KeyAlgorithm::Ed25519.into();
        assert_eq!(key_algorithm, ca::KeyAlgorithm::Ed25519);
    }

    #[test]
    fn keyalg_display() {
        assert_eq!(format!("{}", KeyAlgorithm::EcdsaP256), "ecdsa-p256");
        assert_eq!(format!("{}", KeyAlgorithm::EcdsaP384), "ecdsa-p384");
        assert_eq!(format!("{}", KeyAlgorithm::Ed25519), "ed25519");
    }

    #[cfg(feature = "postgres_db")]
    #[test]
    fn datasource_repository_factories_when_postgresdb() {
        _ = DataSource::PostgresDb.repository_factories();
    }

    #[cfg(feature = "postgres_db")]
    #[test]
    fn datasource_repository_factories_when_not_postgresdb() {
        let (access_repo_factory, service_repo_factory, role_repo_factory, user_repo_factory) =
            DataSource::default().repository_factories();

        let access_repo = access_repo_factory();
        let access = access_repo
            .lock()
            .unwrap()
            .get(200, &model::access::EntityType::User, 100);
        assert!(access.is_ok());
        assert!(access.unwrap().is_none());

        let service_repo = service_repo_factory();
        let services = service_repo.lock().unwrap().get_all();
        assert!(services.is_ok());
        assert!(services.unwrap().is_empty());

        let role_repo = role_repo_factory();
        let roles = role_repo.lock().unwrap().get_all();
        assert!(roles.is_ok());
        assert!(roles.unwrap().is_empty());

        let user_repo = user_repo_factory();
        let user = user_repo.lock().unwrap().get(100);
        assert!(user.is_ok());
        assert!(user.unwrap().is_none());
    }

    #[test]
    fn appcfg_new_when_all_supplied_and_valid() {
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key_file_str = gateway_key_file.to_str().unwrap();
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert_file_str = gateway_cert_file.to_str().unwrap();
        let db_dir: PathBuf = DB_DIR_PATHPARTS.iter().collect();
        let db_dir_str = db_dir.to_str().unwrap();
        let result;
        {
            let mutex = TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            clear_env_vars();
            env::set_var("HOST", "127.0.0.1");
            env::set_var("PORT", "8000");
            env::set_var("KEY_FILE", gateway_key_file_str);
            env::set_var("CERT_FILE", gateway_cert_file_str);
            env::set_var("AUTH_CERT_FILE", gateway_cert_file_str);
            env::set_var("AUTH_KEY_FILE", gateway_key_file_str);
            env::set_var("PROTOCOL_VERSION", "1.3");
            env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
            env::set_var("ICKETS", "true");
            env::set_var("GATEWAY_SERVICE_HOST", "gwhost1");
            env::set_var("GATEWAY_SERVICE_PORTS", "8000-8010");
            env::set_var("GATEWAY_SERVICE_REPLY_HOST", "gwhost2");
            env::set_var("NO_MASK_ADDRESSES", "true");
            env::set_var("MODE", "control-plane");
            env::set_var("DATASOURCE", "in-memory-db");
            env::set_var("DB_CONNECT", db_dir_str);
            env::set_var("CA_ENABLED", "true");
            env::set_var("CA_KEY_ALGORITHM", "ecdsa-p384");
            env::set_var("CA_VALIDITY_PERIOD_DAYS", "200");
            env::set_var("CA_REISSUANCE_THRESHOLD_DAYS", "30");
            env::set_var("VERBOSE", "true");

            result = AppConfig::new();
        }

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.server_host, "127.0.0.1");
        assert_eq!(config.server_port, 8000);
        assert!(config.gateway_service_host.is_some());
        assert_eq!(config.gateway_service_host.unwrap(), "gwhost1".to_string());
        assert!(config.gateway_service_ports.is_some());
        assert_eq!(config.gateway_service_ports.unwrap(), (8000, 8010));
        assert!(!config.mask_addresses);
        assert_eq!(config.gateway_service_reply_host, "gwhost2".to_string());
        assert!(config.ca_enabled);
        assert_eq!(
            config.ca_signer_cert_file,
            gateway_cert_file_str.to_string()
        );
        assert!(config.ca_signer_key_file.is_some());
        assert_eq!(
            config.ca_signer_key_file.as_ref().unwrap(),
            &gateway_key_file_str.to_string()
        );
        assert_eq!(config.ca_key_algorithm, KeyAlgorithm::EcdsaP384);
        assert_eq!(config.ca_validity_period_days, 200);
        assert_eq!(config.ca_reissuance_threshold_days, 30);
        assert!(config.verbose_logging);
    }

    #[test]
    fn appcfg_new_when_mixed_configfile_and_env_and_defaults() {
        let config_file: PathBuf = CONFIG_FILE_PATHPARTS.iter().collect();
        let config_file_str = config_file.to_str().unwrap();
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key_file_str = gateway_key_file.to_str().unwrap();
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert_file_str = gateway_cert_file.to_str().unwrap();
        let db_dir: PathBuf = DB_DIR_PATHPARTS.iter().collect();
        let db_dir_str = db_dir.to_str().unwrap();
        let result;
        {
            let mutex = TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            clear_env_vars();
            env::set_var("CONFIG_FILE", config_file_str);
            env::set_var("HOST", "127.0.0.1");
            env::set_var("KEY_FILE", gateway_key_file_str);
            env::set_var("CERT_FILE", gateway_cert_file_str);
            env::set_var("AUTH_CERT_FILE", gateway_cert_file_str);
            env::set_var("AUTH_KEY_FILE", gateway_key_file_str);
            env::set_var("PROTOCOL_VERSION", "1.3");
            env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
            env::set_var("ICKETS", "true");
            env::set_var("GATEWAY_SERVICE_PORTS", "8000-8010");
            env::set_var("GATEWAY_SERVICE_REPLY_HOST", "gwhost2");
            env::set_var("NO_MASK_ADDRESSES", "true");
            env::set_var("MODE", "control-plane");
            env::set_var("DATASOURCE", "in-memory-db");
            env::set_var("DB_CONNECT", db_dir_str);
            env::set_var("VERBOSE", "true");

            result = AppConfig::new();
        }
        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.server_host, "127.0.0.1");
        assert_eq!(config.server_port, 8888);
        assert!(config.gateway_service_host.is_some());
        assert_eq!(config.gateway_service_host.unwrap(), "gwhost1a".to_string());
        assert!(config.gateway_service_ports.is_some());
        assert_eq!(config.gateway_service_ports.unwrap(), (8000, 8010));
        assert!(!config.mask_addresses);
        assert_eq!(config.gateway_service_reply_host, "gwhost2".to_string());
        assert!(!config.ca_enabled);
        assert_eq!(
            config.ca_signer_cert_file,
            gateway_cert_file_str.to_string()
        );
        assert!(config.ca_signer_key_file.is_some());
        assert_eq!(
            config.ca_signer_key_file.as_ref().unwrap(),
            &gateway_key_file_str.to_string()
        );
        assert_eq!(config.ca_key_algorithm, DEFAULT_CA_KEY_ALGORITHM);
        assert_eq!(
            config.ca_validity_period_days,
            DEFAULT_CA_CERTIFICATE_VALIDITY_PERIOD_DAYS
        );
        assert_eq!(
            config.ca_reissuance_threshold_days,
            DEFAULT_CA_CERTIFICATE_REISSUANCE_THRESHOLD_DAYS
        );
        assert!(config.verbose_logging);
    }

    #[test]
    fn tlsservercfgbld_build() {
        let gateway_key_file: PathBuf = KEYFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_key_file_str = gateway_key_file.to_str().unwrap();
        let gateway_cert_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let gateway_cert_file_str = gateway_cert_file.to_str().unwrap();
        let mut auth_root_certs = rustls::RootCertStore::empty();
        for auth_root_cert in load_certificates(gateway_cert_file_str).unwrap() {
            auth_root_certs.add(auth_root_cert).unwrap();
        }

        let config_builder = TlsServerConfigBuilder {
            certs: load_certificates(gateway_cert_file_str).unwrap(),
            key: load_private_key(gateway_key_file_str).unwrap(),
            cipher_suites: rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec(),
            auth_root_certs,
            crl_list: None,
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
        let db_dir: PathBuf = DB_DIR_PATHPARTS.iter().collect();
        let db_dir_str = db_dir.to_str().unwrap();

        let access_db_file_str_copy = db_dir
            .join(INMEMDB_ACCESS_FILENAME)
            .to_str()
            .unwrap()
            .to_string();
        let role_db_file_str_copy = db_dir
            .join(INMEMDB_ROLE_FILENAME)
            .to_str()
            .unwrap()
            .to_string();
        let service_db_file_str_copy = db_dir
            .join(INMEMDB_SERVICE_FILENAME)
            .to_str()
            .unwrap()
            .to_string();
        let user_db_file_str_copy = db_dir
            .join(INMEMDB_USER_FILENAME)
            .to_str()
            .unwrap()
            .to_string();
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
            &Some(db_dir_str.to_string()),
            &repo_factories,
        );

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", err);
        }
    }

    #[cfg(feature = "postgres_db")]
    #[test]
    fn appconfig_create_datasource_repositories_when_postgresdb_ds() {
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

        let datasource = DataSource::PostgresDb;

        let result = AppConfig::create_datasource_repositories(&datasource, &None, &repo_factories);

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

        let result = AppConfig::create_datasource_repositories(&datasource, &None, &repo_factories);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", err);
        }
    }
}
