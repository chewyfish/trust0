use std::collections::HashMap;
use std::env;

use clap::Parser;

use trust0_common::error::AppError;

/// Represents the client configuration, used to create and stage the files appropriately for client installation.
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

    /// Trust0 client binary file
    #[arg(required = true, short = 'b', long = "client-binary-file", env)]
    pub client_binary_file: String,

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
    #[arg(required=false, long="protocol-version", env, value_parser=trust0_common::crypto::tls::verify_version, value_delimiter=',')]
    pub protocol_version: Option<Vec<String>>,

    /// Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead
    #[arg(required=false, long="cipher-suite", env, value_parser=trust0_common::crypto::tls::verify_suite, value_delimiter=',')]
    pub cipher_suite: Option<Vec<String>>,

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

impl AppConfigArgs {
    /// Convert to corresponding environment variable map
    pub fn into_env_map(self) -> HashMap<String, String> {
        let mut env_map = HashMap::new();
        env_map.insert(
            "CLIENT_BINARY_FILE".to_string(),
            self.client_binary_file.clone(),
        );
        env_map.insert("GATEWAY_HOST".to_string(), self.gateway_host.clone());
        env_map.insert("GATEWAY_PORT".to_string(), self.gateway_port.to_string());
        env_map.insert("AUTH_KEY_FILE".to_string(), self.auth_key_file.clone());
        env_map.insert("AUTH_CERT_FILE".to_string(), self.auth_cert_file.clone());
        env_map.insert(
            "CA_ROOT_CERT_FILE".to_string(),
            self.ca_root_cert_file.clone(),
        );
        if self.protocol_version.is_some() {
            env_map.insert(
                "PROTOCOL_VERSION".to_string(),
                self.protocol_version.unwrap().join(","),
            );
        }
        if self.cipher_suite.is_some() {
            env_map.insert(
                "CIPHER_SUITE".to_string(),
                self.cipher_suite.unwrap().join(","),
            );
        }
        if self.max_frag_size.is_some() {
            env_map.insert(
                "MAX_FRAG_SIZE".to_string(),
                self.max_frag_size.unwrap().to_string(),
            );
        }
        env_map.insert(
            "SESSION_RESUMPTION".to_string(),
            self.session_resumption.to_string(),
        );
        env_map.insert("NO_TICKETS".to_string(), self.no_tickets.to_string());
        env_map.insert("NO_SNI".to_string(), self.no_sni.to_string());
        env_map.insert("INSECURE".to_string(), self.insecure.to_string());
        env_map.insert("VERBOSE".to_string(), self.verbose.to_string());
        env_map
    }
}

pub struct AppConfig {
    pub args: AppConfigArgs,
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

        // Instantiate AppConfig
        Ok(AppConfig { args: config_args })
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
    use std::env;
    use std::path::PathBuf;
    use trust0_common::testutils;

    const CONFIG_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "client-config.rc"];
    const CERTFILE_ROOT_CA_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "root-ca.local.crt.pem",
    ];
    const CERTFILE_CLIENT0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.crt.pem",
    ];
    const KEYFILE_CLIENT0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.key.pem",
    ];
    const CLIENT_BINARY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "invalid.crl.pem"];

    fn clear_env_vars() {
        env::remove_var("CONFIG_FILE");
        env::remove_var("CLIENT_BINARY_FILE");
        env::remove_var("GATEWAY_HOST");
        env::remove_var("GATEWAY_PORT");
        env::remove_var("AUTH_KEY_FILE");
        env::remove_var("AUTH_CERT_FILE");
        env::remove_var("CA_ROOT_CERT_FILE");
        env::remove_var("PROTOCOL_VERSION");
        env::remove_var("CIPHER_SUITE");
        env::remove_var("MAX_FRAG_SIZE");
        env::remove_var("SESSION_RESUMPTION");
        env::remove_var("NO_TICKETS");
        env::remove_var("NO_SNI");
        env::remove_var("INSECURE");
        env::remove_var("VERBOSE");
    }

    // Make sure you lock TEST_MUTEX before calling this
    pub fn setup_complete_env_vars() {
        let config_file: PathBuf = CONFIG_FILE_PATHPARTS.iter().collect();
        let config_file_str = config_file.to_str().unwrap();
        let client_binary_file: PathBuf = CLIENT_BINARY_PATHPARTS.iter().collect();
        let client_binary_file_str = client_binary_file.to_str().unwrap();
        let ca_root_cert_file: PathBuf = CERTFILE_ROOT_CA_PATHPARTS.iter().collect();
        let ca_root_cert_file_str = ca_root_cert_file.to_str().unwrap();
        let client_key_file: PathBuf = KEYFILE_CLIENT0_PATHPARTS.iter().collect();
        let client_key_file_str = client_key_file.to_str().unwrap();
        let client_cert_file: PathBuf = CERTFILE_CLIENT0_PATHPARTS.iter().collect();
        let client_cert_file_str = client_cert_file.to_str().unwrap();
        clear_env_vars();
        env::set_var("CONFIG_FILE", config_file_str);
        env::set_var("CLIENT_BINARY_FILE", client_binary_file_str);
        env::set_var("GATEWAY_HOST", "gwhost1");
        env::set_var("GATEWAY_PORT", "8000");
        env::set_var("AUTH_KEY_FILE", client_key_file_str);
        env::set_var("AUTH_CERT_FILE", client_cert_file_str);
        env::set_var("CA_ROOT_CERT_FILE", ca_root_cert_file_str);
        env::set_var("PROTOCOL_VERSION", "1.2,1.3");
        env::set_var("CIPHER_SUITE", "TLS13_AES_256_GCM_SHA384");
        env::set_var("MAX_FRAG_SIZE", "1024");
        env::set_var("SESSION_RESUMPTION", "true");
        env::set_var("NO_TICKETS", "true");
        env::set_var("NO_SNI", "true");
        env::set_var("INSECURE", "true");
        env::set_var("VERBOSE", "true");
    }

    #[test]
    fn appcfg_new_when_all_supplied_and_valid() {
        let client_binary_file_str;
        let ca_root_cert_file_str;
        let client_key_file_str;
        let client_cert_file_str;
        let result;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            setup_complete_env_vars();
            env::remove_var("CONFIG_FILE");
            client_binary_file_str = env::var("CLIENT_BINARY_FILE").unwrap();
            ca_root_cert_file_str = env::var("CA_ROOT_CERT_FILE").unwrap();
            client_key_file_str = env::var("AUTH_KEY_FILE").unwrap();
            client_cert_file_str = env::var("AUTH_CERT_FILE").unwrap();

            result = AppConfig::new();
        }

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.args.client_binary_file, client_binary_file_str);
        assert_eq!(config.args.gateway_host, "gwhost1");
        assert_eq!(config.args.gateway_port, 8000);
        assert_eq!(config.args.auth_key_file, client_key_file_str);
        assert_eq!(config.args.auth_cert_file, client_cert_file_str);
        assert_eq!(config.args.ca_root_cert_file, ca_root_cert_file_str);
        assert!(config.args.protocol_version.is_some());
        assert_eq!(
            config.args.protocol_version.unwrap(),
            vec!["1.2".to_string(), "1.3".to_string()]
        );
        assert!(config.args.cipher_suite.is_some());
        assert_eq!(
            config.args.cipher_suite.unwrap(),
            vec!["TLS13_AES_256_GCM_SHA384".to_string()]
        );
        assert!(config.args.max_frag_size.is_some());
        assert_eq!(config.args.max_frag_size.unwrap(), 1024);
        assert_eq!(config.args.session_resumption, true);
        assert_eq!(config.args.no_tickets, true);
        assert_eq!(config.args.no_sni, true);
        assert_eq!(config.args.insecure, true);
        assert_eq!(config.args.verbose, true);
    }

    #[test]
    fn appcfg_new_when_mixed_configfile_and_env_supplied() {
        let config_file_str;
        let client_binary_file_str;
        let ca_root_cert_file_str;
        let client_key_file_str;
        let client_cert_file_str;
        let result;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            setup_complete_env_vars();
            env::remove_var("GATEWAY_PORT");
            env::remove_var("MAX_FRAG_SIZE");
            config_file_str = env::var("CONFIG_FILE").unwrap();
            client_binary_file_str = env::var("CLIENT_BINARY_FILE").unwrap();
            ca_root_cert_file_str = env::var("CA_ROOT_CERT_FILE").unwrap();
            client_key_file_str = env::var("AUTH_KEY_FILE").unwrap();
            client_cert_file_str = env::var("AUTH_CERT_FILE").unwrap();

            result = AppConfig::new();
        }

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert!(config.args.config_file.is_some());
        assert_eq!(config.args.config_file.unwrap(), config_file_str);
        assert_eq!(config.args.client_binary_file, client_binary_file_str);
        assert_eq!(config.args.gateway_host, "gwhost1");
        assert_eq!(config.args.gateway_port, 8888);
        assert_eq!(config.args.auth_key_file, client_key_file_str);
        assert_eq!(config.args.auth_cert_file, client_cert_file_str);
        assert_eq!(config.args.ca_root_cert_file, ca_root_cert_file_str);
        assert!(config.args.protocol_version.is_some());
        assert_eq!(
            config.args.protocol_version.unwrap(),
            vec!["1.2".to_string(), "1.3".to_string()]
        );
        assert!(config.args.cipher_suite.is_some());
        assert_eq!(
            config.args.cipher_suite.unwrap(),
            vec!["TLS13_AES_256_GCM_SHA384".to_string()]
        );
        assert!(config.args.max_frag_size.is_some());
        assert_eq!(config.args.max_frag_size.unwrap(), 128);
        assert_eq!(config.args.session_resumption, true);
        assert_eq!(config.args.no_tickets, true);
        assert_eq!(config.args.no_sni, true);
        assert_eq!(config.args.insecure, true);
        assert_eq!(config.args.verbose, true);
    }

    #[test]
    fn appcfgargs_into_env_map() {
        let expected_gateway_port = 8000;
        let expected_max_frag_size = 1024;
        let expected_bool_field_val = true;
        let expected_env_map = HashMap::from([
            ("CLIENT_BINARY_FILE".to_string(), "clientbin1".to_string()),
            ("GATEWAY_HOST".to_string(), "gwhost1".to_string()),
            (
                "GATEWAY_PORT".to_string(),
                expected_gateway_port.to_string(),
            ),
            ("AUTH_KEY_FILE".to_string(), "authkey1".to_string()),
            ("AUTH_CERT_FILE".to_string(), "authcert1".to_string()),
            ("CA_ROOT_CERT_FILE".to_string(), "cacert1".to_string()),
            ("PROTOCOL_VERSION".to_string(), "1.2,1.3".to_string()),
            (
                "CIPHER_SUITE".to_string(),
                "TLS13_AES_256_GCM_SHA384".to_string(),
            ),
            (
                "MAX_FRAG_SIZE".to_string(),
                expected_max_frag_size.to_string(),
            ),
            (
                "SESSION_RESUMPTION".to_string(),
                expected_bool_field_val.to_string(),
            ),
            (
                "NO_TICKETS".to_string(),
                expected_bool_field_val.to_string(),
            ),
            ("NO_SNI".to_string(), expected_bool_field_val.to_string()),
            ("INSECURE".to_string(), expected_bool_field_val.to_string()),
            ("VERBOSE".to_string(), expected_bool_field_val.to_string()),
        ]);
        let app_cfg = AppConfigArgs {
            config_file: None,
            client_binary_file: expected_env_map
                .get("CLIENT_BINARY_FILE")
                .unwrap()
                .to_string(),
            gateway_host: expected_env_map.get("GATEWAY_HOST").unwrap().to_string(),
            gateway_port: expected_gateway_port,
            auth_key_file: expected_env_map.get("AUTH_KEY_FILE").unwrap().to_string(),
            auth_cert_file: expected_env_map.get("AUTH_CERT_FILE").unwrap().to_string(),
            ca_root_cert_file: expected_env_map
                .get("CA_ROOT_CERT_FILE")
                .unwrap()
                .to_string(),
            protocol_version: Some(
                expected_env_map
                    .get("PROTOCOL_VERSION")
                    .unwrap()
                    .split(",")
                    .map(|val| val.to_string())
                    .collect(),
            ),
            cipher_suite: Some(
                expected_env_map
                    .get("CIPHER_SUITE")
                    .unwrap()
                    .split(",")
                    .map(|val| val.to_string())
                    .collect(),
            ),
            max_frag_size: Some(expected_max_frag_size),
            session_resumption: expected_bool_field_val,
            no_tickets: expected_bool_field_val,
            no_sni: expected_bool_field_val,
            insecure: expected_bool_field_val,
            verbose: expected_bool_field_val,
        };

        let env_map = app_cfg.into_env_map();

        assert_eq!(env_map, expected_env_map);
    }
}
