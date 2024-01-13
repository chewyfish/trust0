use std::fmt;

use clap::Parser;

use trust0_common::error::AppError;

/// (Password-based) Authentication implementation types
#[derive(Clone, Debug, PartialEq)]
pub enum AuthnType {
    ScramSha256,
}

impl fmt::Display for AuthnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AuthnType::ScramSha256 => "scram-sha256",
            }
        )
    }
}

impl From<String> for AuthnType {
    fn from(type_name: String) -> Self {
        Self::from(type_name.as_str())
    }
}

impl From<&str> for AuthnType {
    fn from(type_name: &str) -> Self {
        match type_name {
            "scram-sha256" => AuthnType::ScramSha256,
            _ => panic!("Invalid AuthnType: val={}", type_name),
        }
    }
}

/// Creates valid user password hashes, usable by (relevant) Trust0 authentication schemes
#[derive(Parser, Debug)]
#[command(author, version, long_about)]
pub struct AppConfigArgs {
    /// Authentication mechanism
    /// Current schemes: 'scram-sha256': SCRAM SHA256 using credentials stored in user repository
    #[arg(required = true, long = "authn-scheme", env, verbatim_doc_comment)]
    pub authn_scheme: AuthnType,
}

pub struct AppConfig {
    pub args: AppConfigArgs,
}

impl AppConfig {
    // load config
    pub fn new() -> Result<Self, AppError> {
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
    use trust0_common::testutils;

    pub fn setup_env_vars(authn_scheme_str: &str) {
        env::set_var("AUTHN_SCHEME", authn_scheme_str);
    }

    #[test]
    fn appcfg_new_when_scramsha256_authn_supplied() {
        let result;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            setup_env_vars("scram-sha256");
            result = AppConfig::new();
        }

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config = result.unwrap();

        assert_eq!(config.args.authn_scheme, AuthnType::ScramSha256);
    }
}
