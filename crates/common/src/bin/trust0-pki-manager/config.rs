use clap::{Parser, Subcommand, ValueEnum};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use trust0_common::crypto::ca;

use trust0_common::error::AppError;

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

impl From<KeyAlgorithm> for ca::KeyAlgorithm {
    fn from(key_algorithm: KeyAlgorithm) -> Self {
        match key_algorithm {
            KeyAlgorithm::EcdsaP256 => ca::KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384 => ca::KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::Ed25519 => ca::KeyAlgorithm::Ed25519,
        }
    }
}

/// Trust0 PKI resource administration tool. Refer to commands help for further information.
#[derive(Parser, Debug)]
#[command(version, version, long_about)]
pub struct AppConfigArgs {
    #[command(subcommand)]
    pub command: Command,
}

#[allow(clippy::enum_variant_names)]
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create root CA certificate and key files usable in a Trust0 environment.
    RootCaPkiCreator {
        /// Store root CA certificate to <CERT_FILE>. This certificate will be PEM-encoded
        #[arg(required = true, short = 'c', long = "cert-file", env)]
        cert_file: String,

        /// Store root CA private key to <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
        /// Note - For ECDSA keys, NIST curves 'P-256' and 'P-384' are supported
        /// Note - For EdDSA keys, 'Ed25519' is supported
        #[arg(
            required = true,
            short = 'k',
            long = "key-file",
            env,
            verbatim_doc_comment
        )]
        key_file: String,

        /// Private key algorithm
        #[arg(required = true, short = 'a', long = "key-algorithm", env)]
        key_algorithm: KeyAlgorithm,

        /// Serial number, to uniquely identify certificate, up to 20 (hex character 0-F) octets
        #[arg(required = false, short = 's', long = "serial-number", value_parser=crate::config::AppConfig::parse_serial_number, env)]
        serial_number: Option<std::vec::Vec<u8>>,

        /// Certificate validity end time (RFC3339 format, for example '2021-01-02T03:04:05Z')
        #[arg(required=true, long="validity-not-after", value_parser=crate::config::AppConfig::parse_offset_date_time, env)]
        validity_not_after: OffsetDateTime,

        /// Certificate validity start time (RFC3339 format, for example '2021-01-02T03:04:05Z'). Defaults to yesterday.
        #[arg(required=false, long="validity-not-before", value_parser=crate::config::AppConfig::parse_offset_date_time, env)]
        validity_not_before: Option<OffsetDateTime>,

        /// Certificate subject common-name
        #[arg(required = true, long = "subject-common-name", env)]
        subject_common_name: String,

        /// Certificate subject organization. Defaults to 'NA'.
        #[arg(required = false, long = "subject-organization", env)]
        subject_organization: Option<String>,

        /// Certificate subject country. Defaults to 'NA'.
        #[arg(required = false, long = "subject-country", env)]
        subject_country: Option<String>,
    },

    /// Create gateway certificate and key files usable in a Trust0 environment.
    GatewayPkiCreator {
        /// Store gateway certificate to <CERT_FILE>. This certificate will be PEM-encoded
        #[arg(required = true, short = 'c', long = "cert-file", env)]
        cert_file: String,

        /// Store gateway private key to <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
        /// Note - For ECDSA keys, NIST curves 'P-256' and 'P-384' are supported
        /// Note - For EdDSA keys, 'Ed25519' is supported
        #[arg(required = true, short = 'k', long = "key-file", env)]
        key_file: String,

        /// root CA certificate from <KEY_FILE>. This will be a PKCS#8 PEM-encoded certificate.
        #[arg(required = true, long = "rootca-cert-file", env)]
        rootca_cert_file: String,

        /// root CA private key from <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key.
        #[arg(required = true, long = "rootca-key-file", env)]
        rootca_key_file: String,

        /// Private key algorithm
        #[arg(required = true, short = 'a', long = "key-algorithm", env)]
        key_algorithm: KeyAlgorithm,

        /// Serial number, to uniquely identify certificate, up to 20 (hex character 0-F) octets
        #[arg(required = false, short = 's', long = "serial-number", value_parser=crate::config::AppConfig::parse_serial_number, env)]
        serial_number: Option<std::vec::Vec<u8>>,

        /// Certificate validity end time (RFC3339 format, for example '2021-01-02T03:04:05Z')
        #[arg(required=true, long="validity-not-after", value_parser=crate::config::AppConfig::parse_offset_date_time, env)]
        validity_not_after: OffsetDateTime,

        /// Certificate validity start time (RFC3339 format, for example '2021-01-02T03:04:05Z'). Defaults to yesterday.
        #[arg(required=false, long="validity-not-before", value_parser=crate::config::AppConfig::parse_offset_date_time, env)]
        validity_not_before: Option<OffsetDateTime>,

        /// Certificate subject common-name
        #[arg(required = true, long = "subject-common-name", env)]
        subject_common_name: String,

        /// Certificate subject organization. Defaults to 'NA'.
        #[arg(required = false, long = "subject-organization", env)]
        subject_organization: Option<String>,

        /// Certificate subject country. Defaults to 'NA'.
        #[arg(required = false, long = "subject-country", env)]
        subject_country: Option<String>,

        /// Certificate subject alternative name DNS value(s). Provided value is a comma-separated list of host names.
        #[arg(required = false, long = "san-dns-names", env, value_delimiter = ',')]
        san_dns_names: Option<Vec<String>>,
    },

    /// Create client certificate and key files usable in a Trust0 environment.
    ClientPkiCreator {
        /// Store root CA certificate to <CERT_FILE>. This certificate will be PEM-encoded
        #[arg(required = true, short = 'c', long = "cert-file", env)]
        cert_file: String,

        /// Store root CA private key to <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
        /// Note - For ECDSA keys, NIST curves 'P-256' and 'P-384' are supported
        /// Note - For EdDSA keys, 'Ed25519' is supported
        #[arg(
            required = true,
            short = 'k',
            long = "key-file",
            env,
            verbatim_doc_comment
        )]
        key_file: String,

        /// root CA certificate from <KEY_FILE>. This will be a PKCS#8 PEM-encoded certificate.
        #[arg(required = true, long = "rootca-cert-file", env)]
        rootca_cert_file: String,

        /// root CA private key from <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key.
        #[arg(required = true, long = "rootca-key-file", env)]
        rootca_key_file: String,

        /// Private key algorithm
        #[arg(required = true, short = 'a', long = "key-algorithm", env)]
        key_algorithm: KeyAlgorithm,

        /// Serial number, to uniquely identify certificate, up to 20 (hex character 0-F) octets
        #[arg(required = false, short = 's', long = "serial-number", value_parser=crate::config::AppConfig::parse_serial_number, env)]
        serial_number: Option<std::vec::Vec<u8>>,

        /// Certificate validity end time (RFC3339 format, for example '2021-01-02T03:04:05Z')
        #[arg(required=true, long="validity-not-after", value_parser=crate::config::AppConfig::parse_offset_date_time, env)]
        validity_not_after: OffsetDateTime,

        /// Certificate validity start time (RFC3339 format, for example '2021-01-02T03:04:05Z'). Defaults to yesterday.
        #[arg(required=false, long="validity-not-before", value_parser=crate::config::AppConfig::parse_offset_date_time, env)]
        validity_not_before: Option<OffsetDateTime>,

        /// Certificate subject common-name
        #[arg(required = true, long = "subject-common-name", env)]
        subject_common_name: String,

        /// Certificate subject organization. Defaults to 'NA'.
        #[arg(required = false, long = "subject-organization", env)]
        subject_organization: Option<String>,

        /// Certificate subject country. Defaults to 'NA'.
        #[arg(required = false, long = "subject-country", env)]
        subject_country: Option<String>,

        /// The Trust0 user account ID value
        #[arg(required = true, long = "auth-user-id", env)]
        auth_user_id: u64,

        /// The machine architecture/platform for the device using the client certificate
        #[arg(required = true, long = "auth-platform", env)]
        auth_platform: String,
    },
}

/// Application configuration object
pub struct AppConfig {
    /// The [`AppConfigArgs`] object created by the Clap parser
    pub args: AppConfigArgs,
}

impl AppConfig {
    /// AppConfig constructor
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the newly constructed [`AppConfig`] object.
    ///
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

    /// Parse value producing OffsetDateTime. (RFC3339 format)
    ///
    /// # Arguments
    ///
    /// * `datetime_rfc3339` - RFC3339-compliant date time string
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`OffsetDateTime`] for given string
    ///
    fn parse_offset_date_time(datetime_rfc3339: &str) -> Result<OffsetDateTime, AppError> {
        OffsetDateTime::parse(datetime_rfc3339, &Rfc3339).map_err(|err| {
            AppError::General(format!(
                "Error parsing datetime: val={}, err={:?}",
                datetime_rfc3339, &err
            ))
        })
    }

    /// Parse encoded serial number (<=20 hex-encoded chars) producing byte vector.
    ///
    /// # Arguments
    ///
    /// * `encoded_serial_num` - hex-encoded string
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the unencoded byte vector
    ///
    fn parse_serial_number(encoded_serial_num: &str) -> Result<Vec<u8>, AppError> {
        let serial_number = hex::decode(encoded_serial_num).map_err(|err| {
            AppError::General(format!(
                "Error parsing hex-encoded serial number: val={}, err={:?}",
                encoded_serial_num, &err
            ))
        })?;
        if serial_number.len() > ca::SERIAL_NUMBER_MAX_OCTETS {
            return Err(AppError::General(format!(
                "Serial number may not exceed 20 octets: val={}",
                encoded_serial_num
            )));
        }
        Ok(serial_number)
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use std::path::PathBuf;
    use time::macros::datetime;
    use trust0_common::testutils::XDG_ROOT_DIR_PATHPARTS;

    // utils
    // =====

    pub fn setup_new_file_path(basename: &str) -> String {
        let xdg_root_dir: PathBuf = XDG_ROOT_DIR_PATHPARTS.iter().collect();
        xdg_root_dir
            .join("pki-manager")
            .join(basename)
            .to_str()
            .unwrap()
            .to_string()
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
    fn appcfg_new_when_no_command_supplied() {
        let expected_cert_file = setup_new_file_path("rootca.crt.pem");
        let expected_key_file = setup_new_file_path("rootca.key.pem");

        let result = AppConfigArgs::try_parse_from([
            "test",
            "--cert-file",
            &expected_cert_file,
            "--key-file",
            &expected_key_file,
            "--key-algorithm",
            "ecdsa-p256",
            "--validity-not-after",
            "2025-01-01T00:00:00Z",
            "--validity-not-before",
            "2024-01-01T00:00:00Z",
            "--subject-common-name",
            "name1",
            "--subject-organization",
            "org1",
            "--subject-country",
            "country1",
        ]);

        if result.is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn appcfg_new_when_rootca_pki_creator_and_all_supplied() {
        let expected_cert_file = setup_new_file_path("rootca.crt.pem");
        let expected_key_file = setup_new_file_path("rootca.key.pem");

        let result = AppConfigArgs::try_parse_from([
            "test",
            "root-ca-pki-creator",
            "--cert-file",
            &expected_cert_file,
            "--key-file",
            &expected_key_file,
            "--key-algorithm",
            "ecdsa-p256",
            "--serial-number",
            "00a1ff47",
            "--validity-not-after",
            "2025-01-01T00:00:00Z",
            "--validity-not-before",
            "2024-01-01T00:00:00Z",
            "--subject-common-name",
            "name1",
            "--subject-organization",
            "org1",
            "--subject-country",
            "country1",
        ]);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config_args = result.unwrap();

        match &config_args.command {
            Command::RootCaPkiCreator {
                cert_file,
                key_file,
                key_algorithm,
                serial_number,
                validity_not_after,
                validity_not_before,
                subject_common_name,
                subject_organization,
                subject_country,
            } => {
                assert_eq!(cert_file, &expected_cert_file);
                assert_eq!(key_file, &expected_key_file);
                assert_eq!(key_algorithm, &KeyAlgorithm::EcdsaP256);
                assert!(serial_number.is_some());
                assert_eq!(
                    serial_number.as_ref().unwrap(),
                    &vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]
                );
                assert_eq!(validity_not_after, &datetime!(2025-01-01 0:00 UTC));
                assert!(validity_not_before.is_some());
                assert_eq!(
                    validity_not_before.as_ref().unwrap(),
                    &datetime!(2024-01-01 0:00 UTC)
                );
                assert_eq!(subject_common_name, "name1");
                assert!(subject_organization.is_some());
                assert_eq!(subject_organization.as_ref().unwrap(), "org1");
                assert!(subject_country.is_some());
                assert_eq!(subject_country.as_ref().unwrap(), "country1");
            }

            _ => panic!("Invalid sub-command parsed: cmd={:?}", &config_args.command),
        }
    }

    #[test]
    fn appcfg_new_when_gateway_pki_creator_and_all_supplied() {
        let expected_cert_file = setup_new_file_path("gateway.crt.pem");
        let expected_key_file = setup_new_file_path("gateway.key.pem");
        let expected_rootca_cert_file = setup_new_file_path("rootca.crt.pem");
        let expected_rootca_key_file = setup_new_file_path("rootca.key.pem");

        let result = AppConfigArgs::try_parse_from([
            "test",
            "gateway-pki-creator",
            "--cert-file",
            &expected_cert_file,
            "--key-file",
            &expected_key_file,
            "--rootca-cert-file",
            &expected_rootca_cert_file,
            "--rootca-key-file",
            &expected_rootca_key_file,
            "--key-algorithm",
            "ecdsa-p256",
            "--serial-number",
            "00a1ff47",
            "--validity-not-after",
            "2025-01-01T00:00:00Z",
            "--validity-not-before",
            "2024-01-01T00:00:00Z",
            "--subject-common-name",
            "name1",
            "--subject-organization",
            "org1",
            "--subject-country",
            "country1",
            "--san-dns-names",
            "host1.com,host2.com",
        ]);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config_args = result.unwrap();

        match &config_args.command {
            Command::GatewayPkiCreator {
                cert_file,
                key_file,
                rootca_cert_file,
                rootca_key_file,
                key_algorithm,
                serial_number,
                validity_not_after,
                validity_not_before,
                subject_common_name,
                subject_organization,
                subject_country,
                san_dns_names,
            } => {
                assert_eq!(cert_file, &expected_cert_file);
                assert_eq!(key_file, &expected_key_file);
                assert_eq!(rootca_key_file, &expected_rootca_key_file);
                assert_eq!(rootca_cert_file, &expected_rootca_cert_file);
                assert_eq!(key_algorithm, &KeyAlgorithm::EcdsaP256);
                assert!(serial_number.is_some());
                assert_eq!(
                    serial_number.as_ref().unwrap(),
                    &vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]
                );
                assert_eq!(validity_not_after, &datetime!(2025-01-01 0:00 UTC));
                assert!(validity_not_before.is_some());
                assert_eq!(
                    validity_not_before.as_ref().unwrap(),
                    &datetime!(2024-01-01 0:00 UTC)
                );
                assert_eq!(subject_common_name, "name1");
                assert!(subject_organization.is_some());
                assert_eq!(subject_organization.as_ref().unwrap(), "org1");
                assert!(subject_country.is_some());
                assert_eq!(subject_country.as_ref().unwrap(), "country1");
                assert!(san_dns_names.is_some());
                assert_eq!(
                    san_dns_names.as_ref().unwrap(),
                    &vec!["host1.com".to_string(), "host2.com".to_string()]
                );
            }

            _ => panic!("Invalid sub-command parsed: cmd={:?}", &config_args.command),
        }
    }

    #[test]
    fn appcfg_new_when_client_pki_creator_and_all_supplied() {
        let expected_cert_file = setup_new_file_path("client.crt.pem");
        let expected_key_file = setup_new_file_path("client.key.pem");
        let expected_rootca_cert_file = setup_new_file_path("rootca.crt.pem");
        let expected_rootca_key_file = setup_new_file_path("rootca.key.pem");

        let result = AppConfigArgs::try_parse_from([
            "test",
            "client-pki-creator",
            "--cert-file",
            &expected_cert_file,
            "--key-file",
            &expected_key_file,
            "--rootca-cert-file",
            &expected_rootca_cert_file,
            "--rootca-key-file",
            &expected_rootca_key_file,
            "--key-algorithm",
            "ecdsa-p256",
            "--serial-number",
            "00a1ff47",
            "--validity-not-after",
            "2025-01-01T00:00:00Z",
            "--validity-not-before",
            "2024-01-01T00:00:00Z",
            "--subject-common-name",
            "name1",
            "--subject-organization",
            "org1",
            "--subject-country",
            "country1",
            "--auth-user-id",
            "100",
            "--auth-platform",
            "Linux",
        ]);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let config_args = result.unwrap();

        match &config_args.command {
            Command::ClientPkiCreator {
                cert_file,
                key_file,
                rootca_cert_file,
                rootca_key_file,
                key_algorithm,
                serial_number,
                validity_not_after,
                validity_not_before,
                subject_common_name,
                subject_organization,
                subject_country,
                auth_user_id,
                auth_platform,
            } => {
                assert_eq!(cert_file, &expected_cert_file);
                assert_eq!(key_file, &expected_key_file);
                assert_eq!(rootca_key_file, &expected_rootca_key_file);
                assert_eq!(rootca_cert_file, &expected_rootca_cert_file);
                assert_eq!(key_algorithm, &KeyAlgorithm::EcdsaP256);
                assert!(serial_number.is_some());
                assert_eq!(
                    serial_number.as_ref().unwrap(),
                    &vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]
                );
                assert_eq!(validity_not_after, &datetime!(2025-01-01 0:00 UTC));
                assert!(validity_not_before.is_some());
                assert_eq!(
                    validity_not_before.as_ref().unwrap(),
                    &datetime!(2024-01-01 0:00 UTC)
                );
                assert_eq!(subject_common_name, "name1");
                assert!(subject_organization.is_some());
                assert_eq!(subject_organization.as_ref().unwrap(), "org1");
                assert!(subject_country.is_some());
                assert_eq!(subject_country.as_ref().unwrap(), "country1");
                assert_eq!(auth_user_id, &100);
                assert_eq!(auth_platform, "Linux");
            }

            _ => panic!("Invalid sub-command parsed: cmd={:?}", &config_args.command),
        }
    }

    #[test]
    fn appcfg_parse_offset_date_time_when_valid_rfc3339() {
        let result = AppConfig::parse_offset_date_time("2025-01-01T00:00:00Z");

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(result.unwrap(), datetime!(2025-01-01 0:00 UTC));
    }

    #[test]
    fn appcfg_parse_offset_date_time_when_invalid_rfc3339() {
        let result = AppConfig::parse_offset_date_time("202501-01T00:00:00Z");

        if let Ok(datetime) = result {
            panic!("Unexpected successful result: val={:?}", &datetime);
        }
    }

    #[test]
    fn appcfg_parse_serial_number_when_valid() {
        let result = AppConfig::parse_serial_number("00a1ff47");

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(result.unwrap(), vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]);
    }

    #[test]
    fn appcfg_parse_serial_number_when_invalid_length() {
        let result = AppConfig::parse_serial_number("0001030405060708090a0b0c0d0e0f101112131415");

        if let Ok(serial_num) = result {
            panic!("Unexpected successful result: val={:?}", &serial_num);
        }
    }

    #[test]
    fn appcfg_parse_serial_number_when_invalid_encoding() {
        let result = AppConfig::parse_serial_number("invalid");

        if let Ok(serial_num) = result {
            panic!("Unexpected successful result: val={:?}", &serial_num);
        }
    }
}
