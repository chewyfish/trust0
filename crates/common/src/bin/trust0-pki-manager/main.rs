mod config;
use std::path::Path;
use std::{fs, process};

use anyhow::Result;
use time::{Duration, OffsetDateTime};
use trust0_common::crypto::ca::{Certificate, KeyAlgorithm};
use trust0_common::error::AppError;
use trust0_common::file;

use crate::config::{AppConfig, Command};

/// Run main process
///
/// # Arguments
///
/// * `app_config` - Application configuration object
///
/// # Returns
///
/// A [`Result`] indicating the success/failure of the processing operation.
///
fn process_runner(app_config: &AppConfig) -> Result<(), AppError> {
    match app_config.args.command {
        Command::RootCaPkiCreator { .. } => process_rootca_pki_creator(app_config),
        Command::GatewayPkiCreator { .. } => process_gateway_pki_creator(app_config),
        Command::ClientPkiCreator { .. } => process_client_pki_creator(app_config),
    }
}

/// Trust0 root CA PKI creator
///
/// # Arguments
///
/// * `app_config` - Application configuration object
///
/// # Returns
///
/// A [`Result`] indicating the success/failure of the processing operation.
///
fn process_rootca_pki_creator(app_config: &AppConfig) -> Result<(), AppError> {
    match &app_config.args.command {
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
            // Create certificate object
            let mut builder = Certificate::root_ca_certificate_builder();
            builder
                .key_algorithm(&(*key_algorithm).into())
                .validity_not_after(validity_not_after)
                .validity_not_before(
                    &validity_not_before.unwrap_or(
                        OffsetDateTime::now_utc()
                            .checked_sub(Duration::days(1))
                            .unwrap(),
                    ),
                )
                .dn_common_name(subject_common_name.as_str());
            if serial_number.is_some() {
                builder.serial_number(serial_number.as_ref().unwrap());
            }
            if subject_organization.is_some() {
                builder.dn_organization(subject_organization.as_ref().unwrap().as_str());
            }
            if subject_country.is_some() {
                builder.dn_country(subject_country.as_ref().unwrap().as_str());
            }
            let certificate = builder.build()?;

            // Persist certificate and private key files
            create_certificate_pem_file(&certificate, &None, cert_file.as_str())?;
            create_private_key_pem_file(&certificate, key_file.as_str())
        }

        _ => unimplemented!(),
    }
}

/// Trust0 gateway PKI creator
///
/// # Arguments
///
/// * `app_config` - Application configuration object
///
/// # Returns
///
/// A [`Result`] indicating the success/failure of the processing operation.
///
fn process_gateway_pki_creator(app_config: &AppConfig) -> Result<(), AppError> {
    match &app_config.args.command {
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
            let key_algorithm: KeyAlgorithm = (*key_algorithm).into();

            // Create certificate object
            let mut builder = Certificate::gateway_certificate_builder();
            builder
                .key_algorithm(&key_algorithm)
                .validity_not_after(validity_not_after)
                .validity_not_before(
                    &validity_not_before.unwrap_or(
                        OffsetDateTime::now_utc()
                            .checked_sub(Duration::days(1))
                            .unwrap(),
                    ),
                )
                .dn_common_name(subject_common_name.as_str());
            if serial_number.is_some() {
                builder.serial_number(serial_number.as_ref().unwrap());
            }
            if subject_organization.is_some() {
                builder.dn_organization(subject_organization.as_ref().unwrap().as_str());
            }
            if subject_country.is_some() {
                builder.dn_country(subject_country.as_ref().unwrap().as_str());
            }
            if san_dns_names.is_some() {
                builder.san_dns_names(san_dns_names.as_ref().unwrap());
            }
            let certificate = builder.build()?;

            // Persist certificate and private key files
            let rootca_certificate = load_existing_rootca_certificate(
                rootca_cert_file,
                rootca_key_file,
                &key_algorithm,
            )?;

            create_certificate_pem_file(
                &certificate,
                &Some(rootca_certificate),
                cert_file.as_str(),
            )?;
            create_private_key_pem_file(&certificate, key_file.as_str())
        }

        _ => unimplemented!(),
    }
}

/// Trust0 client PKI creator
///
/// # Arguments
///
/// * `app_config` - Application configuration object
///
/// # Returns
///
/// A [`Result`] indicating the success/failure of the processing operation.
///
fn process_client_pki_creator(app_config: &AppConfig) -> Result<(), AppError> {
    match &app_config.args.command {
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
            let key_algorithm: KeyAlgorithm = (*key_algorithm).into();

            // Create certificate object
            let mut builder = Certificate::client_certificate_builder();
            builder
                .key_algorithm(&key_algorithm)
                .validity_not_after(validity_not_after)
                .validity_not_before(
                    &validity_not_before.unwrap_or(
                        OffsetDateTime::now_utc()
                            .checked_sub(Duration::days(1))
                            .unwrap(),
                    ),
                )
                .dn_common_name(subject_common_name.as_str())
                .san_uri_user_id(*auth_user_id)
                .san_uri_platform(auth_platform.as_str());
            if serial_number.is_some() {
                builder.serial_number(serial_number.as_ref().unwrap());
            }
            if subject_organization.is_some() {
                builder.dn_organization(subject_organization.as_ref().unwrap().as_str());
            }
            if subject_country.is_some() {
                builder.dn_country(subject_country.as_ref().unwrap().as_str());
            }
            let certificate = builder.build()?;

            // Persist certificate and private key files
            let rootca_certificate = load_existing_rootca_certificate(
                rootca_cert_file,
                rootca_key_file,
                &key_algorithm,
            )?;

            create_certificate_pem_file(
                &certificate,
                &Some(rootca_certificate),
                cert_file.as_str(),
            )?;
            create_private_key_pem_file(&certificate, key_file.as_str())
        }

        _ => unimplemented!(),
    }
}

/// Create root CA [`Certificate`] based on existing root CA certificate/key pem files and corresponding key algorithm
///
/// # Arguments
///
/// * `rootca_cert_file` - Root CA certificate file path
/// * `rootca_key_file` - Root CA key pait file path
/// * `key_algorithm` - Private key algorithm corresponding to stored key
///
/// # Returns
///
/// A [`Result`] containing a newly constructured [`Certificate`] based on existing key and algorithm.
///
fn load_existing_rootca_certificate(
    rootca_cert_file: &str,
    rootca_key_file: &str,
    key_algorithm: &KeyAlgorithm,
) -> Result<Certificate, AppError> {
    let rootca_key_pem = file::load_text_data(rootca_key_file)?;
    let rootca_cert_pem = file::load_text_data(rootca_cert_file)?;
    Certificate::root_ca_certificate_builder()
        .key_algorithm(key_algorithm)
        .key_pair_pem(&rootca_key_pem)
        .certificate_pem(&rootca_cert_pem)
        .build()
}

/// Create certificate PEM file
///
/// # Arguments
///
/// * `certificate` - [`Certificate`] to serialize
/// * `signer_certificate` - Optional [`Certificate`]  to use to sign certificate
/// * `file` - Pathspec for PEM file
///
/// # Returns
///
/// A [`Result`] indicating success/failure of the create operation.
///
fn create_certificate_pem_file(
    certificate: &Certificate,
    signer_certificate: &Option<Certificate>,
    file: &str,
) -> Result<(), AppError> {
    create_parent_directories(file)?;
    fs::write(file, certificate.serialize_certificate(signer_certificate)?).map_err(|err| {
        AppError::GenWithMsgAndErr(
            format!("Error writing certificate file: file={}", file),
            Box::new(err),
        )
    })
}

/// Create private key PEM file
///
/// # Arguments
///
/// * `certificate` - Private key from [`Certificate`] to serialize
/// * `file` - Pathspec for PEM file
///
/// # Returns
///
/// A [`Result`] indicating success/failure of the create operation.
///
fn create_private_key_pem_file(certificate: &Certificate, file: &str) -> Result<(), AppError> {
    create_parent_directories(file)?;
    fs::write(file, certificate.serialize_private_key()).map_err(|err| {
        AppError::GenWithMsgAndErr(
            format!("Error writing certificate file: file={}", file),
            Box::new(err),
        )
    })
}

/// Create (if necessary) all parent directories for given file
///
/// # Arguments
///
/// * `file` - Pathspec to file (whose parent directories need to exist)
///
/// # Returns
///
/// A [`Result`] indicating success/failure of the create operation.
///
fn create_parent_directories(file: &str) -> Result<(), AppError> {
    fs::create_dir_all(Path::new(file).parent().unwrap()).map_err(|err| {
        AppError::IoWithMsg(
            format!("Error creating parent directories: file={:?}", file),
            err,
        )
    })
}

/// Main execution function
///
pub fn main() {
    let app_config = AppConfig::new().unwrap();
    match process_runner(&app_config) {
        Ok(()) => {
            process::exit(0);
        }
        Err(err) => {
            eprintln!("{:?}", err);
            process::exit(1);
        }
    }
}

/// Unit tests
#[cfg(test)]
mod test {
    use super::*;
    use crate::config::tests::setup_new_file_path;
    use crate::config::AppConfigArgs;
    use crate::config::Command::{ClientPkiCreator, GatewayPkiCreator, RootCaPkiCreator};
    use std::path::PathBuf;
    use time::macros::datetime;
    use trust0_common::crypto::file::{verify_certificates, verify_private_key_file};

    const CERTFILE_ROOTCAT_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "ca-generated-rootca-ecdsa256.crt.pem",
    ];

    const KEYFILE_ROOTCAT_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "ca-generated-rootca-ecdsa256.key.pem",
    ];

    // tests
    // =====

    #[test]
    fn main_process_runner_when_rootca_pki_creator_and_all_valid() {
        let expected_cert_file = setup_new_file_path("rootca.crt.pem");
        let expected_key_file = setup_new_file_path("rootca.key.pem");

        let app_config = AppConfig {
            args: AppConfigArgs {
                command: RootCaPkiCreator {
                    cert_file: expected_cert_file.clone(),
                    key_file: expected_key_file.clone(),
                    key_algorithm: config::KeyAlgorithm::EcdsaP256,
                    serial_number: Some(vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]),
                    validity_not_after: datetime!(2025-01-01 0:00 UTC),
                    validity_not_before: None,
                    subject_common_name: "name1".to_string(),
                    subject_organization: None,
                    subject_country: None,
                },
            },
        };

        let result = process_runner(&app_config);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let cert_verify_result = verify_certificates(expected_cert_file.as_str());

        if let Err(err) = cert_verify_result {
            panic!("Unexpected certificate verification: err={:?}", &err);
        }

        let key_verify_result = verify_private_key_file(expected_key_file.as_str());

        if let Err(err) = key_verify_result {
            panic!("Unexpected private key verification: err={:?}", &err);
        }
    }

    #[test]
    fn main_process_runner_when_gateway_pki_creator_and_all_valid() {
        let rootca_cert_filepath: PathBuf = CERTFILE_ROOTCAT_PATHPARTS.iter().collect();
        let rootca_cert_filepath_str = rootca_cert_filepath.to_str().unwrap();
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCAT_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let expected_cert_file = setup_new_file_path("gateway.crt.pem");
        let expected_key_file = setup_new_file_path("gateway.key.pem");

        let app_config = AppConfig {
            args: AppConfigArgs {
                command: GatewayPkiCreator {
                    cert_file: expected_cert_file.clone(),
                    key_file: expected_key_file.clone(),
                    rootca_cert_file: rootca_cert_filepath_str.to_string(),
                    rootca_key_file: rootca_key_filepath_str.to_string(),
                    key_algorithm: config::KeyAlgorithm::EcdsaP256,
                    serial_number: Some(vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]),
                    validity_not_after: datetime!(2025-01-01 0:00 UTC),
                    validity_not_before: None,
                    subject_common_name: "name1".to_string(),
                    subject_organization: None,
                    subject_country: None,
                    san_dns_names: Some(vec!["host1.com".to_string()]),
                },
            },
        };

        let result = process_runner(&app_config);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let cert_verify_result = verify_certificates(expected_cert_file.as_str());

        if let Err(err) = cert_verify_result {
            panic!("Unexpected certificate verification: err={:?}", &err);
        }

        let key_verify_result = verify_private_key_file(expected_key_file.as_str());

        if let Err(err) = key_verify_result {
            panic!("Unexpected private key verification: err={:?}", &err);
        }
    }

    #[test]
    fn main_process_runner_when_client_pki_creator_and_all_valid() {
        let rootca_cert_filepath: PathBuf = CERTFILE_ROOTCAT_PATHPARTS.iter().collect();
        let rootca_cert_filepath_str = rootca_cert_filepath.to_str().unwrap();
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCAT_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let expected_cert_file = setup_new_file_path("client.crt.pem");
        let expected_key_file = setup_new_file_path("client.key.pem");

        let app_config = AppConfig {
            args: AppConfigArgs {
                command: ClientPkiCreator {
                    cert_file: expected_cert_file.clone(),
                    key_file: expected_key_file.clone(),
                    rootca_cert_file: rootca_cert_filepath_str.to_string(),
                    rootca_key_file: rootca_key_filepath_str.to_string(),
                    key_algorithm: config::KeyAlgorithm::EcdsaP256,
                    serial_number: Some(vec![0x00u8, 0xa1u8, 0xffu8, 0x47u8]),
                    validity_not_after: datetime!(2025-01-01 0:00 UTC),
                    validity_not_before: None,
                    subject_common_name: "name1".to_string(),
                    subject_organization: None,
                    subject_country: None,
                    auth_user_id: 100,
                    auth_platform: "Linux".to_string(),
                },
            },
        };

        let result = process_runner(&app_config);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let cert_verify_result = verify_certificates(expected_cert_file.as_str());

        if let Err(err) = cert_verify_result {
            panic!("Unexpected certificate verification: err={:?}", &err);
        }

        let key_verify_result = verify_private_key_file(expected_key_file.as_str());

        if let Err(err) = key_verify_result {
            panic!("Unexpected private key verification: err={:?}", &err);
        }
    }
}
