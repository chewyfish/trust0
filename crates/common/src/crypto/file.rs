use std::fs;
use std::io::{BufReader, Read};

use anyhow::Result;
use pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use crate::error::AppError;

/// Verify validity of certificates for the given PEM file
///
/// # Arguments
///
/// * `filepath` - Certificate file pathspec
///
/// # Returns
///
/// A [`Result`] containing the same filepath, if it is a valid certificate file.
///
pub fn verify_certificates(filepath: &str) -> Result<String, AppError> {
    match load_certificates(filepath) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err),
    }
}

/// Load certificates from the given PEM file
///
/// # Arguments
///
/// * `filepath` - Certificate file pathspec
///
/// # Returns
///
/// A [`Result`] containing the certificates in the file, if it is a valid certificate file
///
pub fn load_certificates(filepath: &str) -> Result<Vec<CertificateDer<'static>>, AppError> {
    let certs_result = CertificateDer::pem_file_iter(filepath);
    match certs_result {
        Ok(certs_results) => {
            let certs = certs_results
                .map(|result| {
                    result.map_err(|err| {
                        AppError::General(format!(
                            "Error reading certificate entries: file={:?}, err={:?}",
                            &filepath, &err
                        ))
                    })
                })
                .collect::<anyhow::Result<Vec<CertificateDer<'static>>, AppError>>()?;
            Ok(certs)
        }
        Err(err) => Err(AppError::General(format!(
            "Failed parsing certificate(s): file={}, err={:?}",
            filepath, &err
        ))),
    }
}

/// Verify the validity of the private key in the given PEM file
///
/// # Arguments
///
/// * `filepath` - Private key file pathspec
///
/// # Returns
///
/// A [`Result`] containing the same filepath, if it is a valid private key file.
///
pub fn verify_private_key_file(filepath: &str) -> Result<String, AppError> {
    match load_private_key(filepath) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err),
    }
}

/// Load the private key from the given PEM file
///
/// # Arguments
///
/// * `filepath` - Private key file pathspec
///
/// # Returns
///
/// A [`Result`] containing the private keys in the file, if it is a valid private key file
///
pub fn load_private_key(filepath: &str) -> Result<PrivateKeyDer<'static>, AppError> {
    match fs::File::open(filepath).map_err(|err| {
        AppError::IoWithMsg(
            format!("failed to open private key file: file={}", &filepath),
            err,
        )
    }) {
        Ok(key_file) => {
            let mut reader = BufReader::new(key_file);
            PrivateKeyDer::from_pem_reader(&mut reader).map_err(|err| {
                AppError::General(format!(
                    "Invalid key file: file={}, err={:?}",
                    &filepath, &err
                ))
            })
        }
        Err(err) => Err(err),
    }
}

/// Verify the validity certificate revocation list (CRL) entries from the given file
///
/// # Arguments
///
/// * `filepath` - CRL file pathspec
///
/// # Returns
///
/// A [`Result`] containing the same filepath, if it is a valid CRL file.
///
pub fn verify_crl_list(filepath: &str) -> Result<String, AppError> {
    match load_crl_list(filepath) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err),
    }
}

/// Load the certificate revocation list (CRL) entries from the given file
///
/// # Arguments
///
/// * `filepath` - CRL file pathspec
///
/// # Returns
///
/// A [`Result`] containing the file content (as bytes), if it is a valid CRL file
///
pub fn load_crl_list(filepath: &str) -> Result<Vec<u8>, AppError> {
    match fs::File::open(filepath).map_err(|err| {
        AppError::IoWithMsg(format!("failed to open CRL file: file={}", filepath), err)
    }) {
        Ok(mut crl_file) => {
            let mut crl = Vec::new();
            if let Err(crl_err) = crl_file.read_to_end(&mut crl) {
                Err(AppError::IoWithMsg(
                    format!("failed parsing CRL file: file={:?}", filepath),
                    crl_err,
                ))
            } else {
                Ok(crl)
            }
        }

        Err(err) => Err(err),
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::crl;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::path::PathBuf;
    use x509_parser::nom::AsBytes;

    const MISSING_FILE: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "MISSING"];
    const INVALID_PKI_FILE: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "Makefile"];
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

    fn calculate_hash<T: Hash + ?Sized>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn file_load_certificates_when_valid_certfile() {
        let certs_file: PathBuf = CERTFILE_CLIENT0_PATHPARTS.iter().collect();

        let result = load_certificates(certs_file.to_str().as_ref().unwrap());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certs = result.unwrap();

        assert_eq!(certs.len(), 1);
        assert!(certs.get(0).is_some());
        assert_eq!(
            calculate_hash(certs.get(0).unwrap().as_bytes()),
            4742559486257069929
        );
    }

    #[test]
    fn file_load_certificates_when_invalid_certfile() {
        let certs_file: PathBuf = INVALID_PKI_FILE.iter().collect();

        let result = load_certificates(certs_file.to_str().as_ref().unwrap());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certs = result.unwrap();

        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn file_load_certificates_when_invalid_filepath() {
        let certs_file: PathBuf = MISSING_FILE.iter().collect();

        let result = load_certificates(certs_file.to_str().as_ref().unwrap());

        if let Ok(certs) = result {
            panic!("Unexpected successful result: certs={:?}", &certs);
        }
    }

    #[test]
    fn file_verify_certificates_when_valid_certfile() {
        let certs_file: PathBuf = CERTFILE_CLIENT0_PATHPARTS.iter().collect();
        let certs_file_str = certs_file.to_str().unwrap();

        let result = verify_certificates(certs_file_str);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(result.unwrap(), certs_file_str);
    }

    #[test]
    fn file_verify_certificates_when_invalid_certfile() {
        let certs_file: PathBuf = INVALID_PKI_FILE.iter().collect();
        let certs_file_str = certs_file.to_str().unwrap();

        let result = verify_certificates(certs_file_str);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(result.unwrap(), certs_file_str);
    }

    #[test]
    fn file_verify_certificates_when_invalid_filepath() {
        let certs_file: PathBuf = MISSING_FILE.iter().collect();

        let result = verify_certificates(certs_file.to_str().unwrap());

        if let Ok(certs) = result {
            panic!("Unexpected successful result: certs={:?}", &certs);
        }
    }

    #[test]
    fn file_load_private_keys_when_valid_keyfile() {
        let key_file: PathBuf = KEYFILE_CLIENT0_PATHPARTS.iter().collect();

        let result = load_private_key(key_file.to_str().as_ref().unwrap());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(
            calculate_hash(result.unwrap().secret_der()),
            6990430383764372935
        );
    }

    #[test]
    fn file_load_private_keys_when_invalid_keyfile() {
        let key_file: PathBuf = INVALID_PKI_FILE.iter().collect();

        let result = load_private_key(key_file.to_str().as_ref().unwrap());

        if let Ok(key) = result {
            panic!("Unexpected successful result: key={:?}", &key);
        }
    }

    #[test]
    fn file_load_private_keys_when_invalid_filepath() {
        let key_file: PathBuf = MISSING_FILE.iter().collect();

        let result = load_private_key(key_file.to_str().as_ref().unwrap());

        if let Ok(key) = result {
            panic!("Unexpected successful result: key={:?}", &key);
        }
    }

    #[test]
    fn file_verify_private_keys_when_valid_keyfile() {
        let key_file: PathBuf = KEYFILE_CLIENT0_PATHPARTS.iter().collect();
        let key_file_str = key_file.to_str().unwrap();

        let result = verify_private_key_file(key_file_str);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(result.unwrap(), key_file_str);
    }

    #[test]
    fn file_verify_private_keys_when_invalid_keyfile() {
        let key_file: PathBuf = INVALID_PKI_FILE.iter().collect();
        let key_file_str = key_file.to_str().unwrap();

        let result = verify_private_key_file(key_file_str);

        if let Ok(key_file) = result {
            panic!("Unexpected successful result: file={:?}", &key_file);
        }
    }

    #[test]
    fn file_verify_private_keys_when_invalid_filepath() {
        let key_file: PathBuf = MISSING_FILE.iter().collect();
        let key_file_str = key_file.to_str().unwrap();

        let result = verify_private_key_file(key_file_str);

        if let Ok(key_file) = result {
            panic!("Unexpected successful result: file={:?}", &key_file);
        }
    }

    #[test]
    fn file_verify_crl_list_when_invalid_filepath() {
        let crl_filepath: PathBuf = crl::tests::CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let result = verify_crl_list(crl_filepath_str);

        if let Ok(result_crl_filepath_str) = &result {
            panic!(
                "Unexpected successful result: path={}",
                result_crl_filepath_str
            );
        }
    }

    #[test]
    fn file_verify_crl_list_when_invalid_crlfile() {
        let crl_filepath: PathBuf = crl::tests::CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let result = verify_crl_list(crl_filepath_str);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn file_verify_crl_list_when_valid_1_entry_crlfile() {
        let crl_filepath: PathBuf = crl::tests::CRLFILE_REVOKED_CERTS_0_PATHPARTS
            .iter()
            .collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let result = verify_crl_list(crl_filepath_str);

        if let Err(err) = result {
            panic!(
                "Unexpected result: path={}, err={:?}",
                &crl_filepath_str, &err
            );
        }

        assert_eq!(result.unwrap().as_str(), crl_filepath_str);
    }

    #[test]
    fn file_verify_crl_list_when_valid_2_entry_crlfile() {
        let crl_filepath: PathBuf = crl::tests::CRLFILE_REVOKED_CERTS_0_1_PATHPARTS
            .iter()
            .collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let result = verify_crl_list(crl_filepath_str);

        if let Err(err) = result {
            panic!(
                "Unexpected result: path={}, err={:?}",
                &crl_filepath_str, &err
            );
        }

        assert_eq!(result.unwrap().as_str(), crl_filepath_str);
    }
}
