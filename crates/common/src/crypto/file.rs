use std::io::{BufReader, Read};
use std::ops::DerefMut;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};

use anyhow::Result;
use pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

use crate::error::AppError;
use crate::file;

/// Verify validity of certificates for the given PEM file
pub fn verify_certificates(filepath: &str) -> Result<String, AppError> {
    match load_certificates(filepath.to_string()) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err),
    }
}

/// Load certificates from the given PEM file
pub fn load_certificates(filepath: String) -> Result<Vec<CertificateDer<'static>>, AppError> {
    match fs::File::open(filepath.clone()).map_err(|err| {
        AppError::GenWithMsgAndErr(
            format!("failed to open certificates file: file={}", &filepath),
            Box::new(err),
        )
    }) {
        Ok(cert_file) => {
            let mut reader = BufReader::new(cert_file);
            let certs = rustls_pemfile::certs(&mut reader);
            let certs_result: Result<Vec<CertificateDer<'static>>, io::Error> =
                certs.into_iter().collect();
            match certs_result {
                Ok(certs) => Ok(certs),
                Err(err) => Err(AppError::GenWithMsgAndErr(
                    format!("Failed parsing certificates: file={}", &filepath),
                    Box::new(err),
                )),
            }
        }
        Err(err) => Err(err),
    }
}

/// Verify the validity of the private key in the given PEM file
pub fn verify_private_key_file(filepath: &str) -> Result<String, AppError> {
    match load_private_key(filepath.to_string()) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err),
    }
}

/// Load the private key from the given PEM file
pub fn load_private_key(filepath: String) -> Result<PrivateKeyDer<'static>, AppError> {
    match fs::File::open(filepath.clone()).map_err(|err| {
        AppError::IoWithMsg(
            format!("failed to open private key file: file={}", &filepath),
            err,
        )
    }) {
        Ok(key_file) => {
            let mut reader = BufReader::new(key_file);
            match rustls_pemfile::private_key(&mut reader) {
                Ok(key_option) => match key_option {
                    Some(key) => Ok(key),
                    None => Err(AppError::General(format!(
                        "No private key found: file={}",
                        &filepath
                    ))),
                },
                Err(err) => Err(AppError::General(format!(
                    "Invalid key file: file={}, err={:?}",
                    &filepath, &err
                ))),
            }
        }
        Err(err) => Err(err),
    }
}

/// Verify the validity certificate revocation list (CRL) entries from the given file
pub fn verify_crl_list(filepath: &str) -> Result<String, AppError> {
    match load_crl_list(filepath) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err),
    }
}

/// Load the certificate revocation list (CRL) entries from the given file
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

/// Represents a certificate revocation list (CRL) file.
/// Exposes the ability to re-parse entries when file has changed.
pub struct CRLFile {
    path: PathBuf,
    last_mtime: SystemTime,
    crl_list: Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>>,
    reloading: Arc<Mutex<bool>>,
}

impl CRLFile {
    /// CRLFile constructor
    pub fn new(
        filepath_str: &str,
        crl_list: &Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>>,
        reloading: &Arc<Mutex<bool>>,
    ) -> Result<Self, AppError> {
        let filepath = PathBuf::from_str(filepath_str).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Error converting string to file path: file={}",
                    filepath_str
                ),
                Box::new(err),
            )
        })?;
        Ok(CRLFile {
            path: filepath,
            last_mtime: UNIX_EPOCH,
            crl_list: crl_list.clone(),
            reloading: reloading.clone(),
        })
    }

    /// CRL list accessor
    pub fn crl_list(&mut self) -> Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>> {
        self.crl_list.clone()
    }
}

impl file::ReloadableFile for CRLFile {
    fn filepath(&self) -> &PathBuf {
        &self.path
    }

    fn last_file_mtime(&mut self) -> &mut SystemTime {
        &mut self.last_mtime
    }

    fn on_reload_data(&mut self) -> Result<(), AppError> {
        match load_crl_list(self.path.to_str().unwrap()) {
            Ok(list) => {
                *self.crl_list.lock().unwrap().deref_mut() =
                    rustls_pemfile::crls(&mut list.as_slice())
                        .map(|result| {
                            result.map_err(|err| {
                                AppError::GenWithMsgAndErr(
                                    format!("Error reading CRL entries: file={:?}", &self.path),
                                    Box::new(err),
                                )
                            })
                        })
                        .collect::<Result<Vec<CertificateRevocationListDer<'static>>, AppError>>(
                        )?;
                Ok(())
            }
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error loading CRL file: file={:?}", &self.path),
                Box::new(err),
            )),
        }
    }

    fn on_critical_error(&mut self, err: &AppError) {
        panic!("Error during CRL reload, exiting: err={:?}", &err);
    }

    fn reloading(&self) -> &Arc<Mutex<bool>> {
        &self.reloading
    }
}

/// CRL unit tests
#[cfg(test)]
mod crl_tests {

    use super::*;
    use crate::file::ReloadableFile;
    use std::path::PathBuf;

    const _CERTFILE_CLIENT0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.crt.pem",
    ];
    const CRLFILE_REVOKED_CERTS_0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "revoked-crts-0.crl.pem",
    ];
    const CRLFILE_REVOKED_CERTS_0_1_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "revoked-crts-0-1.crl.pem",
    ];
    const CRLFILE_INVALID_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "invalid.crl.pem"];
    const CRLFILE_MISSING_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    #[test]
    fn file_verify_crl_list_when_invalid_filepath() {
        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
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
        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let result = verify_crl_list(crl_filepath_str);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn file_verify_crl_list_when_valid_1_entry_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
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
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_1_PATHPARTS.iter().collect();
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
    fn crlfile_new() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        assert_eq!(
            crl_file.path.to_str().unwrap().to_string(),
            crl_filepath_str.to_string()
        );
        assert!(crl_file.crl_list.lock().unwrap().is_empty());
        assert_eq!(*crl_file.reloading.lock().unwrap(), false);
    }

    #[test]
    fn crlfile_accessors() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = file::file_mtime(crl_filepath.as_path()).unwrap();

        let mut crl_file = CRLFile {
            path: crl_filepath.clone(),
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        assert_eq!(*crl_file.filepath(), crl_filepath);
        assert_eq!(*crl_file.last_file_mtime(), last_mtime);
        assert!(*crl_file.reloading().lock().unwrap());
    }

    #[test]
    fn crlfile_crl_list_when_invalid_filepath() {
        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Ok(()) = reload_result {
            panic!("Unexpected successful reload result");
        }

        let crl_list = crl_file.crl_list();

        assert!(crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_crl_list_when_invalid_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Ok(()) = reload_result {
            panic!("Unexpected successful reload result:");
        }

        let crl_list = crl_file.crl_list();

        assert!(crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_crl_list_when_valid_1_entry_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Err(err) = reload_result {
            panic!("Unexpected reload result: err={:?}", &err);
        }

        let crl_list = crl_file.crl_list();

        assert!(!crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_crl_list_when_valid_2_entry_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_1_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Err(err) = reload_result {
            panic!("Unexpected reload result: err={:?}", &err);
        }

        let crl_list = crl_file.crl_list();

        assert!(!crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_process_reload_when_file_unchanged() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap().to_string();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = file::file_mtime(crl_filepath.as_path()).unwrap();
        let saved_last_mtime = last_mtime.clone();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = crl_file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed CRL list reload result: path={}, err={:?}",
                &crl_filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, false);
        assert_eq!(crl_file.last_mtime, saved_last_mtime);
        assert!(crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_process_reload_when_file_changed() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap().to_string();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = SystemTime::now();
        let saved_last_mtime = last_mtime.clone();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = crl_file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed CRL list reload result: path={}, err={:?}",
                &crl_filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, true);
        assert_ne!(crl_file.last_mtime, saved_last_mtime);
        assert!(!crl_list.lock().unwrap().is_empty());
    }

    #[test]
    #[should_panic]
    fn crlfile_process_reload_when_invalid_filepath() {
        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = SystemTime::now();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let _ = crl_file.process_reload();
    }

    #[test]
    fn crlfile_process_reload_when_invalid_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap().to_string();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = SystemTime::now();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = crl_file.process_reload();
        if let Ok(was_reloaded) = result {
            panic!(
                "Unexpected processed CRL list reload result: path={}, reloaded={}",
                &crl_filepath_str, &was_reloaded
            );
        }

        assert!(crl_list.lock().unwrap().is_empty());
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
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

        let result = load_certificates(certs_file.to_str().unwrap().to_string());

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

        let result = load_certificates(certs_file.to_str().unwrap().to_string());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certs = result.unwrap();

        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn file_load_certificates_when_invalid_filepath() {
        let certs_file: PathBuf = MISSING_FILE.iter().collect();

        let result = load_certificates(certs_file.to_str().unwrap().to_string());

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

        let result = load_private_key(key_file.to_str().unwrap().to_string());

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

        let result = load_private_key(key_file.to_str().unwrap().to_string());

        if let Ok(key) = result {
            panic!("Unexpected successful result: key={:?}", &key);
        }
    }

    #[test]
    fn file_load_private_keys_when_invalid_filepath() {
        let key_file: PathBuf = MISSING_FILE.iter().collect();

        let result = load_private_key(key_file.to_str().unwrap().to_string());

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
}
