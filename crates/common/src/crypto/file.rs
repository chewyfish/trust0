use std::{fs, io, thread};
use std::io::{BufReader, Read};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::AppError;
use crate::logging::{error, info};
use crate::{file, target};

const CRLFILE_RECHECK_DELAY_MSECS: Duration = Duration::from_millis(30_000);

/// Verify validity of certificates for the given PEM file
pub fn verify_certificates(filepath: &str) -> Result<String, AppError> {
    match load_certificates(filepath.to_string()) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err)
    }
}

/// Load certificates from the given PEM file
pub fn load_certificates(filepath: String) -> Result<Vec<CertificateDer<'static>>, AppError> {

    match fs::File::open(filepath.clone()).or_else(
        |err| Err(AppError::GenWithMsgAndErr(format!("failed to open certificates file: file={}", &filepath), Box::new(err)))) {

        Ok(cert_file) => {
            let mut reader = BufReader::new(cert_file);
            let certs = rustls_pemfile::certs(&mut reader);
            let certs_result: Result<Vec<CertificateDer<'static>>, io::Error> = certs.into_iter().collect();
            match certs_result {
                Ok(certs) => Ok(certs),
                Err(err) => Err(AppError::GenWithMsgAndErr(format!("Failed parsing certificates: file={}", &filepath), Box::new(err)))
            }
        }
        Err(err) => Err(err.into())
    }
}

/// Verify the validity of the (PKCS8) key in the given PEM file
pub fn verify_private_key_file(filepath: &str) -> Result<String, AppError> {
    match load_private_key(filepath.to_string()) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err)
    }
}

/// Load the (PKCS8) key from the given PEM file
pub fn load_private_key(filepath: String) -> Result<PrivateKeyDer<'static>, AppError> {

    match fs::File::open(filepath.clone()).or_else(
        |err| Err(AppError::IoWithMsg(format!("failed to open private key file: file={}", &filepath), err))) {

        Ok(key_file) => {
            let mut reader = BufReader::new(key_file);
            let mut keys: Vec<Result<PrivatePkcs8KeyDer<'static>, io::Error>> = rustls_pemfile::pkcs8_private_keys(&mut reader).collect();

            return match keys.len() {
                0 => Err(AppError::General(format!("No PKCS8-encoded private key: file={}", &filepath))),
                1 => {
                    match keys.remove(0) {
                        Ok(pkcs8_key) => Ok(pkcs8_key.into()),
                        Err(err) => Err(AppError::General(format!("Invalid PKCS8 key: file={}, err={:?}", &filepath, &err)))
                    }
                },
                _ => Err(AppError::General(format!("More than one PKCS8-encoded private key: file={}", &filepath)))
            }
        },

        Err(err) => Err(err)
    }
}

/// Verify the validity certificate revocation list (CRL) entries from the given file
pub fn verify_crl_list(filepath: &str) -> Result<String, AppError> {
    match load_crl_list(filepath) {
        Ok(_) => Ok(filepath.to_string()),
        Err(err) => Err(err)
    }
}

/// Load the certificate revocation list (CRL) entries from the given file
pub fn load_crl_list(filepath: &str) -> Result<Vec<u8>, AppError> {

    match fs::File::open(filepath).or_else(
        |err| Err(AppError::IoWithMsg(format!("failed to open CRL file: file={}", filepath), err))) {
        Ok(mut crl_file) => {
            let mut crl = Vec::new();
            if let Err(crl_err) = crl_file.read_to_end(&mut crl) {
                Err(AppError::IoWithMsg(format!("failed parsing CRL file: file={:?}", filepath), crl_err))
            } else {
                Ok(crl)
            }
        },

        Err(err) => Err(err)
    }
}

/// Error handler function
pub type ErrorHandlerFn = Box<dyn Fn(&AppError) + Send + 'static>;

/// Represents a certificate revocation list (CRL) file.
/// Exposes the ability to re-parse entries when file has changed.
pub struct CRLFile {
    path: String,
    crl_list: Arc<Mutex<Option<CertificateRevocationListDer<'static>>>>,
    reloading: Arc<Mutex<bool>>
}

impl CRLFile {

    /// CRLFile constructor
    pub fn new(filepath: &str) -> Self {
        CRLFile {
            path: filepath.to_string(),
            crl_list: Arc::new(Mutex::new(None)),
            reloading: Arc::new(Mutex::new(false))
        }
    }

    /// file path accessor
    pub fn filepath(&self) -> &str {
        &self.path
    }

    /// CRL list accessor (if not present, attempt to load from file)
    pub fn crl_list(&mut self) -> Result<CertificateRevocationListDer<'static>, AppError> {

        if let Some(crl_list) = self.crl_list.lock().unwrap().deref() {
            return Ok(crl_list.clone());
        }

        let crl_list_bytes = load_crl_list(&self.path)?;
        let crl_list = CertificateRevocationListDer::from(crl_list_bytes);
        self.crl_list = Arc::new(Mutex::new(Some(crl_list.clone())));
        Ok(crl_list)
    }

    /// Spawn a thread to handle re-loading entries if file changes.
    /// If recheck delay is not supplied, a default of 30s will be used.
    /// A function closure may be passed in to handle critical errors.
    pub fn spawn_list_reloader(&self,
                               recheck_delay: Option<Duration>,
                               on_critical_err_fn: Option<ErrorHandlerFn>) {

        let crlfile_pathbuf = PathBuf::from(self.path.as_str());
        let crl_list = self.crl_list.clone();
        let is_reloading = self.reloading.clone();
        let recheck_delay = recheck_delay.unwrap_or(CRLFILE_RECHECK_DELAY_MSECS);

        info(&target!(), &format!("Starting CRL reloader: file={:?}", &crlfile_pathbuf));

        thread::spawn(move || {

            let mut last_mtime: SystemTime = SystemTime::UNIX_EPOCH;
            *is_reloading.lock().unwrap() = true;

            while *is_reloading.lock().unwrap() {

                match Self::process_list_reload(&mut last_mtime, &crlfile_pathbuf, &crl_list, &on_critical_err_fn) {
                    Ok(reloaded) => if reloaded { info(&target!(), "CRL file changed, new list loaded") },
                    Err(err) => error(&target!(), &format!("{:?}", err))
                }

                thread::sleep(recheck_delay);
            }

            info(&target!(), &format!("Stopped CRL reloader: file={:?}", &crlfile_pathbuf));
        });
    }

    /// Reload list if file has changed. Returns true if file was reloaded
    fn process_list_reload(last_mtime: &mut SystemTime,
                           crlfile_pathbuf: &PathBuf,
                           crl_list: &Arc<Mutex<Option<CertificateRevocationListDer<'static>>>>,
                           on_critical_err_fn: &Option<ErrorHandlerFn>)
        -> Result<bool, AppError> {

        // Check if file has changed
        match file::file_mtime(crlfile_pathbuf.as_path()) {
            Ok(mtime) => {
                if *last_mtime == mtime { return Ok(false); }
                last_mtime.clone_from(&mtime);
            }
            Err(err) => {
                if on_critical_err_fn.is_some() {
                    on_critical_err_fn.as_ref().unwrap()(&err);
                }
                return Err(err);
            }
        }

        // Parse/reload CRL list
        match load_crl_list(crlfile_pathbuf.to_str().unwrap()) {
            Ok(list) => {
                let _ = crl_list.lock().unwrap().deref_mut().replace(CertificateRevocationListDer::from(list));
                Ok(true)
            }
            Err(err) => {
                Err(AppError::GenWithMsgAndErr(format!("Error loading CRL file: file={:?}", crlfile_pathbuf), Box::new(err)))
            }
        }
    }

    /// Stop file reloading thread
    pub fn stop_reloading(&mut self) {
        *self.reloading.lock().unwrap() = false;
    }
}

/// Unit tests
#[cfg(test)]
mod crl_tests {
    use std::path::PathBuf;
    use super::*;

    const _CERTFILE_CLIENT0_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "client0.local.crt.pem"];
    const CRLFILE_REVOKED_CERTS_0_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "revoked-crts-0.crl.pem"];
    const CRLFILE_REVOKED_CERTS_0_1_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "revoked-crts-0-1.crl.pem"];
    const CRLFILE_INVALID_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "invalid.crl.pem"];
    const CRLFILE_MISSING_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    #[test]
    fn crlfile_new() {

        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let crl_file = CRLFile::new(crl_filepath_str);

        assert_eq!(crl_file.path, crl_filepath_str.to_string());
        assert!(crl_file.crl_list.lock().unwrap().is_none());
        assert_eq!(*crl_file.reloading.lock().unwrap(), false);
    }

    #[test]
    fn crlfile_crl_list_when_invalid_filepath() {

        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let mut crl_file = CRLFile::new(crl_filepath_str);

        let result = crl_file.crl_list();

        if let Ok(crl_list) = result {
            panic!("Unexpected result: path={}, list_bytes_len={}", &crl_filepath_str, &crl_list.len());
        }

        assert!(crl_file.crl_list.lock().unwrap().is_none());
    }

    #[ignore]
    #[test]
    fn crlfile_crl_list_when_invalid_crlfile() {

        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let mut crl_file = CRLFile::new(crl_filepath_str);

        let result = crl_file.crl_list();

        if let Err(err) = result {
            panic!("Unexpected loaded CRL list result: path={}, err={:?}", &crl_filepath_str, &err);
        }

        if let Ok(crl_list) = result {
            panic!("Unexpected parsed CRL list result: path={}, list={:?}", &crl_filepath_str, &crl_list);
        }

        assert!(crl_file.crl_list.lock().unwrap().is_some());
    }

    #[test]
    fn crlfile_crl_list_when_valid_1_entry_crlfile() {

        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let mut crl_file = CRLFile::new(crl_filepath_str);

        let result = crl_file.crl_list();

        if let Err(err) = result {
            panic!("Unexpected loaded CRL list result: path={}, err={:?}", &crl_filepath_str, &err);
        }

        assert!(crl_file.crl_list.lock().unwrap().is_some());
    }

    #[test]
    fn crlfile_crl_list_when_valid_2_entry_crlfile() {

        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_1_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();

        let mut crl_file = CRLFile::new(crl_filepath_str);

        let result = crl_file.crl_list();

        if let Err(err) = result {
            panic!("Unexpected loaded CRL list result: path={}, err={:?}", &crl_filepath_str, &err);
        }

        assert!(crl_file.crl_list.lock().unwrap().is_some());
    }

    #[test]
    fn crlfile_process_list_reload_when_file_unchanged() {

        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(None));
        let mut last_mtime = file::file_mtime(crl_filepath.as_path()).unwrap();
        let saved_last_mtime = last_mtime.clone();
        let invoked_error_fn = Arc::new(Mutex::new(false));
        let invoked_error_fn_copy = invoked_error_fn.clone();
        let on_critical_error_fn: Option<ErrorHandlerFn> = Some(Box::new(move |_err: &AppError| {
            *invoked_error_fn_copy.lock().unwrap() = true;
        }));

        let result = CRLFile::process_list_reload(&mut last_mtime, &crl_filepath, &crl_list, &on_critical_error_fn);

        if let Err(err) = result {
            panic!("Unexpected processed CRL list reload result: path={}, err={:?}", &crl_filepath_str, &err);
        }

        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, false);
        assert_eq!(last_mtime, saved_last_mtime);
        assert!(crl_list.lock().unwrap().is_none());
        assert_eq!(*invoked_error_fn.lock().unwrap(), false);
    }

    #[test]
    fn crlfile_process_list_reload_when_file_changed() {

        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(None));
        let mut last_mtime = SystemTime::now();
        let saved_last_mtime = last_mtime.clone();
        let invoked_error_fn = Arc::new(Mutex::new(false));
        let invoked_error_fn_copy = invoked_error_fn.clone();
        let on_critical_error_fn: Option<ErrorHandlerFn> = Some(Box::new(move |_err: &AppError| {
            *invoked_error_fn_copy.lock().unwrap() = true;
        }));

        let result = CRLFile::process_list_reload(&mut last_mtime, &crl_filepath, &crl_list, &on_critical_error_fn);

        if let Err(err) = result {
            panic!("Unexpected processed CRL list reload result: path={}, err={:?}", &crl_filepath_str, &err);
        }

        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, true);
        assert_ne!(last_mtime, saved_last_mtime);
        assert!(crl_list.lock().unwrap().is_some());
        assert_eq!(*invoked_error_fn.lock().unwrap(), false);
    }

    #[test]
    fn crlfile_process_list_reload_when_invalid_filepath() {

        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(None));
        let mut last_mtime = SystemTime::now();
        let invoked_error_fn = Arc::new(Mutex::new(false));
        let invoked_error_fn_copy = invoked_error_fn.clone();
        let on_critical_error_fn: Option<ErrorHandlerFn> = Some(Box::new(move |_err: &AppError| {
            *invoked_error_fn_copy.lock().unwrap() = true;
        }));

        let result = CRLFile::process_list_reload(&mut last_mtime, &crl_filepath, &crl_list, &on_critical_error_fn);

        if let Ok(was_reloaded) = result {
            panic!("Unexpected processed CRL list reload result: path={}, reloaded={}", &crl_filepath_str, &was_reloaded);
        }

        assert!(crl_list.lock().unwrap().is_none());
        assert_eq!(*invoked_error_fn.lock().unwrap(), true);
    }

    #[ignore]
    #[test]
    fn crlfile_process_list_reload_when_invalid_crlfile() {

        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(None));
        let mut last_mtime = SystemTime::now();
        let invoked_error_fn = Arc::new(Mutex::new(false));
        let invoked_error_fn_copy = invoked_error_fn.clone();
        let on_critical_error_fn: Option<ErrorHandlerFn> = Some(Box::new(move |_err: &AppError| {
            *invoked_error_fn_copy.lock().unwrap() = true;
        }));

        let result = CRLFile::process_list_reload(&mut last_mtime, &crl_filepath, &crl_list, &on_critical_error_fn);

        if let Ok(was_reloaded) = result {
            panic!("Unexpected processed CRL list reload result: path={}, reloaded={}", &crl_filepath_str, &was_reloaded);
        }

        assert!(crl_list.lock().unwrap().is_none());
        assert_eq!(*invoked_error_fn.lock().unwrap(), false);
    }
}
