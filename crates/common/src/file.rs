use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

use anyhow::Result;

use crate::error::AppError;
use crate::logging::{error, info};
use crate::target;

const RELOADABLEFILE_RECHECK_DELAY_MSECS: Duration = Duration::from_millis(30_000);

/// Return file modification time
pub fn file_mtime(filepath: &Path) -> Result<SystemTime, AppError> {
    match filepath.metadata() {
        Ok(meta) => match meta.modified() {
            Ok(mtime) => Ok(mtime),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error acquiring file metadata mtime: file={:?}", filepath),
                Box::new(err),
            )),
        },

        Err(err) => Err(AppError::GenWithMsgAndErr(
            format!("Error acquiring file metadata: file={:?}", filepath),
            Box::new(err),
        )),
    }
}

/// Load data as text string from given file
pub fn load_text_data(filepath_str: &str) -> Result<String, AppError> {
    fs::read_to_string(filepath_str).map_err(|err| {
        AppError::GenWithMsgAndErr(
            format!("Failed to read file: path={}", filepath_str),
            Box::new(err),
        )
    })
}

/// Represents a file resource that is reloadable upon file change events.
pub trait ReloadableFile: Send {
    /// file path accessor
    fn filepath(&self) -> &PathBuf;

    /// Stores the last file modified time seen
    fn last_file_mtime(&mut self) -> &mut SystemTime;

    /// reload data callback function
    fn on_reload_data(&mut self) -> Result<(), AppError>;

    /// critical-level error callback function
    fn on_critical_error(&mut self, err: &AppError);

    /// reloading loop processing state
    fn reloading(&self) -> &Arc<Mutex<bool>>;

    /// Trigger file reload, if file has changed. Returns true if file was reloaded
    fn process_reload(&mut self) -> Result<bool, AppError> {
        // Check if file has changed
        let filepath = self.filepath().clone();
        let last_file_mtime = self.last_file_mtime();
        match file_mtime(filepath.as_path()) {
            Ok(file_mtime) => {
                if *last_file_mtime == file_mtime {
                    return Ok(false);
                }
                last_file_mtime.clone_from(&file_mtime);
            }
            Err(err) => {
                self.on_critical_error(&err);
                return Err(err);
            }
        }

        // Process new file contents
        self.on_reload_data()?;

        Ok(true)
    }

    /// Spawn a thread to handle re-loading if file changes.
    /// If recheck delay is not supplied, a default of 30s will be used.
    fn spawn_reloader(
        mut reloadable_file: impl ReloadableFile + 'static,
        recheck_delay: Option<Duration>,
    ) where
        Self: Sized,
    {
        info(
            &target!(),
            &format!(
                "Starting file reloader: file={:?}",
                &reloadable_file.filepath()
            ),
        );

        thread::spawn(move || {
            let file_pathbuf = reloadable_file.filepath().to_str().unwrap().to_string();
            let recheck_delay = recheck_delay.unwrap_or(RELOADABLEFILE_RECHECK_DELAY_MSECS);

            let is_reloading = reloadable_file.reloading().clone();

            *is_reloading.lock().unwrap() = true;
            while *is_reloading.lock().unwrap() {
                match reloadable_file.process_reload() {
                    Ok(reloaded) => {
                        if reloaded {
                            info(
                                &target!(),
                                &format!(
                                    "Processed changed file: file={:?}, mtime={:?}",
                                    &file_pathbuf,
                                    reloadable_file.last_file_mtime()
                                ),
                            );
                        }
                    }
                    Err(err) => error(&target!(), &format!("{:?}", err)),
                }

                thread::sleep(recheck_delay);
            }

            info(
                &target!(),
                &format!("Stopped file reloader: file={:?}", &file_pathbuf),
            );
        });
    }
}

/// Represents a reloadable text file
pub struct ReloadableTextFile {
    path: PathBuf,
    last_mtime: SystemTime,
    text_data: Arc<Mutex<String>>,
    reloading: Arc<Mutex<bool>>,
}

impl ReloadableTextFile {
    /// ReloadableTextFile constructor
    pub fn new(
        filepath_str: &str,
        text_data: &Arc<Mutex<String>>,
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
        Ok(ReloadableTextFile {
            path: filepath,
            last_mtime: UNIX_EPOCH,
            text_data: text_data.clone(),
            reloading: reloading.clone(),
        })
    }

    /// Text data accessor
    pub fn text_data(&mut self) -> Arc<Mutex<String>> {
        self.text_data.clone()
    }
}

impl ReloadableFile for ReloadableTextFile {
    fn filepath(&self) -> &PathBuf {
        &self.path
    }

    fn last_file_mtime(&mut self) -> &mut SystemTime {
        &mut self.last_mtime
    }

    fn on_reload_data(&mut self) -> Result<(), AppError> {
        match load_text_data(self.path.to_str().unwrap()) {
            Ok(text_data) => {
                *self.text_data.lock().unwrap().deref_mut() = text_data;
                Ok(())
            }
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error loading file: file={:?}", &self.path),
                Box::new(err),
            )),
        }
    }

    fn on_critical_error(&mut self, err: &AppError) {
        panic!(
            "Error during text file reload, exiting: file={:?}, err={:?}",
            &self.path, &err
        );
    }

    fn reloading(&self) -> &Arc<Mutex<bool>> {
        &self.reloading
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const VALID_FILE: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "client-config.rc"];
    const MISSING_FILE: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    #[test]
    fn file_file_mtime_when_invalid_filepath() {
        let file_pathbuf: PathBuf = MISSING_FILE.iter().collect();

        let result = file_mtime(file_pathbuf.as_path());

        if result.is_ok() {
            panic!(
                "Unexpected result: path={:?}, val={:?}",
                &file_pathbuf, &result
            );
        }
    }

    #[test]
    fn file_file_mtime_when_valid_filepath() {
        let file_pathbuf: PathBuf = VALID_FILE.iter().collect();

        let result = file_mtime(file_pathbuf.as_path());

        if result.is_err() {
            panic!(
                "Unexpected result: path={:?}, val={:?}",
                &file_pathbuf, &result
            );
        }
    }

    #[test]
    fn file_load_text_data_when_invalid_filepath() {
        let file_pathbuf: PathBuf = MISSING_FILE.iter().collect();

        let result = load_text_data(file_pathbuf.to_str().unwrap());

        if result.is_ok() {
            panic!(
                "Unexpected result: path={:?}, val={:?}",
                &file_pathbuf, &result
            );
        }
    }

    #[test]
    fn file_load_text_data_when_valid_filepath() {
        let file_pathbuf: PathBuf = VALID_FILE.iter().collect();

        let result = load_text_data(file_pathbuf.to_str().unwrap());

        if result.is_err() {
            panic!(
                "Unexpected result: path={:?}, val={:?}",
                &file_pathbuf, &result
            );
        }

        assert_eq!(
            result.unwrap().replace(&[' ', '\t', '\r', '\n'], ""),
            "GATEWAY_PORT=8888MAX_FRAG_SIZE=128".to_string()
        );
    }
}

/// ReloadableFile unit tests
#[cfg(test)]
mod reload_tests {
    use super::*;
    use crate::file::ReloadableFile;
    use std::ops::Deref;
    use std::path::PathBuf;

    // constants
    // =========

    const FILE_REVOKED_CERTS_0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "revoked-crts-0.crl.pem",
    ];
    const _FILE_REVOKED_CERTS_0_1_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "revoked-crts-0-1.crl.pem",
    ];
    const FILE_MISSING_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    const FILE_INVALID_CRL_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "invalid.crl.pem"];

    // classes
    // =======

    #[derive(Debug, PartialEq)]
    enum ReloadFileAction {
        None,
        CritErr(String),
        Reload,
    }

    #[derive(Debug)]
    struct ReloadFileImpl {
        path: PathBuf,
        last_mtime: SystemTime,
        action: ReloadFileAction,
        reloading: Arc<Mutex<bool>>,
    }

    impl ReloadableFile for ReloadFileImpl {
        fn filepath(&self) -> &PathBuf {
            &self.path
        }
        fn last_file_mtime(&mut self) -> &mut SystemTime {
            &mut self.last_mtime
        }
        fn on_reload_data(&mut self) -> Result<(), AppError> {
            self.action = ReloadFileAction::Reload;
            Ok(())
        }
        fn on_critical_error(&mut self, err: &AppError) {
            self.action = ReloadFileAction::CritErr(format!("{:?}", err));
        }
        fn reloading(&self) -> &Arc<Mutex<bool>> {
            &self.reloading
        }
    }

    #[test]
    fn reloadfile_accessors() {
        let filepath: PathBuf = FILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let last_mtime = file_mtime(filepath.as_path()).unwrap();

        let mut file = ReloadFileImpl {
            path: filepath.clone(),
            last_mtime: last_mtime.clone(),
            action: ReloadFileAction::None,
            reloading: Arc::new(Mutex::new(true)),
        };

        assert_eq!(*file.filepath(), filepath);
        assert_eq!(*file.last_file_mtime(), last_mtime);
        assert!(*file.reloading().lock().unwrap());

        file.on_reload_data().unwrap();
        assert_eq!(file.action, ReloadFileAction::Reload);

        let error = AppError::WouldBlock;
        file.on_critical_error(&error);
        assert_eq!(
            file.action,
            ReloadFileAction::CritErr("WouldBlock".to_string())
        );
    }

    #[test]
    fn reloadfile_process_reload_when_file_unchanged() {
        let filepath: PathBuf = FILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let filepath_str = filepath.to_str().unwrap().to_string();
        let last_mtime = file_mtime(filepath.as_path()).unwrap();
        let saved_last_mtime = last_mtime.clone();

        let mut file = ReloadFileImpl {
            path: filepath,
            last_mtime,
            action: ReloadFileAction::None,
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed reload result: path={}, err={:?}",
                &filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, false);
        assert_eq!(file.action, ReloadFileAction::None);
        assert_eq!(file.last_mtime, saved_last_mtime);
    }

    #[test]
    fn reloadfile_process_reload_when_file_changed() {
        let filepath: PathBuf = FILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let filepath_str = filepath.to_str().unwrap().to_string();
        let last_mtime = SystemTime::now();
        let saved_last_mtime = last_mtime.clone();

        let mut file = ReloadFileImpl {
            path: filepath,
            last_mtime,
            action: ReloadFileAction::None,
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed reload result: path={}, err={:?}",
                &filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, true);
        assert_eq!(file.action, ReloadFileAction::Reload);
        assert_ne!(file.last_mtime, saved_last_mtime);
    }

    #[test]
    fn reloadfile_process_reload_when_invalid_filepath() {
        let filepath: PathBuf = FILE_MISSING_PATHPARTS.iter().collect();
        let filepath_str = filepath.to_str().unwrap().to_string();
        let last_mtime = SystemTime::now();
        let saved_last_mtime = last_mtime.clone();

        let mut file = ReloadFileImpl {
            path: filepath,
            last_mtime,
            action: ReloadFileAction::None,
            reloading: Arc::new(Mutex::new(true)),
        };

        let _ = file.process_reload();
        let result = file.process_reload();
        if let Ok(reloaded) = result {
            panic!(
                "Unexpected processed reload result: path={}, reload={}",
                &filepath_str, &reloaded
            );
        }

        assert_eq!(file.last_mtime, saved_last_mtime);

        match &file.action {
            ReloadFileAction::CritErr(_) => {}
            _ => panic!("Unexpected action: val={:?}", &file.action),
        }
    }

    #[test]
    fn reloadfile_spawn_reloader_when_valid_file() {
        let filepath: PathBuf = FILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let last_mtime = SystemTime::now();
        let reloading = Arc::new(Mutex::new(false));

        let file = ReloadFileImpl {
            path: filepath,
            last_mtime,
            action: ReloadFileAction::None,
            reloading: reloading.clone(),
        };

        <ReloadFileImpl as ReloadableFile>::spawn_reloader(file, Some(Duration::from_millis(1000)));
        *reloading.lock().unwrap() = false;
    }

    #[test]
    fn reloadfile_spawn_reloader_when_invalid_file() {
        let filepath: PathBuf = FILE_MISSING_PATHPARTS.iter().collect();
        let last_mtime = SystemTime::now();
        let reloading = Arc::new(Mutex::new(false));

        let file = ReloadFileImpl {
            path: filepath,
            last_mtime,
            action: ReloadFileAction::None,
            reloading: reloading.clone(),
        };

        <ReloadFileImpl as ReloadableFile>::spawn_reloader(file, Some(Duration::from_millis(1000)));
        *reloading.lock().unwrap() = false;
    }

    #[test]
    fn reloadtext_new_when_valid_file() {
        let filepath: PathBuf = FILE_INVALID_CRL_PATHPARTS.iter().collect();
        let text_data = Arc::new(Mutex::new("txt1".to_string()));

        let text_file_result = ReloadableTextFile::new(
            filepath.to_str().unwrap(),
            &text_data,
            &Arc::new(Mutex::new(true)),
        );

        if let Err(err) = text_file_result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let mut text_file = text_file_result.unwrap();

        assert_eq!(*text_file.filepath(), filepath);
        assert_eq!(
            *text_file.text_data().lock().unwrap().deref(),
            "txt1".to_string()
        );
        assert!(*text_file.reloading().lock().unwrap());
    }

    #[test]
    fn reloadtext_accessors() {
        let filepath: PathBuf = FILE_INVALID_CRL_PATHPARTS.iter().collect();
        let text_data = Arc::new(Mutex::new(String::new()));
        let last_mtime = file_mtime(filepath.as_path()).unwrap();

        let mut text_file = ReloadableTextFile {
            path: filepath.clone(),
            last_mtime,
            text_data: text_data.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        assert_eq!(*text_file.filepath(), filepath);
        assert_eq!(*text_file.last_file_mtime(), last_mtime);
        assert!(*text_file.reloading().lock().unwrap());
    }

    #[test]
    fn reloadtext_process_reload_when_file_unchanged() {
        let filepath: PathBuf = FILE_INVALID_CRL_PATHPARTS.iter().collect();
        let filepath_str = filepath.to_str().unwrap().to_string();
        let text_data = Arc::new(Mutex::new(String::new()));
        let last_mtime = file_mtime(filepath.as_path()).unwrap();
        let saved_last_mtime = last_mtime.clone();

        let mut text_file = ReloadableTextFile {
            path: filepath.clone(),
            last_mtime,
            text_data: text_data.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = text_file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed text data reload result: path={}, err={:?}",
                &filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, false);
        assert_eq!(text_file.last_mtime, saved_last_mtime);
        assert!(text_data.lock().unwrap().is_empty());
    }

    #[test]
    fn reloadtext_process_reload_when_file_changed() {
        let filepath: PathBuf = FILE_INVALID_CRL_PATHPARTS.iter().collect();
        let filepath_str = filepath.to_str().unwrap().to_string();
        let text_data = Arc::new(Mutex::new(String::new()));
        let last_mtime = SystemTime::now();
        let saved_last_mtime = last_mtime.clone();

        let mut text_file = ReloadableTextFile {
            path: filepath.clone(),
            last_mtime,
            text_data: text_data.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = text_file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed text data reload result: path={}, err={:?}",
                &filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, true);
        assert_ne!(text_file.last_mtime, saved_last_mtime);
        assert!(!text_data.lock().unwrap().is_empty());
        assert_eq!(text_data.lock().unwrap().to_string().replace(&[' ', '\t', '\r', '\n'], ""),
                   "-----BEGINX509CRL-----WRONG1-----ENDX509CRL----------BEGINX509CRL-----WRONG2-----ENDX509CRL-----".to_string());
    }

    #[test]
    #[should_panic]
    fn reloadtext_process_reload_when_invalid_filepath() {
        let filepath: PathBuf = FILE_MISSING_PATHPARTS.iter().collect();
        let text_data = Arc::new(Mutex::new(String::new()));
        let last_mtime = file_mtime(filepath.as_path()).unwrap();

        let mut text_file = ReloadableTextFile {
            path: filepath.clone(),
            last_mtime,
            text_data: text_data.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let _ = text_file.process_reload();
    }

    #[test]
    #[should_panic]
    fn reloadtext_on_critical_error() {
        let filepath: PathBuf = FILE_INVALID_CRL_PATHPARTS.iter().collect();
        let text_data = Arc::new(Mutex::new(String::new()));
        let last_mtime = file_mtime(filepath.as_path()).unwrap();

        let mut text_file = ReloadableTextFile {
            path: filepath.clone(),
            last_mtime,
            text_data: text_data.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let _ = text_file.on_critical_error(&AppError::General("msg1".to_string()));
    }
}
