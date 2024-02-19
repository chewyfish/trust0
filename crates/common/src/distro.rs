use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use crate::error::AppError;
use once_cell::sync::Lazy;

const APP_BASE_FILENAME: &str = "Trust0";

/// Application home directory (for formally installed product)
static APP_HOME_DIR: Lazy<PathBuf> = Lazy::new(AppInstallDir::home_dir);

/// Application config directory (for formally installed product)
static APP_CONFIG_DIR: Lazy<PathBuf> = Lazy::new(AppInstallDir::config_dir);

/// Application transient files directory (for formally installed product)
static APP_TRANSIENT_DIR: Lazy<PathBuf> = Lazy::new(AppInstallDir::transient_dir);

/// Application directory types
#[derive(Clone, Debug, PartialEq)]
pub enum AppInstallDir {
    /// Backup/save files directory
    Backup,
    /// Application binaries/executables directory
    Binary,
    /// Configuration files directory
    Config,
    /// Main application root directory
    Home,
    /// Logs (and other variable/dynamic) files directory
    Logs,
    /// PKI/sensitive files directory
    Pki,
    /// Temporary files directory
    Transient,
}

impl AppInstallDir {
    /// Application root directory
    ///
    /// # Returns
    ///
    /// A [`PathBuf`] to the application parent (containing [`Self::home_dir`]) directory
    ///
    fn parent_dir() -> PathBuf {
        #[cfg(windows)]
        {
            if let Ok(data_dir) = env::var("APPDATA").or_else(|_| env::var("CSIDL_APPDATA")) {
                Path::new(&data_dir).to_path_buf()
            } else {
                panic!("Unable to determine user data directory. Please ensure 'APPDATA' environment variable is provided.");
            }
        }
        #[cfg(unix)]
        {
            if let Ok(home_dir) = env::var("HOME") {
                Path::new(&home_dir).to_path_buf()
            } else {
                panic!("Unable to determine user home directory. Please ensure 'HOME' environment variable is provided.");
            }
        }
    }

    /// Application home directory
    ///
    /// # Returns
    ///
    /// A [`PathBuf`] to the application home directory
    ///
    fn home_dir() -> PathBuf {
        match env::var("XDG_DATA_HOME") {
            Ok(data_dir) => Path::new(&data_dir).join(APP_BASE_FILENAME),
            Err(_) => {
                #[cfg(windows)]
                {
                    Self::parent_dir().join(APP_BASE_FILENAME)
                }
                #[cfg(unix)]
                {
                    Self::parent_dir()
                        .join(".local")
                        .join("share")
                        .join(APP_BASE_FILENAME)
                }
            }
        }
    }

    /// Application configuration directory
    ///
    /// # Returns
    ///
    /// A [`PathBuf`] to the application configuration directory
    ///
    fn config_dir() -> PathBuf {
        match env::var("XDG_CONFIG_HOME") {
            Ok(config_dir) => Path::new(&config_dir).join(APP_BASE_FILENAME),
            Err(_) => {
                #[cfg(windows)]
                {
                    Self::home_dir().join("config")
                }
                #[cfg(unix)]
                {
                    Self::parent_dir().join(".config").join(APP_BASE_FILENAME)
                }
            }
        }
    }

    /// Application transient files directory
    ///
    /// # Returns
    ///
    /// A [`PathBuf`] to the application transient/temporary files directory
    ///
    fn transient_dir() -> PathBuf {
        match env::var("XDG_CACHE_HOME") {
            Ok(cache_dir) => Path::new(&cache_dir).join(APP_BASE_FILENAME),
            Err(_) => {
                #[cfg(windows)]
                {
                    Self::home_dir().join("cache")
                }
                #[cfg(unix)]
                {
                    Self::parent_dir().join(".cache").join(APP_BASE_FILENAME)
                }
            }
        }
    }

    /// Installation directory path
    ///
    /// # Returns
    ///
    /// A [`PathBuf`] corresponding to [`Self`]
    ///
    pub fn pathspec(&self) -> PathBuf {
        match self {
            AppInstallDir::Backup => APP_TRANSIENT_DIR.clone().join("backup"),
            AppInstallDir::Binary => APP_HOME_DIR.clone().join("bin"),
            AppInstallDir::Config => APP_CONFIG_DIR.clone(),
            AppInstallDir::Home => APP_HOME_DIR.clone(),
            AppInstallDir::Logs => APP_TRANSIENT_DIR.clone().join("logs"),
            AppInstallDir::Pki => APP_HOME_DIR.clone().join("pki"),
            AppInstallDir::Transient => APP_TRANSIENT_DIR.clone(),
        }
    }
}

/// Application file types
#[derive(Clone, Debug, PartialEq)]
pub enum AppInstallFile {
    /// CA root certificate file
    CARootCertificate,
    /// Client config file
    ClientConfig,
    /// Client binary executable
    ClientBinary,
    /// Client (auth) certificate file
    ClientCertificate,
    /// Client (auth) private key file
    ClientKey,
    /// Gateway config file
    GatewayConfig,
    /// Gateway binary executable
    GatewayBinary,
    /// Gateway certificate file
    GatewayCertificate,
    /// Gateway private key file
    GatewayKey,
    /// Custom file creator
    Custom(AppInstallDir, PathBuf, u32),
}

impl AppInstallFile {
    /// Install directory accessor
    ///
    /// # Returns
    ///
    /// A [`AppInstallDir`] corresponding to [`Self`].
    ///
    pub fn app_install_dir(&self) -> &AppInstallDir {
        match self {
            AppInstallFile::CARootCertificate => &AppInstallDir::Pki,
            AppInstallFile::ClientConfig => &AppInstallDir::Config,
            AppInstallFile::ClientBinary => &AppInstallDir::Binary,
            AppInstallFile::ClientCertificate => &AppInstallDir::Pki,
            AppInstallFile::ClientKey => &AppInstallDir::Pki,
            AppInstallFile::GatewayConfig => &AppInstallDir::Config,
            AppInstallFile::GatewayBinary => &AppInstallDir::Binary,
            AppInstallFile::GatewayCertificate => &AppInstallDir::Pki,
            AppInstallFile::GatewayKey => &AppInstallDir::Pki,
            AppInstallFile::Custom(dir, _, _) => dir,
        }
    }

    /// File path, relative to the parent [`AppInstallDir`]
    ///
    /// # Returns
    ///
    /// The relative file path corresponding to [`Self`].
    ///
    pub fn relative_path(&self) -> PathBuf {
        match self {
            AppInstallFile::CARootCertificate => "ca-root.cert.pem".into(),
            AppInstallFile::ClientConfig => "trust0-client.conf".into(),
            AppInstallFile::ClientBinary => {
                format!("trust0-client{}", env::consts::EXE_SUFFIX).into()
            }
            AppInstallFile::ClientCertificate => "trust0-client.cert.pem".into(),
            AppInstallFile::ClientKey => "trust0-client.key.pem".into(),
            AppInstallFile::GatewayConfig => "trust0-gateway.conf".into(),
            AppInstallFile::GatewayBinary => {
                format!("trust0-gateway{}", env::consts::EXE_SUFFIX).into()
            }
            AppInstallFile::GatewayCertificate => "trust0-gateway.cert.pem".into(),
            AppInstallFile::GatewayKey => "trust0-gateway.key.pem".into(),
            AppInstallFile::Custom(_, relative_path, _) => relative_path.clone(),
        }
    }

    /// File pathspec
    ///
    /// # Returns
    ///
    /// A [`PathBuf`] corresponding to [`Self`].
    ///
    pub fn pathspec(&self) -> PathBuf {
        self.app_install_dir().pathspec().join(self.relative_path())
    }

    /// File permissions
    ///
    /// # Returns
    ///
    /// The unix permissions bit mask for [`Self`].
    ///
    pub fn permissions(&self) -> u32 {
        match self {
            AppInstallFile::CARootCertificate => 0o600,
            AppInstallFile::ClientConfig => 0o600,
            AppInstallFile::ClientBinary => 0o700,
            AppInstallFile::ClientCertificate => 0o600,
            AppInstallFile::ClientKey => 0o600,
            AppInstallFile::GatewayConfig => 0o600,
            AppInstallFile::GatewayBinary => 0o700,
            AppInstallFile::GatewayCertificate => 0o600,
            AppInstallFile::GatewayKey => 0o600,
            AppInstallFile::Custom(_, _, mode) => *mode,
        }
    }

    /// Create new file
    ///
    /// # Arguments
    ///
    /// * `data` - File contents data byte array
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the corresponding [`File`] object for the successfully created file.
    ///
    pub fn create(&self, data: &[u8]) -> Result<File, AppError> {
        // Create/truncate file
        let mut file = Self::create_impl(self.pathspec().as_path(), self.permissions())?;

        // Write file content
        file.write_all(data).map_err(|err| {
            AppError::IoWithMsg(
                format!("Error writing file data: path={:?}", self.pathspec()),
                err,
            )
        })?;
        file.flush().map_err(|err| {
            AppError::IoWithMsg(
                format!("Error flushing file: path={:?}", self.pathspec()),
                err,
            )
        })?;
        file.rewind().map_err(|err| {
            AppError::IoWithMsg(
                format!("Error rewinding file: path={:?}", self.pathspec()),
                err,
            )
        })?;

        Ok(file)
    }

    /// Create from existing file
    ///
    /// # Arguments
    ///
    /// * `pathspec` - File pathspec to copy contents from
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the corresponding [`File`] object for the successfully created file.
    ///
    pub fn create_from_file(&self, pathspec: &PathBuf) -> Result<File, AppError> {
        self.create(
            fs::read(pathspec)
                .map_err(|err| {
                    AppError::IoWithMsg(
                        format!(
                            "Error reading source file: src-path={:?}, dest-path={:?}",
                            pathspec,
                            &self.pathspec()
                        ),
                        err,
                    )
                })?
                .as_slice(),
        )
    }

    #[cfg(unix)]
    /// Create new (or truncate) file (unix implementation)
    fn create_impl(path: &Path, mode: u32) -> Result<File, AppError> {
        fs::create_dir_all(path.parent().unwrap()).map_err(|err| {
            AppError::IoWithMsg(
                format!("Error creating parent directories: path={:?}", path),
                err,
            )
        })?;
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .map_err(|err| {
                AppError::IoWithMsg(format!("Error creating file: path={:?}", path), err)
            })
    }

    #[cfg(windows)]
    /// Create new (or truncate) file (windows implementation)
    fn create_impl(path: &Path, mode: u32) -> Result<File, AppError> {
        let curr_user_name = windows_acl::helper::current_user().ok_or(AppError::General(
            "Unable to retrieve current username".to_string(),
        ))?;
        let curr_user_sid = windows_acl::helper::name_to_sid(curr_user_name.as_str(), None)
            .map_err(|err_code| {
                AppError::General(format!(
                    "Error forming current user SID: user={}, err-code={}",
                    &curr_user_name, err_code
                ))
            })?;

        fs::create_dir_all(path.parent().unwrap()).map_err(|err| {
            AppError::IoWithMsg(
                format!("Error creating parent directories: path={:?}", path),
                err,
            )
        })?;
        File::create(path).map_err(|err| {
            AppError::IoWithMsg(format!("Error creating file: path={:?}", path), err)
        })?;
        let file = OpenOptions::new()
            .access_mode(
                winapi::um::winnt::GENERIC_READ
                    | winapi::um::winnt::GENERIC_WRITE
                    | winapi::um::winnt::WRITE_DAC,
            )
            .open(path)
            .map_err(|err| {
                AppError::IoWithMsg(
                    format!("Error creating file for DAC writable: path={:?}", path),
                    err,
                )
            })?;

        let mut acl = windows_acl::acl::ACL::from_file_handle(
            file.as_raw_handle() as *mut winapi::ctypes::c_void,
            false,
        )
        .map_err(|err_code| {
            AppError::General(format!(
                "Error creating file ACL: path={:?}, err-code={}",
                &curr_user_name, err_code
            ))
        })?;

        let mut perms: winapi::shared::minwindef::DWORD = winapi::um::winnt::FILE_GENERIC_READ;
        if (mode & 0o600) != 0 || (mode & 0o700) != 0 {
            perms |= winapi::um::winnt::FILE_GENERIC_WRITE;
        }
        if (mode & 0o500) != 0 || (mode & 0o700) != 0 {
            perms |= winapi::um::winnt::FILE_GENERIC_EXECUTE;
        }

        let _ = acl
            .allow(
                curr_user_sid.as_ptr() as winapi::um::winnt::PSID,
                false,
                perms,
            )
            .map_err(|err_code| {
                AppError::General(format!(
                    "Error adding file ACL allow entry: path={:?}, err-code={}",
                    &curr_user_name, err_code
                ))
            })?;

        Ok(file)
    }

    /// Backup to predetermined location, which uses the file's relative path spec rooted under [`AppInstallDir::Backup`].
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a tuple of the corresponding [`File`] object and path for the successfully backed up file.
    /// If no current existing file, then `None` is returned
    ///
    pub fn backup(&self) -> Result<Option<(File, PathBuf)>, AppError> {
        if !self.pathspec().exists() {
            return Ok(None);
        }
        let backup_file_pathspec = format!(
            "{}.{}",
            self.relative_path().to_str().unwrap(),
            Self::backup_file_extension()
        );
        let backup_file = AppInstallFile::Custom(
            AppInstallDir::Backup,
            PathBuf::from(backup_file_pathspec),
            self.permissions(),
        );
        Ok(Some((
            backup_file.create_from_file(&self.pathspec())?,
            backup_file.pathspec(),
        )))
    }

    /// File extension to use in new back file
    ///
    /// # Returns
    ///
    /// A string of the current duration in seconds since the Epoch.
    ///
    #[cfg(not(test))]
    fn backup_file_extension() -> String {
        format!(
            "{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )
    }
    #[cfg(test)]
    fn backup_file_extension() -> String {
        "9876543210".to_string()
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::testutils;
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    const EXISTING_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "invalid.crl.pem"];
    const NONEXISTENT_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    #[cfg(windows)]
    fn acl_entry_exists(
        entries: &Vec<windows_acl::acl::ACLEntry>,
        expected: &windows_acl::acl::ACLEntry,
    ) -> Option<usize> {
        for i in 0..entries.len() {
            let entry = &entries[i];

            if entry.entry_type == expected.entry_type
                && entry.string_sid == expected.string_sid
                && entry.flags == expected.flags
                && entry.mask == expected.mask
            {
                return Some(i);
            }
        }

        None
    }

    #[cfg(unix)]
    #[test]
    #[should_panic]
    fn appinstalldir_parent_dir_when_home_envvar_not_set() {
        env::remove_var("HOME");

        let _ = AppInstallDir::home_dir();
    }

    #[cfg(windows)]
    #[test]
    #[should_panic]
    fn appinstalldir_parent_dir_when_home_envvar_not_set() {
        env::remove_var("APPDATA");
        env::remove_var("CSIDL_APPDATA");

        let _ = AppInstallDir::home_dir();
    }

    #[test]
    fn appinstalldir_verify_app_dirs_when_xdg_is_defined() {
        let expected_data_home_path;
        let expected_config_home_path;
        let expected_cache_home_path;
        let data_home_path;
        let config_home_path;
        let cache_home_path;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            let xdg_root_dir: PathBuf = testutils::XDG_ROOT_DIR_PATHPARTS.iter().collect();
            expected_data_home_path = xdg_root_dir.clone().join("data").join(APP_BASE_FILENAME);
            expected_config_home_path = xdg_root_dir.clone().join("config").join(APP_BASE_FILENAME);
            expected_cache_home_path = xdg_root_dir.clone().join("cache").join(APP_BASE_FILENAME);
            env::set_var("HOME", "home");
            env::set_var("APPDATA", "appdata");
            data_home_path = AppInstallDir::home_dir().clone();
            config_home_path = AppInstallDir::config_dir().clone();
            cache_home_path = AppInstallDir::transient_dir().clone();
        }

        assert_eq!(data_home_path, expected_data_home_path);
        assert_eq!(config_home_path, expected_config_home_path);
        assert_eq!(cache_home_path, expected_cache_home_path);
    }

    #[cfg(unix)]
    #[test]
    fn appinstalldir_verify_app_dirs_when_xdg_is_not_defined() {
        let data_home_path;
        let config_home_path;
        let cache_home_path;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            env::set_var("HOME", "home");
            env::remove_var("XDG_DATA_HOME");
            env::remove_var("XDG_CONFIG_HOME");
            env::remove_var("XDG_CACHE_HOME");
            data_home_path = AppInstallDir::home_dir().clone();
            config_home_path = AppInstallDir::config_dir().clone();
            cache_home_path = AppInstallDir::transient_dir().clone();
        }

        assert_eq!(
            data_home_path,
            Path::new("home")
                .join(".local")
                .join("share")
                .join(APP_BASE_FILENAME)
        );
        assert_eq!(
            config_home_path,
            Path::new("home").join(".config").join(APP_BASE_FILENAME)
        );
        assert_eq!(
            cache_home_path,
            Path::new("home").join(".cache").join(APP_BASE_FILENAME)
        );
    }

    #[cfg(windows)]
    #[test]
    fn appinstalldir_verify_app_dirs_when_xdg_is_not_defined() {
        let data_home_path;
        let config_home_path;
        let cache_home_path;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            env::set_var("APPDATA", "appdata");
            env::remove_var("XDG_DATA_HOME");
            env::remove_var("XDG_CONFIG_HOME");
            env::remove_var("XDG_CACHE_HOME");
            data_home_path = AppInstallDir::home_dir().clone();
            config_home_path = AppInstallDir::config_dir().clone();
            cache_home_path = AppInstallDir::transient_dir().clone();
        }

        assert_eq!(data_home_path, Path::new("appdata").join(APP_BASE_FILENAME));
        assert_eq!(
            config_home_path,
            Path::new("appdata").join(APP_BASE_FILENAME).join("config")
        );
        assert_eq!(
            cache_home_path,
            Path::new("appdata").join(APP_BASE_FILENAME).join("cache")
        );
    }

    #[test]
    fn appinstalldir_pathspec() {
        let expected_data_home_path;
        let expected_config_home_path;
        let expected_cache_home_path;
        let backup_home_path;
        let binary_home_path;
        let config_home_path;
        let home_path;
        let logs_home_path;
        let pki_home_path;
        let transient_home_path;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            let xdg_root_dir: PathBuf = testutils::XDG_ROOT_DIR_PATHPARTS.iter().collect();
            expected_data_home_path = xdg_root_dir.clone().join("data").join(APP_BASE_FILENAME);
            expected_config_home_path = xdg_root_dir.clone().join("config").join(APP_BASE_FILENAME);
            expected_cache_home_path = xdg_root_dir.clone().join("cache").join(APP_BASE_FILENAME);
            backup_home_path = AppInstallDir::Backup.pathspec();
            binary_home_path = AppInstallDir::Binary.pathspec();
            config_home_path = AppInstallDir::Config.pathspec();
            home_path = AppInstallDir::Home.pathspec();
            logs_home_path = AppInstallDir::Logs.pathspec();
            pki_home_path = AppInstallDir::Pki.pathspec();
            transient_home_path = AppInstallDir::Transient.pathspec();
        }

        assert_eq!(
            backup_home_path,
            expected_cache_home_path.clone().join("backup")
        );
        assert_eq!(
            binary_home_path,
            expected_data_home_path.clone().join("bin")
        );
        assert_eq!(config_home_path, expected_config_home_path.clone());
        assert_eq!(home_path, expected_data_home_path.clone());
        assert_eq!(
            logs_home_path,
            expected_cache_home_path.clone().join("logs")
        );
        assert_eq!(pki_home_path, expected_data_home_path.clone().join("pki"));
        assert_eq!(transient_home_path, expected_cache_home_path.clone());
    }

    #[test]
    fn appinstallfile_clone() {
        assert_eq!(
            AppInstallFile::CARootCertificate.clone(),
            AppInstallFile::CARootCertificate
        );
        assert_eq!(
            AppInstallFile::ClientConfig.clone(),
            AppInstallFile::ClientConfig
        );
        assert_eq!(
            AppInstallFile::ClientBinary.clone(),
            AppInstallFile::ClientBinary
        );
        assert_eq!(
            AppInstallFile::ClientCertificate.clone(),
            AppInstallFile::ClientCertificate
        );
        assert_eq!(AppInstallFile::ClientKey.clone(), AppInstallFile::ClientKey);
        assert_eq!(
            AppInstallFile::GatewayConfig.clone(),
            AppInstallFile::GatewayConfig
        );
        assert_eq!(
            AppInstallFile::GatewayBinary.clone(),
            AppInstallFile::GatewayBinary
        );
        assert_eq!(
            AppInstallFile::GatewayCertificate.clone(),
            AppInstallFile::GatewayCertificate
        );
        assert_eq!(
            AppInstallFile::GatewayKey.clone(),
            AppInstallFile::GatewayKey
        );
        assert_eq!(
            AppInstallFile::Custom(AppInstallDir::Pki, "test.txt".into(), 100).clone(),
            AppInstallFile::Custom(AppInstallDir::Pki, "test.txt".into(), 100)
        );
    }

    #[test]
    fn appinstallfile_debug() {
        assert_eq!(
            format!("{:?}", AppInstallFile::CARootCertificate),
            "CARootCertificate".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::ClientConfig),
            "ClientConfig".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::ClientBinary),
            "ClientBinary".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::ClientCertificate),
            "ClientCertificate".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::ClientKey),
            "ClientKey".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::GatewayConfig),
            "GatewayConfig".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::GatewayBinary),
            "GatewayBinary".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::GatewayCertificate),
            "GatewayCertificate".to_string()
        );
        assert_eq!(
            format!("{:?}", AppInstallFile::GatewayKey),
            "GatewayKey".to_string()
        );
        assert_eq!(
            format!(
                "{:?}",
                AppInstallFile::Custom(AppInstallDir::Pki, "test.txt".into(), 100)
            ),
            "Custom(Pki, \"test.txt\", 100)".to_string()
        );
    }

    #[test]
    fn appinstallfile_app_install_dir() {
        assert_eq!(
            AppInstallFile::CARootCertificate.app_install_dir(),
            &AppInstallDir::Pki
        );
        assert_eq!(
            AppInstallFile::ClientConfig.app_install_dir(),
            &AppInstallDir::Config
        );
        assert_eq!(
            AppInstallFile::ClientBinary.app_install_dir(),
            &AppInstallDir::Binary
        );
        assert_eq!(
            AppInstallFile::ClientCertificate.app_install_dir(),
            &AppInstallDir::Pki
        );
        assert_eq!(
            AppInstallFile::ClientKey.app_install_dir(),
            &AppInstallDir::Pki
        );
        assert_eq!(
            AppInstallFile::GatewayConfig.app_install_dir(),
            &AppInstallDir::Config
        );
        assert_eq!(
            AppInstallFile::GatewayBinary.app_install_dir(),
            &AppInstallDir::Binary
        );
        assert_eq!(
            AppInstallFile::GatewayCertificate.app_install_dir(),
            &AppInstallDir::Pki
        );
        assert_eq!(
            AppInstallFile::GatewayKey.app_install_dir(),
            &AppInstallDir::Pki
        );
        assert_eq!(
            AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700)
                .app_install_dir(),
            &AppInstallDir::Home
        );
    }

    #[test]
    fn appinstallfile_relative_path() {
        assert_eq!(
            AppInstallFile::CARootCertificate.relative_path(),
            PathBuf::from("ca-root.cert.pem")
        );
        assert_eq!(
            AppInstallFile::ClientConfig.relative_path(),
            PathBuf::from("trust0-client.conf")
        );
        assert_eq!(
            AppInstallFile::ClientBinary.relative_path(),
            PathBuf::from(format!("trust0-client{}", env::consts::EXE_SUFFIX))
        );
        assert_eq!(
            AppInstallFile::ClientCertificate.relative_path(),
            PathBuf::from("trust0-client.cert.pem")
        );
        assert_eq!(
            AppInstallFile::ClientKey.relative_path(),
            PathBuf::from("trust0-client.key.pem")
        );
        assert_eq!(
            AppInstallFile::GatewayConfig.relative_path(),
            PathBuf::from("trust0-gateway.conf")
        );
        assert_eq!(
            AppInstallFile::GatewayBinary.relative_path(),
            PathBuf::from(format!("trust0-gateway{}", env::consts::EXE_SUFFIX))
        );
        assert_eq!(
            AppInstallFile::GatewayCertificate.relative_path(),
            PathBuf::from("trust0-gateway.cert.pem")
        );
        assert_eq!(
            AppInstallFile::GatewayKey.relative_path(),
            PathBuf::from("trust0-gateway.key.pem")
        );
        assert_eq!(
            AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700)
                .relative_path(),
            PathBuf::from("file123.txt")
        );
    }

    #[test]
    fn appinstallfile_pathspec() {
        let expected_data_home_path;
        let expected_config_home_path;
        let ca_root_file_path;
        let client_config_file_path;
        let client_binary_file_path;
        let client_cert_file_path;
        let client_key_file_path;
        let gateway_config_file_path;
        let gateway_binary_file_path;
        let gateway_cert_file_path;
        let gateway_key_file_path;
        let custom_file_path;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            let xdg_root_dir: PathBuf = testutils::XDG_ROOT_DIR_PATHPARTS.iter().collect();
            expected_data_home_path = xdg_root_dir.clone().join("data").join(APP_BASE_FILENAME);
            expected_config_home_path = xdg_root_dir.clone().join("config").join(APP_BASE_FILENAME);
            ca_root_file_path = AppInstallFile::CARootCertificate.pathspec();
            client_config_file_path = AppInstallFile::ClientConfig.pathspec();
            client_binary_file_path = AppInstallFile::ClientBinary.pathspec();
            client_cert_file_path = AppInstallFile::ClientCertificate.pathspec();
            client_key_file_path = AppInstallFile::ClientKey.pathspec();
            gateway_config_file_path = AppInstallFile::GatewayConfig.pathspec();
            gateway_binary_file_path = AppInstallFile::GatewayBinary.pathspec();
            gateway_cert_file_path = AppInstallFile::GatewayCertificate.pathspec();
            gateway_key_file_path = AppInstallFile::GatewayKey.pathspec();
            custom_file_path =
                AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700).pathspec();
        }

        assert_eq!(
            ca_root_file_path,
            expected_data_home_path
                .clone()
                .join("pki")
                .join("ca-root.cert.pem")
        );
        assert_eq!(
            client_config_file_path,
            expected_config_home_path.clone().join("trust0-client.conf")
        );
        let mut expected_client_binary_file_path = expected_data_home_path
            .clone()
            .join("bin")
            .join("trust0-client");
        expected_client_binary_file_path.set_extension(env::consts::EXE_EXTENSION);
        assert_eq!(client_binary_file_path, expected_client_binary_file_path);
        assert_eq!(
            client_cert_file_path,
            expected_data_home_path
                .clone()
                .join("pki")
                .join("trust0-client.cert.pem")
        );
        assert_eq!(
            client_key_file_path,
            expected_data_home_path
                .clone()
                .join("pki")
                .join("trust0-client.key.pem")
        );
        assert_eq!(
            gateway_config_file_path,
            expected_config_home_path
                .clone()
                .join("trust0-gateway.conf")
        );
        let mut expected_gateway_binary_file_path = expected_data_home_path
            .clone()
            .join("bin")
            .join("trust0-gateway");
        expected_gateway_binary_file_path.set_extension(env::consts::EXE_EXTENSION);
        assert_eq!(gateway_binary_file_path, expected_gateway_binary_file_path);
        assert_eq!(
            gateway_cert_file_path,
            expected_data_home_path
                .clone()
                .join("pki")
                .join("trust0-gateway.cert.pem")
        );
        assert_eq!(
            gateway_key_file_path,
            expected_data_home_path
                .clone()
                .join("pki")
                .join("trust0-gateway.key.pem")
        );
        assert_eq!(
            custom_file_path,
            expected_data_home_path.clone().join("file123.txt")
        );
    }

    #[test]
    fn appinstallfile_permissions() {
        let ca_root_file_perms;
        let client_config_file_perms;
        let client_binary_file_perms;
        let client_cert_file_perms;
        let client_key_file_perms;
        let gateway_config_file_perms;
        let gateway_binary_file_perms;
        let gateway_cert_file_perms;
        let gateway_key_file_perms;
        let custom_file_perms;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            ca_root_file_perms = AppInstallFile::CARootCertificate.permissions();
            client_config_file_perms = AppInstallFile::ClientConfig.permissions();
            client_binary_file_perms = AppInstallFile::ClientBinary.permissions();
            client_cert_file_perms = AppInstallFile::ClientCertificate.permissions();
            client_key_file_perms = AppInstallFile::ClientKey.permissions();
            gateway_config_file_perms = AppInstallFile::GatewayConfig.permissions();
            gateway_binary_file_perms = AppInstallFile::GatewayBinary.permissions();
            gateway_cert_file_perms = AppInstallFile::GatewayCertificate.permissions();
            gateway_key_file_perms = AppInstallFile::GatewayKey.permissions();
            custom_file_perms =
                AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700)
                    .permissions();
        }

        assert_eq!(ca_root_file_perms, 0o600);
        assert_eq!(client_config_file_perms, 0o600);
        assert_eq!(client_binary_file_perms, 0o700);
        assert_eq!(client_cert_file_perms, 0o600);
        assert_eq!(client_key_file_perms, 0o600);
        assert_eq!(gateway_config_file_perms, 0o600);
        assert_eq!(gateway_binary_file_perms, 0o700);
        assert_eq!(gateway_cert_file_perms, 0o600);
        assert_eq!(gateway_key_file_perms, 0o600);
        assert_eq!(custom_file_perms, 0o700);
    }

    #[test]
    fn appinstallfile_create_from_file_when_file_doesnt_exist() {
        let non_existent_file: PathBuf;
        let install_file;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            non_existent_file = NONEXISTENT_FILE_PATHPARTS.iter().collect();
            install_file = AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700);
        }

        if let Ok(path) = install_file.create_from_file(&non_existent_file) {
            panic!("Unexpected successful create result: path={:?}", &path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn appinstallfile_create_from_file_when_file_exists() {
        let existing_file: PathBuf;
        let install_file;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            existing_file = EXISTING_FILE_PATHPARTS.iter().collect();
            install_file = AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700);
        }

        let created_file = install_file.create_from_file(&existing_file);
        if let Err(err) = created_file {
            panic!("Unexpected create result: err={:?}", &err);
        }
        let mut created_file = created_file.unwrap();

        let created_file_meta = created_file.metadata();
        if let Err(err) = created_file_meta {
            panic!("Unexpected file metadata result: err={:?}", &err);
        }
        let created_file_meta = created_file_meta.unwrap();

        let created_file_perms = created_file_meta.permissions().mode() & 0o777;
        assert_eq!(created_file_perms, 0o700);

        let mut file_data = String::new();
        if let Err(err) = created_file.read_to_string(&mut file_data) {
            panic!(
                "Error reading file contents: file={:?}, err={:?}",
                &created_file, &err
            );
        }
        assert_eq!(file_data.replace(&[' ', '\t', '\r', '\n'], ""),
                   "-----BEGINX509CRL-----WRONG1-----ENDX509CRL----------BEGINX509CRL-----WRONG2-----ENDX509CRL-----".to_string());
    }

    #[cfg(windows)]
    #[test]
    fn appinstallfile_create_from_file_when_file_exists() {
        let existing_file: PathBuf;
        let install_file;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            existing_file = EXISTING_FILE_PATHPARTS.iter().collect();
            install_file = AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700);
        }

        let created_file = install_file.create_from_file(&existing_file);
        if let Err(err) = created_file {
            panic!("Unexpected create result: err={:?}", &err);
        }
        let mut created_file = created_file.unwrap();

        let acl_result = windows_acl::acl::ACL::from_file_handle(
            created_file.as_raw_handle() as *mut winapi::ctypes::c_void,
            false,
        );
        if let Err(err_code) = acl_result {
            panic!(
                "Unexpected file acl retrieval result: file={:?}, err_code={}",
                &created_file, err_code
            );
        }
        let acl = acl_result.unwrap();

        let acl_entries = acl.all().unwrap_or(Vec::new());
        assert!(!acl_entries.is_empty());

        let curr_user_name = windows_acl::helper::current_user()
            .ok_or(AppError::General(
                "Unable to retrieve current username".to_string(),
            ))
            .unwrap();
        let curr_user_sid = windows_acl::helper::sid_to_string(
            windows_acl::helper::name_to_sid(&curr_user_name.as_str(), None)
                .unwrap_or(vec![])
                .as_ptr() as winapi::um::winnt::PSID,
        )
        .unwrap_or(String::new());

        let mut expected_acl = windows_acl::acl::ACLEntry::new();
        expected_acl.entry_type = windows_acl::acl::AceType::AccessAllow;
        expected_acl.string_sid = curr_user_sid;
        expected_acl.flags = 0;
        expected_acl.mask = winapi::um::winnt::FILE_GENERIC_READ
            | winapi::um::winnt::FILE_GENERIC_WRITE
            | winapi::um::winnt::FILE_GENERIC_EXECUTE;

        if let None = acl_entry_exists(&acl_entries, &expected_acl) {
            panic!("ACL entry not found: file={:?}", &created_file);
        }

        let mut file_data = String::new();
        if let Err(err) = created_file.read_to_string(&mut file_data) {
            panic!(
                "Error reading file contents: file={:?}, err={:?}",
                &created_file, &err
            );
        }
        assert_eq!(file_data.replace(&[' ', '\t', '\r', '\n'], ""),
                   "-----BEGINX509CRL-----WRONG1-----ENDX509CRL----------BEGINX509CRL-----WRONG2-----ENDX509CRL-----".to_string());
    }

    #[test]
    fn appinstallfile_backup_when_file_doesnt_exist() {
        let install_file = AppInstallFile::GatewayBinary;

        let backed_up_file = install_file.backup();
        if let Err(err) = backed_up_file {
            panic!("Unexpected backup result: err={:?}", &err);
        }

        assert!(backed_up_file.unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn appinstallfile_backup_when_file_exists() {
        let mutex = testutils::TEST_MUTEX.clone();
        let _lock = mutex.lock().unwrap();
        testutils::setup_xdg_vars().unwrap();
        let backup_install_dir = AppInstallDir::Backup;
        let existing_file = EXISTING_FILE_PATHPARTS.iter().collect();
        let install_file = AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700);

        let created_file = install_file.create_from_file(&existing_file);
        if let Err(err) = created_file {
            panic!("Unexpected create result: err={:?}", &err);
        }

        let backed_up_file = install_file.backup();
        if let Err(err) = backed_up_file {
            panic!("Unexpected backup result: err={:?}", &err);
        }

        let backed_up_file = backed_up_file.unwrap();
        assert!(backed_up_file.is_some());
        let (mut backed_up_file, backed_up_file_path) = backed_up_file.unwrap();

        let expected_back_up_file_path =
            backup_install_dir.pathspec().join("file123.txt.9876543210");
        assert_eq!(backed_up_file_path, expected_back_up_file_path);

        let backed_up_file_meta = backed_up_file.metadata();
        if let Err(err) = backed_up_file_meta {
            panic!("Unexpected file metadata result: err={:?}", &err);
        }
        let backed_up_file_meta = backed_up_file_meta.unwrap();

        let backed_up_file_perms = backed_up_file_meta.permissions().mode() & 0o777;
        assert_eq!(backed_up_file_perms, 0o700);

        let mut file_data = String::new();
        if let Err(err) = backed_up_file.read_to_string(&mut file_data) {
            panic!(
                "Error reading file contents: file={:?}, err={:?}",
                &backed_up_file, &err
            );
        }
        assert_eq!(file_data.replace(&[' ', '\t', '\r', '\n'], ""),
                   "-----BEGINX509CRL-----WRONG1-----ENDX509CRL----------BEGINX509CRL-----WRONG2-----ENDX509CRL-----".to_string());
    }

    #[cfg(windows)]
    #[test]
    fn appinstallfile_backup_when_file_exists() {
        let mutex = testutils::TEST_MUTEX.clone();
        let _lock = mutex.lock().unwrap();
        testutils::setup_xdg_vars().unwrap();
        let backup_install_dir = AppInstallDir::Backup;
        let existing_file = EXISTING_FILE_PATHPARTS.iter().collect();
        let install_file = AppInstallFile::Custom(AppInstallDir::Home, "file123.txt".into(), 0o700);

        let created_file = install_file.create_from_file(&existing_file);
        if let Err(err) = created_file {
            panic!("Unexpected create result: err={:?}", &err);
        }

        let backed_up_file = install_file.backup();
        if let Err(err) = backed_up_file {
            panic!("Unexpected backup result: err={:?}", &err);
        }

        let backed_up_file = backed_up_file.unwrap();
        assert!(backed_up_file.is_some());
        let (mut backed_up_file, backed_up_file_path) = backed_up_file.unwrap();

        let expected_back_up_file_path =
            backup_install_dir.pathspec().join("file123.txt.9876543210");
        assert_eq!(backed_up_file_path, expected_back_up_file_path);

        let acl_result = windows_acl::acl::ACL::from_file_handle(
            backed_up_file.as_raw_handle() as *mut winapi::ctypes::c_void,
            false,
        );
        if let Err(err_code) = acl_result {
            panic!(
                "Unexpected file acl retrieval result: file={:?}, err_code={}",
                &backed_up_file, err_code
            );
        }
        let acl = acl_result.unwrap();

        let acl_entries = acl.all().unwrap_or(Vec::new());
        assert!(!acl_entries.is_empty());

        let curr_user_name = windows_acl::helper::current_user()
            .ok_or(AppError::General(
                "Unable to retrieve current username".to_string(),
            ))
            .unwrap();
        let curr_user_sid = windows_acl::helper::sid_to_string(
            windows_acl::helper::name_to_sid(&curr_user_name.as_str(), None)
                .unwrap_or(vec![])
                .as_ptr() as winapi::um::winnt::PSID,
        )
        .unwrap_or(String::new());

        let mut expected_acl = windows_acl::acl::ACLEntry::new();
        expected_acl.entry_type = windows_acl::acl::AceType::AccessAllow;
        expected_acl.string_sid = curr_user_sid;
        expected_acl.flags = 0;
        expected_acl.mask = winapi::um::winnt::FILE_GENERIC_READ
            | winapi::um::winnt::FILE_GENERIC_WRITE
            | winapi::um::winnt::FILE_GENERIC_EXECUTE;

        if let None = acl_entry_exists(&acl_entries, &expected_acl) {
            panic!("ACL entry not found: file={:?}", &backed_up_file);
        }

        let mut file_data = String::new();
        if let Err(err) = backed_up_file.read_to_string(&mut file_data) {
            panic!(
                "Error reading file contents: file={:?}, err={:?}",
                &backed_up_file, &err
            );
        }
        assert_eq!(file_data.replace(&[' ', '\t', '\r', '\n'], ""),
                   "-----BEGINX509CRL-----WRONG1-----ENDX509CRL----------BEGINX509CRL-----WRONG2-----ENDX509CRL-----".to_string());
    }
}
