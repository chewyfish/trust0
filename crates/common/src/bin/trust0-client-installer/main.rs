mod config;

use std::path::Path;
use std::process;

use anyhow::Result;

use crate::config::AppConfig;
use trust0_common::distro::AppInstallFile;
use trust0_common::error::AppError;

/// Run main process
///
/// # Returns
///
/// A [`Result`] indicating the success/failure of the processing operation.
///
fn process_runner() -> Result<(), AppError> {
    // Parse process invocation arguments
    let mut app_config = AppConfig::new()?;

    // Install files
    let ca_root_install = AppInstallFile::CARootCertificate;
    let _ = ca_root_install
        .create_from_file(&Path::new(app_config.args.ca_root_cert_file.as_str()).to_path_buf())?;
    app_config.args.ca_root_cert_file = ca_root_install.pathspec().to_str().unwrap().to_string();
    println!(
        "Installed CA root certificate: path={:?}",
        &app_config.args.ca_root_cert_file
    );

    let client_binary_install = AppInstallFile::ClientBinary;
    let _ = client_binary_install
        .create_from_file(&Path::new(app_config.args.client_binary_file.as_str()).to_path_buf())?;
    app_config.args.client_binary_file = client_binary_install
        .pathspec()
        .to_str()
        .unwrap()
        .to_string();
    println!(
        "Installed client binary: path={:?}",
        &app_config.args.client_binary_file
    );

    let client_cert_install = AppInstallFile::ClientCertificate;
    let _ = client_cert_install
        .create_from_file(&Path::new(app_config.args.auth_cert_file.as_str()).to_path_buf())?;
    app_config.args.auth_cert_file = client_cert_install.pathspec().to_str().unwrap().to_string();
    println!(
        "Installed client certificate: path={:?}",
        &app_config.args.auth_cert_file
    );

    let client_key_install = AppInstallFile::ClientKey;
    let _ = client_key_install
        .create_from_file(&Path::new(app_config.args.auth_key_file.as_str()).to_path_buf())?;
    app_config.args.auth_key_file = client_key_install.pathspec().to_str().unwrap().to_string();
    println!(
        "Installed client key: path={:?}",
        &app_config.args.auth_key_file
    );

    let client_config_install = AppInstallFile::ClientConfig;
    let mut client_config_entries: Vec<String> = app_config
        .args
        .into_env_map()
        .iter()
        .map(|kv| format!("{}={}", &kv.0, &kv.1))
        .collect();
    client_config_entries.sort();
    let _ = client_config_install.create(
        client_config_entries
            .iter()
            .fold(String::new(), |result, entry| {
                format!("{}{}\n", &result, entry)
            })
            .as_bytes(),
    )?;
    println!(
        "Installed client config: path={:?}",
        &client_config_install.pathspec().to_str().unwrap()
    );

    println!(
        "Installation complete! Consider adding '{:?}' to the executable search path.",
        &AppInstallFile::ClientBinary.pathspec().parent().unwrap()
    );

    Ok(())
}

/// Main execution function
///
pub fn main() {
    match process_runner() {
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
pub mod tests {
    use super::*;
    use std::{env, fs};
    use trust0_common::testutils;

    #[test]
    fn main_process_runner() {
        let dest_ca_root_cert_file_path;
        let dest_client_binary_file_path;
        let dest_client_key_file_path;
        let dest_client_cert_file_path;
        let dest_client_config_file_path;
        let result;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            testutils::setup_xdg_vars().unwrap();
            config::tests::setup_complete_env_vars();
            env::remove_var("CONFIG_FILE");
            dest_ca_root_cert_file_path = AppInstallFile::CARootCertificate.pathspec();
            dest_client_binary_file_path = AppInstallFile::ClientBinary.pathspec();
            dest_client_key_file_path = AppInstallFile::ClientKey.pathspec();
            dest_client_cert_file_path = AppInstallFile::ClientCertificate.pathspec();
            dest_client_config_file_path = AppInstallFile::ClientConfig.pathspec();

            result = process_runner();
        }

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        // CA root certificate file
        let ca_root_cert_file_meta = fs::metadata(dest_ca_root_cert_file_path.as_path());
        if let Err(err) = ca_root_cert_file_meta {
            panic!(
                "Unexpected metadata result: path={:?}, err={:?}",
                &dest_ca_root_cert_file_path, &err
            );
        }
        let ca_root_cert_file_meta = ca_root_cert_file_meta.unwrap();
        #[cfg(unix)]
        {
            assert_eq!(ca_root_cert_file_meta.len(), 1834);
        }
        #[cfg(windows)]
        {
            assert_eq!(ca_root_cert_file_meta.len(), 1864);
        }

        // client binary file
        let client_binary_file_meta = fs::metadata(dest_client_binary_file_path.as_path());
        if let Err(err) = client_binary_file_meta {
            panic!(
                "Unexpected metadata result: path={:?}, err={:?}",
                &dest_client_binary_file_path, &err
            );
        }
        let client_binary_file_meta = client_binary_file_meta.unwrap();
        #[cfg(unix)]
        {
            assert_eq!(client_binary_file_meta.len(), 110);
        }
        #[cfg(windows)]
        {
            assert_eq!(client_binary_file_meta.len(), 116);
        }

        // client key file
        let client_key_file_meta = fs::metadata(dest_client_key_file_path.as_path());
        if let Err(err) = client_key_file_meta {
            panic!(
                "Unexpected metadata result: path={:?}, err={:?}",
                &dest_client_key_file_path, &err
            );
        }
        let client_key_file_meta = client_key_file_meta.unwrap();
        #[cfg(unix)]
        {
            assert_eq!(client_key_file_meta.len(), 3272);
        }
        #[cfg(windows)]
        {
            assert_eq!(client_key_file_meta.len(), 3324);
        }

        // client certificate file
        let client_cert_file_meta = fs::metadata(dest_client_cert_file_path.as_path());
        if let Err(err) = client_cert_file_meta {
            panic!(
                "Unexpected metadata result: path={:?}, err={:?}",
                &dest_client_cert_file_path, &err
            );
        }
        let client_cert_file_meta = client_cert_file_meta.unwrap();
        #[cfg(unix)]
        {
            assert_eq!(client_cert_file_meta.len(), 1911);
        }
        #[cfg(windows)]
        {
            assert_eq!(client_cert_file_meta.len(), 1942);
        }

        // client config file
        let client_config_file_meta = fs::metadata(dest_client_config_file_path.as_path());
        if let Err(err) = client_config_file_meta {
            panic!(
                "Unexpected metadata result: path={:?}, err={:?}",
                &dest_client_config_file_path, &err
            );
        }

        let mut client_config_file_lines: Vec<String> =
            fs::read_to_string(dest_client_config_file_path.to_str().unwrap())
                .unwrap()
                .lines()
                .map(String::from)
                .filter(|line| !line.is_empty())
                .collect();
        client_config_file_lines.sort();

        let expected_config_file_lines = vec![
            format!(
                "AUTH_CERT_FILE={}",
                &dest_client_cert_file_path.to_str().unwrap()
            ),
            format!(
                "AUTH_KEY_FILE={}",
                &dest_client_key_file_path.to_str().unwrap()
            ),
            format!(
                "CA_ROOT_CERT_FILE={}",
                &dest_ca_root_cert_file_path.to_str().unwrap()
            ),
            "CIPHER_SUITE=TLS13_AES_256_GCM_SHA384".to_string(),
            format!(
                "CLIENT_BINARY_FILE={}",
                &dest_client_binary_file_path.to_str().unwrap()
            ),
            "GATEWAY_HOST=gwhost1".to_string(),
            "GATEWAY_PORT=8000".to_string(),
            "HOST=127.0.0.1".to_string(),
            "INSECURE=true".to_string(),
            "MAX_FRAG_SIZE=1024".to_string(),
            "NO_SNI=true".to_string(),
            "NO_TICKETS=true".to_string(),
            "PROTOCOL_VERSION=1.2,1.3".to_string(),
            "SESSION_RESUMPTION=true".to_string(),
            "VERBOSE=true".to_string(),
        ];

        assert_eq!(client_config_file_lines, expected_config_file_lines);
    }
}
