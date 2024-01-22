mod config;
mod console;

use std::process;

use anyhow::Result;
use trust0_common::authn::scram_sha256_authenticator;

use crate::config::{AppConfig, AuthnType};
use crate::console::{Console, ConsoleIO, LINE_ENDING};

const LABEL_USERNAME: &[u8] = "Username: ".as_bytes();
const LABEL_PASSWORD: &[u8] = "Password: ".as_bytes();

/// Run main process
///
/// # Returns
///
/// A [`Result`] indicating the success/failure of the processing operation.
///
fn process_runner(app_config: &AppConfig, console: &mut dyn ConsoleIO) -> Result<()> {
    console.write_title()?;

    match app_config.args.authn_scheme {
        AuthnType::ScramSha256 => {
            // Gather username, password
            console.write_data(LABEL_USERNAME, true)?;
            let username = console.read_next_line(false)?;
            console.write_data(LABEL_PASSWORD, true)?;
            let password = console.read_next_line(true)?;

            // Generate password hash
            console.write_data(
                format!(
                    "{}{}",
                    String::from_utf8(scram_sha256_authenticator::hash_password(
                        &username, &password, true
                    ))?,
                    LINE_ENDING
                )
                .as_bytes(),
                true,
            )?;
        }
    }

    Ok(())
}

/// Main execution function
///
pub fn main() {
    let app_config = AppConfig::new().unwrap();
    let mut console = Console::new(None, None);
    match process_runner(&app_config, &mut console) {
        Ok(()) => {
            process::exit(0);
        }
        Err(err) => {
            eprintln!("{:?}", err);
            process::exit(1);
        }
    }
}

// Unit tests
#[cfg(test)]
mod test {
    use super::*;
    use crate::config::tests::setup_env_vars;
    use trust0_common::error::AppError;
    use trust0_common::testutils;

    // structs
    // =======
    struct TestConsole {
        in_data: Vec<String>,
        out_title: Vec<String>,
        out_data: Vec<String>,
    }

    impl ConsoleIO for TestConsole {
        fn write_title(&mut self) -> Result<(), AppError> {
            self.out_title.push("T".to_string());
            Ok(())
        }

        fn write_data(&mut self, data: &[u8], flush_output: bool) -> Result<(), AppError> {
            if flush_output {
                let mut data = String::from_utf8(data.to_vec()).unwrap();
                data.push('!');
                self.out_data.push(data);
            } else {
                self.out_data
                    .push(String::from_utf8(data.to_vec()).unwrap());
            }
            Ok(())
        }

        fn read_next_line(&mut self, _is_password_input: bool) -> Result<String, AppError> {
            Ok(self.in_data.pop().unwrap())
        }
    }

    // tests
    // =====

    #[test]
    fn main_process_runner_when_scramsha256_authn() {
        let mut console = TestConsole {
            in_data: vec!["pass1".to_string(), "user1".to_string()],
            out_title: vec![],
            out_data: vec![],
        };
        let result;
        {
            let mutex = testutils::TEST_MUTEX.clone();
            let _lock = mutex.lock().unwrap();
            setup_env_vars("scram-sha256");
            result = AppConfig::new();
        }
        if let Err(err) = result {
            panic!("Unexpected app config creation result: err={:?}", &err);
        }
        let config = result.unwrap();

        if let Err(err) = process_runner(&config, &mut console) {
            panic!("Unexpected process runner result: err={:?}", &err);
        }

        let mut expected_username = String::from_utf8(LABEL_USERNAME.to_vec()).unwrap();
        let mut expected_password = String::from_utf8(LABEL_PASSWORD.to_vec()).unwrap();
        expected_username.push('!');
        expected_password.push('!');
        let expected_hash = "30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=\n!".to_string();

        assert!(console.in_data.is_empty());
        assert_eq!(console.out_title, vec!["T"]);
        assert_eq!(
            console.out_data,
            vec![expected_username, expected_password, expected_hash]
        );
    }
}
