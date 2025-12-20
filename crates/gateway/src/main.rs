#[cfg(all(feature = "mysql_db", feature = "postgres_db"))]
compile_error!(
    "feature \"mysql_db\" and feature \"postgres_db\" cannot be enabled at the same time"
);

use std::time::Duration;
use std::{process, thread};

use anyhow::Result;

use trust0_common::crypto;
use trust0_common::error::AppError;
use trust0_common::logging::{debug, error, LogLevel, LOG};
use trust0_common::target;
use trust0_gateway::api::{AppConfig, ComponentLifecycle, MainProcessor};

const DEFAULT_PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
const DEFAULT_PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");

fn process_runner() -> Result<(), AppError> {
    let app_config = AppConfig::new()?;

    LOG.lock().unwrap().configure(
        if app_config.verbose_logging {
            &LogLevel::DEBUG
        } else {
            &LogLevel::INFO
        },
        None,
    );

    debug(
        &target!(),
        &format!(
            "{} v{}: {}",
            DEFAULT_PROGRAM_NAME, DEFAULT_PROGRAM_VERSION, &app_config
        ),
    );

    let mut processor = MainProcessor::new(app_config);

    let shutdown_fn = processor.get_shutdown_function();
    ctrlc::set_handler(move || {
        error(&target!(), "Signal caught, gateway shutting down...");
        shutdown_fn();
        thread::sleep(Duration::from_millis(3000));
        process::exit(0);
    })
    .map_err(|err| AppError::General(format!("Error setting Ctrl-C handler: err={:?}", &err)))?;

    crypto::setup_crypto_provider();

    processor.start()
}

pub fn main() -> Result<()> {
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
