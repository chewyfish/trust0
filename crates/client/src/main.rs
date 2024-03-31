use anyhow::Result;
use std::time::Duration;
use std::{process, thread};

use trust0_client::api::{write_shell_prompt, AppConfig, ComponentLifecycle, MainProcessor};
use trust0_common::error::AppError;
use trust0_common::logging::{error, LogLevel, LOG};
use trust0_common::target;

fn process_runner() -> Result<(), AppError> {
    let app_config = AppConfig::new()?;

    LOG.lock().unwrap().configure(
        if app_config.verbose_logging {
            &LogLevel::DEBUG
        } else {
            &LogLevel::ERROR
        },
        Some(Box::new(|_, _| {
            let _ = write_shell_prompt(false);
        })),
    );

    let mut processor = MainProcessor::new(app_config);

    let shutdown_fn = processor.get_shutdown_function();
    ctrlc::set_handler(move || {
        error(&target!(), "Signal caught, client shutting down...");
        shutdown_fn();
        thread::sleep(Duration::from_millis(3000));
        process::exit(0);
    })
    .map_err(|err| AppError::General(format!("Error setting Ctrl-C handler: err={:?}", &err)))?;

    processor.start()
}

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
