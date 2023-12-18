use std::time::Duration;
use std::{process, thread};

use anyhow::Result;

use trust0_common::error::AppError;
use trust0_common::logging::{error, LogLevel, LOG};
use trust0_common::target;
use trust0_gateway::api::{AppConfig, ComponentLifecycle, MainProcessor};

fn process_runner() -> Result<(), AppError> {
    let app_config = AppConfig::new()?;

    LOG.lock().unwrap().configure(
        if app_config.verbose_logging {
            LogLevel::DEBUG
        } else {
            LogLevel::INFO
        },
        None,
    );

    let mut processor = MainProcessor::new(app_config);

    let shutdown_fn = processor.get_shutdown_function();
    ctrlc::set_handler(move || {
        error(&target!(), "Signal caught, gateway shutting down...");
        shutdown_fn();
        thread::sleep(Duration::from_millis(3000));
        process::exit(0);
    })
    .map_err(|err| {
        AppError::GenWithMsgAndErr("Error setting Ctrl-C handler".to_string(), Box::new(err))
    })?;

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
