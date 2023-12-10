use std::{process, thread};
use std::time::Duration;
use anyhow::Result;
use futures::executor::block_on;

use trust0_common::error::AppError;
use trust0_common::logging::{error, LOG, LogLevel};
use trust0_client::api::{AppConfig, ComponentLifecycle, MainProcessor, write_shell_prompt};
use trust0_common::target;

async fn async_main() -> Result<(), AppError> {

    let app_config = AppConfig::new()?;

    LOG.lock().unwrap().configure(
        if app_config.verbose_logging { LogLevel::DEBUG } else { LogLevel::ERROR },
        Some(|_,_| { let _ = write_shell_prompt(false); })
    );

    let mut processor = MainProcessor::new(app_config);

    let shutdown_fn = processor.get_shutdown_function();
    ctrlc::set_handler(move || {
        error(&target!(), "Signal caught, client shutting down...");
        shutdown_fn();
        thread::sleep(Duration::from_millis(3000));
        process::exit(0);
    }).map_err(|err| AppError::GenWithMsgAndErr("Error setting Ctrl-C handler".to_string(), Box::new(err)))?;

    processor.start().await
}

#[tokio::main(flavor="multi_thread")]
pub async fn main() -> Result<()> {

    match block_on(async_main()) {

        Ok(()) => {
            process::exit(0);
        },
        Err(err) =>  {
            eprintln!("{:?}", err);
            process::exit(1);
        }
    }
}
