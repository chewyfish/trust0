use std::sync::Mutex;

use log::{debug, error, info, Level, LevelFilter, log_enabled, warn};
use log4rs::Handle;
use log4rs::append::console::ConsoleAppender;
use log4rs::encode::json::JsonEncoder;
use log4rs::config::{Appender, Root};
use once_cell::sync::Lazy;

/// Logger singleton
pub static LOG: Lazy<Mutex<Logger>> = Lazy::new(|| {
    Mutex::new(Logger {
        handle: None,
        visitor: None
    })
});

/// Logger debug log function
pub fn debug(target: &str, msg: &str) {
    LOG.lock().unwrap().debug(target, msg);
}

/// Logger info log function
pub fn info(target: &str, msg: &str) {
    LOG.lock().unwrap().info(target, msg);
}

/// Logger warn log function
pub fn warn(target: &str, msg: &str) {
    LOG.lock().unwrap().warn(target, msg);
}

/// Logger error log function
pub fn error(target: &str, msg: &str) {
    LOG.lock().unwrap().error(target, msg);
}

/// Simplify code location macro usage for log target
#[macro_export]
macro_rules! target {
    () => ({
        format!("{}:{}:{}", file!(), line!(), column!())
    });
}

pub use target;

/// Construct logging implementation
pub enum LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
}

pub struct Logger {
    handle: Option<Handle>,
    visitor: Option<fn (LogLevel, &str)>
}

impl Logger {

    /// configure logger
    pub fn configure(&mut self,
                     level_filter: LogLevel,
                     visitor: Option<fn(LogLevel, &str)>) {

        let level_filter = match level_filter {
            LogLevel::DEBUG => LevelFilter::Debug,
            LogLevel::INFO => LevelFilter::Info,
            LogLevel::WARN => LevelFilter::Warn,
            LogLevel::ERROR => LevelFilter::Error
        };

        let stdout: ConsoleAppender = ConsoleAppender::builder()
            .encoder(Box::new(JsonEncoder::new()))
            .build();
        let log_config = log4rs::config::Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(level_filter))
            .unwrap();

        self.handle = Some(log4rs::init_config(log_config).unwrap());
        self.visitor = visitor;
    }

    /// debug-level logging
    pub fn debug(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Debug) {
            debug!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.unwrap()(LogLevel::DEBUG, msg);
            }
        }
    }

    /// info-level logging
    pub fn info(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Info) {
            info!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.unwrap()(LogLevel::INFO, msg);
            }
        }
    }

    /// warn-level logging
    pub fn warn(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Warn) {
            warn!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.unwrap()(LogLevel::WARN, msg);
            }
        }
    }

    /// info-level logging
    pub fn error(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Error) {
            error!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.unwrap()(LogLevel::ERROR, msg);
            }
        }
    }
}
