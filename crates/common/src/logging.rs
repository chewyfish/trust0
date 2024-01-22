use std::sync::Mutex;

use log::{debug, error, info, log_enabled, warn, Level, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::json::JsonEncoder;
use log4rs::Handle;
use once_cell::sync::Lazy;

/// Logger singleton
pub static LOG: Lazy<Mutex<Logger>> = Lazy::new(|| {
    Mutex::new(Logger {
        handle: None,
        visitor: None,
    })
});

/// Logger debug log function
///
/// # Arguments
///
/// * `target` - source location context of logging event
/// * `msg` - message content to log
///
pub fn debug(target: &str, msg: &str) {
    LOG.lock().unwrap().debug(target, msg);
}

/// Logger info log function
///
/// # Arguments
///
/// * `target` - source location context of logging event
/// * `msg` - message content to log
///
pub fn info(target: &str, msg: &str) {
    LOG.lock().unwrap().info(target, msg);
}

/// Logger warn log function
///
/// # Arguments
///
/// * `target` - source location context of logging event
/// * `msg` - message content to log
///
pub fn warn(target: &str, msg: &str) {
    LOG.lock().unwrap().warn(target, msg);
}

/// Logger error log function
///
/// # Arguments
///
/// * `target` - source location context of logging event
/// * `msg` - message content to log
///
pub fn error(target: &str, msg: &str) {
    LOG.lock().unwrap().error(target, msg);
}

/// Simplify code location macro usage for log target
#[macro_export]
macro_rules! target {
    () => {{
        format!("{}:{}:{}", file!(), line!(), column!())
    }};
}

pub use target;

/// Construct logging implementation
#[derive(Debug)]
pub enum LogLevel {
    /// Used for debugging, should not be employed in production
    DEBUG,
    /// Informational event, does not indicate an issue
    INFO,
    /// An non-expected event, however not indicative of a critical issue
    WARN,
    /// An abnormal event, and will need to be addressed. Aspects of the system may not be functional
    ERROR,
}

pub type LogVisitor = dyn Fn(LogLevel, &str) + Send + 'static;

pub struct Logger {
    /// A [`log4rs`] logger handle
    handle: Option<Handle>,
    /// Visitor pattern object for the logging events
    visitor: Option<Box<LogVisitor>>,
}

impl Logger {
    /// Configure logger
    ///
    /// # Arguments
    ///
    /// * `level_filter` - Specifies the log level threshold for what should be logged
    /// * `visitor` - Visitor pattern object for the logging events
    ///
    pub fn configure(&mut self, level_filter: LogLevel, visitor: Option<Box<LogVisitor>>) {
        let level_filter = match level_filter {
            LogLevel::DEBUG => LevelFilter::Debug,
            LogLevel::INFO => LevelFilter::Info,
            LogLevel::WARN => LevelFilter::Warn,
            LogLevel::ERROR => LevelFilter::Error,
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
    ///
    /// # Arguments
    ///
    /// * `target` - source location context of logging event
    /// * `msg` - message content to log
    ///
    pub fn debug(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Debug) {
            debug!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.as_ref().unwrap()(LogLevel::DEBUG, msg);
            }
        }
    }

    /// info-level logging
    ///
    /// # Arguments
    ///
    /// * `target` - source location context of logging event
    /// * `msg` - message content to log
    ///
    pub fn info(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Info) {
            info!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.as_ref().unwrap()(LogLevel::INFO, msg);
            }
        }
    }

    /// warn-level logging
    ///
    /// # Arguments
    ///
    /// * `target` - source location context of logging event
    /// * `msg` - message content to log
    ///
    pub fn warn(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Warn) {
            warn!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.as_ref().unwrap()(LogLevel::WARN, msg);
            }
        }
    }

    /// info-level logging
    ///
    /// # Arguments
    ///
    /// * `target` - source location context of logging event
    /// * `msg` - message content to log
    ///
    pub fn error(&self, target: &str, msg: &str) {
        if log_enabled!(Level::Error) {
            error!(target: target, "{}", msg);
            if self.visitor.is_some() {
                self.visitor.as_ref().unwrap()(LogLevel::ERROR, msg);
            }
        }
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Logger singleton
    pub static TST_LOG: Lazy<Mutex<Logger>> = Lazy::new(|| {
        let mut logger = Logger {
            handle: None,
            visitor: None,
        };
        logger.configure(LogLevel::DEBUG, None);
        Mutex::new(logger)
    });

    /// re-configure logger
    pub fn re_configure(
        logger: &mut Logger,
        level_filter: LogLevel,
        visitor: Option<Box<LogVisitor>>,
    ) {
        let level_filter = match level_filter {
            LogLevel::DEBUG => LevelFilter::Debug,
            LogLevel::INFO => LevelFilter::Info,
            LogLevel::WARN => LevelFilter::Warn,
            LogLevel::ERROR => LevelFilter::Error,
        };

        let stdout: ConsoleAppender = ConsoleAppender::builder()
            .encoder(Box::new(JsonEncoder::new()))
            .build();
        let log_config = log4rs::config::Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(level_filter))
            .unwrap();

        logger.handle.as_mut().unwrap().set_config(log_config);
        logger.visitor = visitor;
    }

    #[test]
    fn logger_debug_level() {
        let mut logger = TST_LOG.lock();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_copy = captured.clone();
        let log_visitor = move |level, msg: &str| {
            *captured_copy.lock().unwrap() = Some(format!("{:?}:{}", level, msg));
        };

        re_configure(
            logger.as_mut().unwrap(),
            LogLevel::DEBUG,
            Some(Box::new(log_visitor)),
        );

        logger.as_ref().unwrap().debug("t1", "m1");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "DEBUG:m1".to_string()
        );

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().info("t2", "m2");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "INFO:m2".to_string()
        );

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().warn("t3", "m3");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "WARN:m3".to_string()
        );

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().error("t4", "m4");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "ERROR:m4".to_string()
        );
    }

    #[test]
    fn logger_info_level() {
        let mut logger = TST_LOG.lock();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_copy = captured.clone();
        let log_visitor = move |level, msg: &str| {
            *captured_copy.lock().unwrap() = Some(format!("{:?}:{}", level, msg));
        };

        re_configure(
            logger.as_mut().unwrap(),
            LogLevel::INFO,
            Some(Box::new(log_visitor)),
        );

        logger.as_ref().unwrap().debug("t1", "m1");
        assert!(captured.lock().unwrap().is_none());

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().info("t2", "m2");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "INFO:m2".to_string()
        );

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().warn("t3", "m3");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "WARN:m3".to_string()
        );

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().error("t4", "m4");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "ERROR:m4".to_string()
        );
    }

    #[test]
    fn logger_warn_level() {
        let mut logger = TST_LOG.lock();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_copy = captured.clone();
        let log_visitor = move |level, msg: &str| {
            *captured_copy.lock().unwrap() = Some(format!("{:?}:{}", level, msg));
        };

        re_configure(
            logger.as_mut().unwrap(),
            LogLevel::WARN,
            Some(Box::new(log_visitor)),
        );

        logger.as_ref().unwrap().debug("t1", "m1");
        assert!(captured.lock().unwrap().is_none());

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().info("t2", "m2");
        assert!(captured.lock().unwrap().is_none());

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().warn("t3", "m3");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "WARN:m3".to_string()
        );

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().error("t4", "m4");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "ERROR:m4".to_string()
        );
    }

    #[test]
    fn logger_error_level() {
        let mut logger = TST_LOG.lock();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_copy = captured.clone();
        let log_visitor = move |level, msg: &str| {
            *captured_copy.lock().unwrap() = Some(format!("{:?}:{}", level, msg));
        };

        re_configure(
            logger.as_mut().unwrap(),
            LogLevel::ERROR,
            Some(Box::new(log_visitor)),
        );

        logger.as_ref().unwrap().debug("t1", "m1");
        assert!(captured.lock().unwrap().is_none());

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().info("t2", "m2");
        assert!(captured.lock().unwrap().is_none());

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().warn("t3", "m3");
        assert!(captured.lock().unwrap().is_none());

        *captured.lock().unwrap() = None;
        logger.as_ref().unwrap().error("t4", "m4");
        assert!(captured.lock().unwrap().is_some());
        assert_eq!(
            captured.lock().unwrap().as_ref().unwrap().to_string(),
            "ERROR:m4".to_string()
        );
    }
}
