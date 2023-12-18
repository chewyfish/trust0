use clap::error::ErrorKind;
use clap::Command;
use log::error;

/// invocation error: print usage and panic
pub fn exit_on_usage_error(error: ErrorKind, command: &mut Command, message: &str) {
    error!("{:?}", command.render_help());
    panic!("{}: {}", error, message);
}
