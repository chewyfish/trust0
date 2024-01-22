use clap::error::ErrorKind;
use clap::Command;
use log::error;

/// Invocation error: print usage and panic
///
/// # Arguments
///
/// * `error` - Clap error kind value
/// * `command` - Clap command object (used to generate help)
/// * `message` - Specific/contextual error message
///
pub fn exit_on_usage_error(error: ErrorKind, command: &mut Command, message: &str) {
    error!("{:?}", command.render_help());
    panic!("{}: {}", error, message);
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn config_exit_on_usage_error() {
        exit_on_usage_error(
            ErrorKind::DisplayHelp,
            &mut Command::new("My Command"),
            "msg1",
        );
    }
}
