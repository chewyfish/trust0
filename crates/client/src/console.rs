use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use trust0_common::error::AppError;

/// REPL shell (prompt,...)
const SHELL_MSG_APP_TITLE: &str = "Trust0 SDP Platform";
const SHELL_MSG_APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const SHELL_MSG_APP_HELP: &str = "(enter 'help' for commands)";
const SHELL_PROMPT: &str = "> ";

pub fn write_shell_prompt(include_welcome: bool) -> Result<(), AppError> {

    if include_welcome {
        io::stdout().write_all(
            format!("{} v{} {}\n",
                    SHELL_MSG_APP_TITLE,
                    SHELL_MSG_APP_VERSION,
                    SHELL_MSG_APP_HELP).as_bytes()).map_err(|err|
            AppError::GenWithMsgAndErr("Error writing welcome msg".to_string(), Box::new(err)))?;
    }

    io::stdout().write_all(SHELL_PROMPT.as_bytes()).map_err(|err|
        AppError::GenWithMsgAndErr("Error writing prompt".to_string(), Box::new(err)))?;
    io::stdout().flush().map_err(|err|
        AppError::GenWithMsgAndErr("Error flushing STDOUT".to_string(), Box::new(err)))
}

/// Spawn thread to handle STDIN input
pub struct ThreadedStdin {
    channel_send: Sender<io::Result<String>>,
    channel_recv: Receiver<io::Result<String>>,
}

impl ThreadedStdin {

    /// ThreadedStdin constructor
    pub fn new() -> Self {

        let (send, recv) = mpsc::channel();

        ThreadedStdin {
            channel_send: send,
            channel_recv: recv
        }
    }

    /// Clone message channel sender
    pub fn clone_channel_sender(&self) -> Sender<io::Result<String>> {
        self.channel_send.clone()
    }

    /// Non-blocking call to retrieve next queued input line
    ///
    /// Returns `Ok(None)` if no lines queued
    pub fn next_line(&mut self) -> Result<Option<String>, AppError> {

        match self.channel_recv.try_recv() {

            Ok(result) => match result {
                Ok(line) => Ok(Some(format!("{line}\n"))),
                Err(err) => Err(AppError::GenWithMsgAndErr("Error processing input".to_string(), Box::new(err)))
            },
            Err(TryRecvError::Disconnected) => Err(AppError::General("Input channel sender disconnected".to_string())),
            Err(TryRecvError::Empty) => Ok(None)
        }
    }

    /// Spawn a thread to perform (blocking) STDIN reads (queue resulting lines)
    pub(crate) fn spawn_line_reader(channel_send: Sender<io::Result<String>>) {

        std::thread::spawn(move || {
            loop {
                let lines = io::stdin().lines();
                for line in lines {
                    if channel_send.send(line).is_err() {
                        return;
                    }
                }
            }
        });
    }
}
