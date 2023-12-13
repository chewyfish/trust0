use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use trust0_common::error::AppError;

const SHELL_MSG_APP_TITLE: &str = "Trust0 SDP Platform";
const SHELL_MSG_APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const SHELL_MSG_APP_HELP: &str = "(enter 'help' for commands)";
const SHELL_PROMPT: &str = "> ";

/// print REPL shell prompt to STDOUT
pub fn write_shell_prompt(include_welcome: bool) -> Result<(), AppError> {
    write_shell_prompt_impl(&mut io::stdout(), include_welcome)
}

fn write_shell_prompt_impl(writer: &mut impl Write, include_welcome: bool) -> Result<(), AppError> {

    if include_welcome {
        writer.write_all(
            format!("{} v{} {}\n",
                    SHELL_MSG_APP_TITLE,
                    SHELL_MSG_APP_VERSION,
                    SHELL_MSG_APP_HELP).as_bytes()).map_err(|err|
            AppError::GenWithMsgAndErr("Error writing welcome msg".to_string(), Box::new(err)))?;
    }

    writer.write_all(SHELL_PROMPT.as_bytes()).map_err(|err|
        AppError::GenWithMsgAndErr("Error writing prompt".to_string(), Box::new(err)))?;
    writer.flush().map_err(|err|
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
            Self::lines_connector_processor(io::stdin().lock(), &channel_send);
        });
    }

    /// Source, sink connector for input lines to be sent to channel for processing
    fn lines_connector_processor(reader: impl BufRead, channel_sender: &Sender<io::Result<String>>) {

        let lines = reader.lines();
        for line in lines {
            if channel_sender.send(line).is_err() {
                return;
            }
        }
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use std::io::Cursor;
    use super::*;

    #[test]
    fn console_write_shell_prompt_with_welcome() {

        let expected_output = format!("{} v{} {}\n{}",
                                      SHELL_MSG_APP_TITLE,
                                      SHELL_MSG_APP_VERSION,
                                      SHELL_MSG_APP_HELP,
                                      SHELL_PROMPT).into_bytes();


        let mut cursor = Cursor::new(vec![0; expected_output.len()]);

        if let Err(err) = write_shell_prompt_impl(&mut cursor, true) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(*cursor.get_ref(), expected_output);
    }

    #[test]
    fn console_write_shell_prompt_without_welcome() {

        let expected_output = format!("{}", SHELL_PROMPT).into_bytes();


        let mut cursor = Cursor::new(vec![0; expected_output.len()]);

        if let Err(err) = write_shell_prompt_impl(&mut cursor, false) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(*cursor.get_ref(), expected_output);
    }

    #[test]
    fn thdstdin_lines_connector_processor_when_no_lines() {

        let cursor = Cursor::new(vec![]);
        let lines_channel = mpsc::channel();

        ThreadedStdin::lines_connector_processor(cursor, &lines_channel.0);

        let mut actual_lines = vec![];
        loop {
            let recvd_result = lines_channel.1.try_recv();
            match recvd_result {
                Ok(line_result) => match line_result {
                    Ok(line) => actual_lines.push(line),
                    Err(err) => panic!("Unexpected line result: recvd={:?}, err={:?}", &actual_lines, &err)
                }
                Err(err) => match err {
                    TryRecvError::Disconnected => panic!("Unexpected disconnected line recvd result: recvd={:?}", &actual_lines),
                    TryRecvError::Empty => break
                }
            }
        }

        assert_eq!(actual_lines.len(), 0);
    }

    #[test]
    fn thdstdin_lines_connector_processor_when_2_lines() {

        let cursor = Cursor::new("line1\nline2\n".as_bytes().to_vec());
        let lines_channel = mpsc::channel();

        ThreadedStdin::lines_connector_processor(cursor, &lines_channel.0);

        let mut actual_lines = vec![];
        loop {
            let recvd_result = lines_channel.1.try_recv();
            match recvd_result {
                Ok(line_result) => match line_result {
                    Ok(line) => actual_lines.push(line),
                    Err(err) => panic!("Unexpected line result: recvd={:?}, err={:?}", &actual_lines, &err)
                }
                Err(err) => match err {
                    TryRecvError::Disconnected => panic!("Unexpected disconnected line recvd result: recvd={:?}", &actual_lines),
                    TryRecvError::Empty => break
                }
            }
        }

        assert_eq!(actual_lines.len(), 2);
        assert_eq!(actual_lines, vec!["line1", "line2"]);
    }

    #[test]
    fn thdstdin_next_line_when_no_lines() {

        let mut threaded_stdin = ThreadedStdin::new();

        loop {
            match threaded_stdin.next_line() {
                Ok(line) => match line {
                    Some(line_val) => panic!("Unexpected line received: line={}", &line_val),
                    None => break
                },
                Err(err) =>  panic!("Unexpected next line result: err={:?}", &err)
            }
        }
    }

    #[test]
    fn thdstdin_next_line_when_2_lines() {

        let mut threaded_stdin = ThreadedStdin::new();

        let line_channel_sender = threaded_stdin.clone_channel_sender();

        line_channel_sender.send(Ok("line1".to_string())).unwrap();
        line_channel_sender.send(Ok("line2".to_string())).unwrap();

        let mut recvd_lines = vec![];
        loop {
            match threaded_stdin.next_line() {
                Ok(line) => match line {
                    Some(line_val) => if recvd_lines.len() == 2 {
                        panic!("Unexpected 3rd line received: recvd={:?}, line={}", &recvd_lines, &line_val)
                    } else {
                        recvd_lines.push(line_val);
                    },
                    None => break
                },
                Err(err) =>  panic!("Unexpected next line result: err={:?}", &err)
            }
        }

        assert_eq!(recvd_lines.len(), 2);
    }
}