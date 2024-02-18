use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};

use trust0_common::error::AppError;

pub const SHELL_MSG_APP_TITLE: &str = "Trust0 SDP Platform";
pub const SHELL_MSG_APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SHELL_MSG_APP_HELP: &str = "(enter 'help' for commands)";
pub const SHELL_PROMPT: &str = "> ";

#[cfg(windows)]
pub const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
pub const LINE_ENDING: &str = "\n";

/// Used by logger after lines are displayed
///
/// # Arguments
///
/// * `include_welcome` - If true, will display the application title prior to the prompt
///
/// # Returns
///
/// A [`Result`] indicating success/failure of the write operation.
///
pub fn write_shell_prompt(include_welcome: bool) -> Result<(), AppError> {
    let mut writer = ShellOutputWriter::new(None);
    writer.write_shell_prompt(include_welcome)
}

/// Handles REPL shell's output
pub struct ShellOutputWriter {
    writer: Option<Box<dyn Write + Send>>,
}

impl ShellOutputWriter {
    /// ShellOutputWriter constructor. If writer object is not given, will use STDOUT.
    ///
    /// # Arguments
    ///
    /// * `writer` - A [`Write`] object used to send shell output
    ///
    /// # Returns
    ///
    /// A newly constructed [`ShellOutputWriter`] object.
    ///
    pub fn new(writer: Option<Box<dyn Write + Send>>) -> Self {
        Self { writer }
    }

    /// print REPL shell prompt to STDOUT
    pub fn write_shell_prompt(&mut self, include_welcome: bool) -> Result<(), AppError> {
        let mut stdout_writer: Box<dyn Write + Send> = Box::new(io::stdout());
        let writer = self.writer.as_mut().unwrap_or(&mut stdout_writer);

        if include_welcome {
            writer
                .write_all(
                    format!(
                        "{} v{} {}\n",
                        SHELL_MSG_APP_TITLE, SHELL_MSG_APP_VERSION, SHELL_MSG_APP_HELP
                    )
                    .as_bytes(),
                )
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error writing welcome msg".to_string(),
                        Box::new(err),
                    )
                })?;
        }

        writer.write_all(SHELL_PROMPT.as_bytes()).map_err(|err| {
            AppError::GenWithMsgAndErr("Error writing prompt".to_string(), Box::new(err))
        })?;
        writer.flush().map_err(|err| {
            AppError::GenWithMsgAndErr("Error flushing STDOUT".to_string(), Box::new(err))
        })
    }
}

impl Write for ShellOutputWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stdout_writer: Box<dyn Write + Send> = Box::new(io::stdout());
        let writer = self.writer.as_mut().unwrap_or(&mut stdout_writer);
        writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stdout_writer: Box<dyn Write + Send> = Box::new(io::stdout());
        let writer = self.writer.as_mut().unwrap_or(&mut stdout_writer);
        writer.flush()
    }
}

/// Handles REPL shell's input
pub struct ShellInputReader {
    disable_tty_echo: Arc<Mutex<bool>>,
    channel_send: Sender<io::Result<String>>,
    channel_recv: Receiver<io::Result<String>>,
}

impl ShellInputReader {
    /// ThreadedStdin constructor
    ///
    /// # Returns
    ///
    /// A newly constructed [`ShellInputReader`] object.
    ///
    pub fn new() -> Self {
        let (send, recv) = mpsc::channel();

        ShellInputReader {
            disable_tty_echo: Arc::new(Mutex::new(false)),
            channel_send: send,
            channel_recv: recv,
        }
    }

    /// Return copy of TTY echo disable state (to be able to control whether keyed input is shown on the terminal - next line only)
    ///
    /// # Returns
    ///
    /// A mutex around a boolean to control the TTY echoing.
    ///
    pub fn clone_disable_tty_echo(&self) -> Arc<Mutex<bool>> {
        self.disable_tty_echo.clone()
    }

    /// Blocking read for next input line, which will be sent to channel for processing
    ///
    /// # Arguments
    ///
    /// * `reader` - A [`BufRead`] to use in reading shell input
    /// * `is_password_input` - If true, don't echo input to console
    /// * `channel_sender` - Line read results sent to this channel
    ///
    fn process_next_line(
        mut reader: impl BufRead,
        is_password_input: bool,
        channel_sender: &Sender<io::Result<String>>,
    ) {
        let read_result = match is_password_input {
            true => rpassword::read_password(),
            false => {
                let mut line: String = String::new();
                match reader.read_line(&mut line) {
                    Ok(_) => Ok(line.trim_end().to_string()),
                    Err(err) => Err(err),
                }
            }
        };
        match &read_result {
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => (),
            _ => {
                let _ = channel_sender.send(read_result);
            }
        }
    }
}

/// Connect an IO source to a channel sink for textual content transfer
impl InputTextStreamConnector for ShellInputReader {
    fn clone_channel_sender(&self) -> Sender<io::Result<String>> {
        self.channel_send.clone()
    }

    fn spawn_line_reader(&self) {
        let disable_tty_echo = self.disable_tty_echo.clone();
        let channel_send = self.channel_send.clone();
        std::thread::spawn(move || loop {
            let disable_tty_echo_val = *disable_tty_echo.lock().unwrap();
            let is_password_input = match disable_tty_echo_val {
                false => false,
                true => {
                    *disable_tty_echo.lock().unwrap() = false;
                    true
                }
            };
            Self::process_next_line(io::stdin().lock(), is_password_input, &channel_send);
        });
    }

    fn next_line(&mut self) -> Result<Option<String>, AppError> {
        match self.channel_recv.try_recv() {
            Ok(result) => match result {
                Ok(line) => Ok(Some(format!("{line}\n"))),
                Err(err) => Err(AppError::GenWithMsgAndErr(
                    "Error processing input".to_string(),
                    Box::new(err),
                )),
            },
            Err(TryRecvError::Disconnected) => Err(AppError::General(
                "Input channel sender disconnected".to_string(),
            )),
            Err(TryRecvError::Empty) => Ok(None),
        }
    }
}

pub trait InputTextStreamConnector {
    /// Clone message channel sender
    ///
    /// # Returns
    ///
    /// The channel sender used to queue lines read from console.
    ///
    fn clone_channel_sender(&self) -> Sender<io::Result<String>>;

    /// Spawn a thread to perform (blocking) STDIN reads (queue resulting lines)
    fn spawn_line_reader(&self) {}

    /// Non-blocking call to retrieve next queued input line
    ///
    /// Returns `Ok(None)` if no lines queued
    ///
    fn next_line(&mut self) -> Result<Option<String>, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::{mock, predicate};
    use std::io::{Cursor, Read};
    use trust0_common::testutils::ChannelWriter;

    // mocks
    // =====

    mock! {
        pub InpTxtStreamConnector {}
        impl InputTextStreamConnector for InpTxtStreamConnector {
            fn clone_channel_sender(&self) -> Sender<io::Result<String>>;
            fn next_line(&mut self) -> Result<Option<String>, AppError>;
        }
    }

    mock! {
        pub Writer {}
        impl Write for Writer {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
            fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()>;
            fn flush(&mut self) -> io::Result<()>;
        }
    }

    mock! {
        pub Reader {}
        impl Read for Reader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
        }
        impl BufRead for Reader {
            fn read_line(&mut self, buf: &mut String) -> io::Result<usize>;
            fn fill_buf(&mut self) -> io::Result<&'static [u8]>;
            fn consume(&mut self, amt: usize);
        }
    }

    // tests
    // =====

    #[test]
    fn shellout_write_shell_prompt_with_welcome() {
        let expected_output = format!(
            "{} v{} {}\n{}",
            SHELL_MSG_APP_TITLE, SHELL_MSG_APP_VERSION, SHELL_MSG_APP_HELP, SHELL_PROMPT
        )
        .into_bytes();

        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
        };

        if let Err(err) = shell_output.write_shell_prompt(true) {
            panic!("Unexpected function result: err={:?}", &err);
        }

        let mut output_data: Vec<u8> = vec![];

        loop {
            let output_result = output_channel.1.try_recv();
            if let Err(err) = output_result {
                if let TryRecvError::Empty = err {
                    break;
                }
                panic!("Unexpected output result: err={:?}", &err);
            }
            output_data.append(&mut output_result.unwrap());
        }

        assert_eq!(output_data, expected_output);
    }

    #[test]
    fn shellout_write_shell_prompt_with_welcome_where_1st_write_fails() {
        let mut shell_writer = MockWriter::new();
        shell_writer
            .expect_write_all()
            .with(predicate::always())
            .times(1)
            .returning(|_| Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
        shell_writer.expect_flush().never();

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(shell_writer)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn shellout_write_shell_prompt_with_welcome_where_2nd_write_fails() {
        let mut shell_writer = MockWriter::new();
        shell_writer
            .expect_write_all()
            .with(predicate::always())
            .times(2)
            .returning(|data| {
                if data != SHELL_PROMPT.as_bytes() {
                    Ok(())
                } else {
                    Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                }
            });
        shell_writer.expect_flush().never();

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(shell_writer)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn shellout_write_shell_prompt_with_welcome_where_flush_fails() {
        let mut shell_writer = MockWriter::new();
        shell_writer
            .expect_write_all()
            .with(predicate::always())
            .times(2)
            .returning(|_| Ok(()));
        shell_writer
            .expect_flush()
            .times(1)
            .returning(|| Err(io::Error::from(io::ErrorKind::UnexpectedEof)));

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(shell_writer)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn shellout_write_shell_prompt_without_welcome() {
        let expected_output = format!("{}", SHELL_PROMPT).into_bytes();

        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
        };

        if let Err(err) = shell_output.write_shell_prompt(false) {
            panic!("Unexpected function result: err={:?}", &err);
        }

        let output_result = output_channel.1.try_recv();

        if let Err(err) = output_result {
            panic!("Unexpected output result: err={:?}", &err);
        }

        assert_eq!(output_result.unwrap(), expected_output);
    }

    #[test]
    fn shellinp_new() {
        let input_reader = ShellInputReader::new();

        let disable_tty_echo = input_reader.clone_disable_tty_echo();
        assert!(!*disable_tty_echo.lock().unwrap());

        let channel_sender = input_reader.clone_channel_sender();
        let channel_receiver = &input_reader.channel_recv;
        if let Err(err) = channel_sender.send(Ok("hi".to_string())) {
            panic!("Unexpected channel send result: err={:?}", &err);
        }
        match channel_receiver.try_recv() {
            Ok(msg_result) => match msg_result {
                Ok(msg) => assert_eq!(msg, "hi"),
                Err(err) => panic!("Unexpected channel recv message result: err={:?}", &err),
            },
            Err(err) => panic!("Unexpected channel recv result: err={:?}", &err),
        }
    }

    fn shellinp_process_next_line_when_no_lines(is_password_input: bool) {
        let cursor = Cursor::new(vec![]);
        let lines_channel = mpsc::channel();

        ShellInputReader::process_next_line(cursor, is_password_input, &lines_channel.0);

        let mut actual_lines = vec![];
        loop {
            let recvd_result = lines_channel.1.try_recv();
            match recvd_result {
                Ok(line_result) => match line_result {
                    Ok(line) => actual_lines.push(line),
                    Err(err) => panic!(
                        "Unexpected line result: recvd={:?}, err={:?}",
                        &actual_lines, &err
                    ),
                },
                Err(err) => match err {
                    TryRecvError::Disconnected => panic!(
                        "Unexpected disconnected line recvd result: recvd={:?}",
                        &actual_lines
                    ),
                    TryRecvError::Empty => break,
                },
            }
        }

        assert_eq!(actual_lines.len(), 1);
        assert!(actual_lines.get(0).unwrap().is_empty());
    }

    #[test]
    fn shellinp_process_next_line_when_non_pwd_input_and_no_lines() {
        shellinp_process_next_line_when_no_lines(false);
    }

    fn shellinp_process_next_line_when_2_lines(is_password_input: bool) {
        let mut cursor = Cursor::new("line1\nline2\n".as_bytes().to_vec());
        let lines_channel = mpsc::channel();

        ShellInputReader::process_next_line(&mut cursor, is_password_input, &lines_channel.0);
        ShellInputReader::process_next_line(&mut cursor, is_password_input, &lines_channel.0);

        let mut actual_lines = vec![];
        loop {
            let recvd_result = lines_channel.1.try_recv();
            match recvd_result {
                Ok(line_result) => match line_result {
                    Ok(line) => actual_lines.push(line),
                    Err(err) => panic!(
                        "Unexpected line result: recvd={:?}, err={:?}",
                        &actual_lines, &err
                    ),
                },
                Err(err) => match err {
                    TryRecvError::Disconnected => panic!(
                        "Unexpected disconnected line recvd result: recvd={:?}",
                        &actual_lines
                    ),
                    TryRecvError::Empty => break,
                },
            }
        }

        assert_eq!(actual_lines.len(), 2);
        assert_eq!(actual_lines, vec!["line1", "line2"]);
    }

    #[test]
    fn shellinp_process_next_line_when_non_pwd_input_and_2_lines() {
        shellinp_process_next_line_when_2_lines(false);
    }

    #[test]
    fn shellinp_process_next_line_when_eof_read_error() {
        let mut reader = MockReader::new();
        reader
            .expect_read_line()
            .with(predicate::always())
            .times(1)
            .returning(|_| Err(io::Error::from(io::ErrorKind::UnexpectedEof)));

        let lines_channel = mpsc::channel();

        ShellInputReader::process_next_line(reader, false, &lines_channel.0);

        let recvd_result = lines_channel.1.try_recv();
        match recvd_result {
            Ok(line_result) => panic!("Unexpected lines result received: line={:?}", &line_result),
            Err(err) => match err {
                TryRecvError::Disconnected => panic!("Unexpected disconnected line recvd result"),
                TryRecvError::Empty => {}
            },
        }
    }

    #[test]
    fn shellinp_next_line_when_no_lines() {
        let mut threaded_stdin = ShellInputReader::new();

        loop {
            match threaded_stdin.next_line() {
                Ok(line) => match line {
                    Some(line_val) => panic!("Unexpected line received: line={}", &line_val),
                    None => break,
                },
                Err(err) => panic!("Unexpected next line result: err={:?}", &err),
            }
        }
    }

    #[test]
    fn shellinp_next_line_when_2_lines() {
        let mut threaded_stdin = ShellInputReader::new();

        let line_channel_sender = threaded_stdin.clone_channel_sender();

        line_channel_sender.send(Ok("line1".to_string())).unwrap();
        line_channel_sender.send(Ok("line2".to_string())).unwrap();

        let mut recvd_lines = vec![];
        loop {
            match threaded_stdin.next_line() {
                Ok(line) => match line {
                    Some(line_val) => {
                        if recvd_lines.len() == 2 {
                            panic!(
                                "Unexpected 3rd line received: recvd={:?}, line={}",
                                &recvd_lines, &line_val
                            )
                        } else {
                            recvd_lines.push(line_val);
                        }
                    }
                    None => break,
                },
                Err(err) => panic!("Unexpected next line result: err={:?}", &err),
            }
        }

        assert_eq!(recvd_lines.len(), 2);
    }

    #[test]
    fn shellinp_next_line_when_io_error_line() {
        let mut threaded_stdin = ShellInputReader::new();

        let line_channel_sender = threaded_stdin.clone_channel_sender();

        line_channel_sender
            .send(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
            .unwrap();

        match threaded_stdin.next_line() {
            Ok(line) => panic!("Unexpected successful received line: line={:?}", &line),
            Err(_) => {}
        }
    }

    #[test]
    fn inptextconn_trait_defaults() {
        struct InputConnector {}
        impl InputTextStreamConnector for InputConnector {
            fn clone_channel_sender(&self) -> Sender<io::Result<String>> {
                mpsc::channel().0
            }
            fn next_line(&mut self) -> Result<Option<String>, AppError> {
                Ok(None)
            }
        }

        let input_connect = InputConnector {};

        input_connect.spawn_line_reader();
    }
}
