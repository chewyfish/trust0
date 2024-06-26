use std::collections::VecDeque;
#[cfg(test)]
use std::io::Cursor;
use std::io::{self, BufRead, Write};
#[cfg(test)]
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// A [`Write`] object used to send output
    writer: Option<Box<dyn Write + Send>>,
    /// Prompt displayed toggle
    prompted_toggle: Arc<AtomicBool>,
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
        Self {
            writer,
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shell prompt status toggler accessor
    ///
    /// # Returns
    ///
    /// [`AtomicBool`] for prompted status toggler
    ///
    pub fn prompted_toggle(&self) -> &Arc<AtomicBool> {
        &self.prompted_toggle
    }

    /// print REPL shell prompt to STDOUT
    ///
    /// # Arguments
    ///
    /// * `include_welcome` - Indicates whether to additionally show the application welcome message
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure for the write operation.
    ///
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
                    AppError::General(format!("Error writing welcome msg: err={:?}", &err))
                })?;
        }

        writer
            .write_all(SHELL_PROMPT.as_bytes())
            .map_err(|err| AppError::General(format!("Error writing prompt: err={:?}", &err)))?;
        writer
            .flush()
            .map_err(|err| AppError::General(format!("Error flushing STDOUT: err={:?}", &err)))?;

        self.prompted_toggle.store(true, Ordering::SeqCst);

        Ok(())
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
    /// Indicates whether the next input read from the TTY should not be echoed back
    disable_tty_echo: Arc<Mutex<bool>>,
    /// Channel sender for incoming TTY text lines
    channel_send: Sender<io::Result<String>>,
    /// Channel receiver for incoming TTY text lines
    channel_recv: Receiver<io::Result<String>>,
    /// Initial input lines to use upon shell readiness
    initial_lines: VecDeque<String>,
    /// Prompt displayed toggle
    prompted_toggle: Arc<AtomicBool>,
    #[cfg(test)]
    /// Shell input reader (for testing)
    test_input_reader: Option<Arc<Mutex<Cursor<Vec<u8>>>>>,
    #[cfg(test)]
    /// Shell input lines total (for testing)
    test_input_lines: i32,
}

impl ShellInputReader {
    /// ShellInputReader constructor
    ///
    /// # Arguments
    ///
    /// * `initial_lines` - A vector of initial input lines to use upon shell readiness
    /// * `prompted_toggle` - Shell output prompt toggler
    ///
    /// # Returns
    ///
    /// A newly constructed [`ShellInputReader`] object.
    ///
    pub fn new(initial_lines: &[String], prompted_toggle: &Arc<AtomicBool>) -> Self {
        let (send, recv) = mpsc::channel();

        ShellInputReader {
            disable_tty_echo: Arc::new(Mutex::new(false)),
            channel_send: send,
            channel_recv: recv,
            initial_lines: VecDeque::from(initial_lines.to_vec()),
            prompted_toggle: prompted_toggle.clone(),
            #[cfg(test)]
            test_input_reader: None,
            #[cfg(test)]
            test_input_lines: 0,
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
        #[cfg(test)]
        let test_input_reader = self.test_input_reader.as_ref().unwrap().clone();
        #[cfg(test)]
        let test_input_lines = self.test_input_lines;
        std::thread::spawn(move || {
            let mut _lines_read_idx = 0;
            loop {
                let disable_tty_echo_val = *disable_tty_echo.lock().unwrap();
                let is_password_input = match disable_tty_echo_val {
                    false => false,
                    true => {
                        *disable_tty_echo.lock().unwrap() = false;
                        true
                    }
                };
                #[cfg(not(test))]
                {
                    Self::process_next_line(io::stdin().lock(), is_password_input, &channel_send);
                }
                #[cfg(test)]
                {
                    if _lines_read_idx >= test_input_lines {
                        break;
                    }
                    Self::process_next_line(
                        test_input_reader.lock().unwrap().deref_mut(),
                        is_password_input,
                        &channel_send,
                    );
                }
                _lines_read_idx += 1;
            }
        });
    }

    fn next_line(&mut self) -> Result<Option<String>, AppError> {
        // Prefer initial lines over STDIN (when shell is ready for next input)
        if !self.initial_lines.is_empty()
            && self
                .prompted_toggle
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Ok(Some(format!(
                "{}\n",
                self.initial_lines.pop_front().unwrap()
            )));
        }

        // Return queued input line (if avail)
        match self.channel_recv.try_recv() {
            Ok(result) => match result {
                Ok(line) => Ok(Some(format!("{line}\n"))),
                Err(err) => Err(AppError::General(format!(
                    "Error processing input: err={:?}",
                    &err
                ))),
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
    #[allow(dead_code)]
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
    use std::thread;
    use std::time::Duration;
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
    fn shellout_new() {
        let shell_output = ShellOutputWriter::new(Some(Box::new(ShellOutputWriter::new(Some(
            Box::new(ChannelWriter {
                channel_sender: mpsc::channel().0,
            }),
        )))));

        assert!(shell_output.writer.is_some());
        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst));
        assert!(!shell_output.prompted_toggle().load(Ordering::SeqCst));
    }

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
            prompted_toggle: Arc::new(AtomicBool::new(false)),
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
        assert!(shell_output.prompted_toggle.load(Ordering::SeqCst))
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
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }

        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst))
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
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }

        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst))
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
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }

        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst))
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
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if let Err(err) = shell_output.write_shell_prompt(false) {
            panic!("Unexpected function result: err={:?}", &err);
        }

        let output_result = output_channel.1.try_recv();

        if let Err(err) = output_result {
            panic!("Unexpected output result: err={:?}", &err);
        }

        assert_eq!(output_result.unwrap(), expected_output);
        assert!(shell_output.prompted_toggle.load(Ordering::SeqCst))
    }

    #[test]
    fn shellinp_new() {
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec!["line1".to_string(), "line2".to_string()];

        let input_reader = ShellInputReader::new(initial_lines.as_slice(), &prompted_toggle);

        let disable_tty_echo = input_reader.clone_disable_tty_echo();
        assert!(!*disable_tty_echo.lock().unwrap());

        assert!(input_reader.prompted_toggle.as_ref().load(Ordering::SeqCst));
        assert_eq!(input_reader.initial_lines, VecDeque::from(initial_lines));

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
    fn shellinp_spawn_line_reader_when_2_lines() {
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let mut input_reader = ShellInputReader::new(vec![].as_slice(), &prompted_toggle);
        input_reader.test_input_reader = Some(Arc::new(Mutex::new(Cursor::new(
            "line1\nline2\n".as_bytes().to_vec(),
        ))));
        input_reader.test_input_lines = 2;

        input_reader.spawn_line_reader();

        thread::sleep(Duration::from_millis(40));

        let mut actual_lines = vec![];
        loop {
            let recvd_result = input_reader.channel_recv.try_recv();
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
    fn shellinp_next_line_when_no_lines() {
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec![];

        let mut input_reader = ShellInputReader::new(initial_lines.as_slice(), &prompted_toggle);

        loop {
            match input_reader.next_line() {
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
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec![];

        let mut input_reader = ShellInputReader::new(initial_lines.as_slice(), &prompted_toggle);

        let line_channel_sender = input_reader.clone_channel_sender();
        line_channel_sender.send(Ok("line1".to_string())).unwrap();
        line_channel_sender.send(Ok("line2".to_string())).unwrap();

        let mut recvd_lines = vec![];
        loop {
            match input_reader.next_line() {
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
    fn shellinp_next_line_when_interleaved_initial_and_channel_lines() {
        let prompted_toggle = Arc::new(AtomicBool::new(false));
        let initial_lines = vec!["init_line1".to_string(), "init_line2".to_string()];

        let mut input_reader = ShellInputReader::new(initial_lines.as_slice(), &prompted_toggle);

        let line_channel_sender = input_reader.clone_channel_sender();
        line_channel_sender
            .send(Ok("chan_line1".to_string()))
            .unwrap();
        line_channel_sender
            .send(Ok("chan_line2".to_string()))
            .unwrap();

        let mut recvd_lines = vec![];
        loop {
            if (recvd_lines.len() % 2) == 0 {
                prompted_toggle.store(true, Ordering::SeqCst);
            } else {
                assert!(!prompted_toggle.load(Ordering::SeqCst));
            }

            match input_reader.next_line() {
                Ok(line) => match line {
                    Some(line_val) => {
                        if recvd_lines.len() == 4 {
                            panic!(
                                "Unexpected 5th line received: recvd={:?}, line={}",
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

        assert_eq!(recvd_lines.len(), 4);
        assert_eq!(
            recvd_lines,
            vec![
                "init_line1\n".to_string(),
                "chan_line1\n".to_string(),
                "init_line2\n".to_string(),
                "chan_line2\n".to_string()
            ]
        );
    }

    #[test]
    fn shellinp_next_line_when_io_error_line() {
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec![];

        let mut input_reader = ShellInputReader::new(initial_lines.as_slice(), &prompted_toggle);

        let line_channel_sender = input_reader.clone_channel_sender();
        line_channel_sender
            .send(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
            .unwrap();

        match input_reader.next_line() {
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
