use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};

use crate::error::AppError;
use crate::net::stream_utils::{ChannelReader, ChannelWriter};

pub const SHELL_MSG_APP_TITLE: &str = "Trust0 SDP Platform";
pub const SHELL_MSG_APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SHELL_MSG_APP_HELP: &str = "(enter 'help' for commands)";
pub const SHELL_PROMPT: &str = "> ";

#[cfg(windows)]
pub const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
pub const LINE_ENDING: &str = "\n";

/// Output functions used in communicating with REPL shell
pub trait ReplShellOutputWriter: Write + Send {
    /// Shell prompt status toggler accessor. Indicates whether prompt has currently been written.
    ///
    /// # Returns
    ///
    /// [`AtomicBool`] for prompted status toggler
    ///
    fn prompted_toggle(&self) -> &Arc<AtomicBool>;

    /// Writer accessor (implements [`Write`], used to write output)
    ///
    /// # Returns
    ///
    /// Optional [`Write`] object
    ///
    fn writer(&mut self) -> &mut Option<Box<dyn Write + Send>>;

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
    fn write_shell_prompt(&mut self, include_welcome: bool) -> Result<(), AppError> {
        let mut stdout_writer: Box<dyn Write + Send> = Box::new(io::stdout());
        let writer = self.writer().as_mut().unwrap_or(&mut stdout_writer);

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

        self.prompted_toggle().store(true, Ordering::SeqCst);

        Ok(())
    }
}

/// Input functions used in communicating with REPL shell
pub trait ReplShellInputReader: Send {
    /// Reader accessor (implements [`Read`], used to read input)
    ///
    /// # Returns
    ///
    /// [`BufRead`] object
    ///
    fn reader(&self) -> &Option<Arc<Mutex<Box<dyn BufRead + Send>>>>;

    /// Channel receiver accessor for incoming text lines from line reader thread
    ///
    /// # Returns
    ///
    /// The respective [`Receiver`]
    ///
    fn channel_receiver(&self) -> &Receiver<io::Result<String>>;

    /// Prompt recently displayed accessor/mutator
    ///
    /// # Returns
    ///
    /// [`AtomicBool`] value
    ///
    fn prompted_toggle(&mut self) -> &mut Arc<AtomicBool>;

    /// Return copy of TTY echo disable state (to be able to control whether keyed input is shown on the terminal - next line only)
    ///
    /// # Returns
    ///
    /// A mutex around a boolean to control the TTY echoing.
    ///
    fn clone_disable_tty_echo(&self) -> Arc<Mutex<bool>>;

    /// Clone message channel sender (used by line reader thread to send new message lines)
    ///
    /// # Returns
    ///
    /// The channel sender used to queue lines read from console.
    ///
    fn clone_channel_sender(&self) -> Sender<io::Result<String>>;

    /// Initial input lines to use upon shell readiness
    ///
    /// # Returns
    ///
    /// Vector ([`VecDeque`]) of initial input lines to process
    ///
    fn initial_lines(&mut self) -> &mut VecDeque<String>;

    /// Spawn a thread to perform (blocking) reads (queue resulting lines)
    fn spawn_line_reader(&self) {
        let disable_tty_echo = self.clone_disable_tty_echo();
        let channel_send = self.clone_channel_sender();
        let reader = self.reader().clone();
        #[cfg(test)]
        let test_input_lines = self.test_input_lines();
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
                #[cfg(test)]
                if _lines_read_idx >= test_input_lines {
                    break;
                }
                process_next_line(&reader, is_password_input, &channel_send);
                _lines_read_idx += 1;
            }
        });
    }

    /// Non-blocking call to retrieve next queued input line
    ///
    /// Returns `Ok(None)` if no lines queued
    ///
    fn next_line(&mut self) -> Result<Option<String>, AppError> {
        // Prefer initial lines over IO (when shell is ready for next input)
        if !self.initial_lines().is_empty()
            && self
                .prompted_toggle()
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Ok(Some(format!(
                "{}\n",
                self.initial_lines().pop_front().unwrap()
            )));
        }

        // Return queued input line (if avail)
        match self.channel_receiver().try_recv() {
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

    /// Shell input lines total (for testing)
    fn test_input_lines(&self) -> i32;
}

/// Blocking read for next input line, which will be sent to channel for processing
///
/// # Arguments
///
/// * `reader` - A [`BufRead`] to use in reading shell input. STDIN used if not supplied
/// * `is_password_input` - If true, don't echo input to console
/// * `channel_sender` - Line read results sent to this channel
///
fn process_next_line(
    reader: &Option<Arc<Mutex<Box<dyn BufRead + Send>>>>,
    is_password_input: bool,
    channel_sender: &Sender<io::Result<String>>,
) {
    let read_result = match is_password_input {
        true => match reader {
            Some(reader) => {
                rpassword::read_password_from_bufread(reader.lock().unwrap().deref_mut())
            }
            None => rpassword::read_password(),
        },
        false => {
            let mut line: String = String::new();
            let readline_result = match reader {
                Some(reader) => reader.lock().unwrap().deref_mut().read_line(&mut line),
                None => io::stdin().lock().read_line(&mut line),
            };
            match readline_result {
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

/// Shell output writer ([`ReplShellOutputWriter`]) using [`ChannelWriter`] as underlying writer
pub struct ChannelShellOutputWriter {
    /// Writer accessor (implements [`Write`], used to write output)
    writer: Option<Box<dyn Write + Send>>,
    /// Shell prompt status toggler accessor. Indicates whether prompt has currently been written.
    prompted_toggle: Arc<AtomicBool>,
}

impl ChannelShellOutputWriter {
    /// ShellOutputWriter constructor
    ///
    /// # Arguments
    ///
    /// * `channel_sender` - A [`Sender`] object used to send shell output
    ///
    /// # Returns
    ///
    /// A newly constructed [`ChannelShellOutputWriter`] object.
    ///
    pub fn new(channel_sender: Sender<Vec<u8>>) -> Self {
        let channel_writer: Box<dyn Write + Send> = Box::new(ChannelWriter::new(channel_sender));
        Self {
            writer: Some(channel_writer),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Write for ChannelShellOutputWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let writer = self.writer.as_mut().unwrap();
        writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let writer = self.writer.as_mut().unwrap();
        writer.flush()
    }
}

unsafe impl Send for ChannelShellOutputWriter {}

impl ReplShellOutputWriter for ChannelShellOutputWriter {
    fn prompted_toggle(&self) -> &Arc<AtomicBool> {
        &self.prompted_toggle
    }

    fn writer(&mut self) -> &mut Option<Box<dyn Write + Send>> {
        &mut self.writer
    }
}

/// Shell input reader ([`ReplShellInputReader`]) using [`ChannelReader`] as underlying reader
pub struct ChannelShellInputReader {
    /// Reader accessor (implements [`Read`], used to read input)
    reader: Option<Arc<Mutex<Box<dyn BufRead + Send>>>>,
    /// TTY echo disable state (to be able to control whether keyed input is shown on the terminal - next line only)
    disable_tty_echo: Arc<Mutex<bool>>,
    /// Channel sender for outgoing text lines. Used by line reader thread to send new lines)
    channel_send: Sender<io::Result<String>>,
    /// Channel receiver for incoming text lines sent from line reader thread
    channel_recv: Receiver<io::Result<String>>,
    /// Initial input lines to use upon shell readiness
    initial_lines: VecDeque<String>,
    /// Prompt recently displayed accessor/mutator
    prompted_toggle: Arc<AtomicBool>,
    // (for testing)
    test_input_lines: i32,
}

impl ChannelShellInputReader {
    /// ChannelShellInputReader constructor
    ///
    /// # Arguments
    ///
    /// * `channel_receiver` - A [`Receiver`] used to read input to send to REPL shell
    /// * `initial_lines` - A vector of initial input lines to use upon shell readiness
    /// * `prompted_toggle` - Shell output prompt toggler
    ///
    /// # Returns
    ///
    /// A newly constructed [`ChannelShellInputReader`] object.
    ///
    pub fn new(
        channel_receiver: Receiver<Vec<u8>>,
        initial_lines: &[String],
        prompted_toggle: &Arc<AtomicBool>,
    ) -> Self {
        let channel_reader: Box<dyn BufRead + Send> =
            Box::new(ChannelReader::new(channel_receiver));
        let (send, recv) = mpsc::channel();
        ChannelShellInputReader {
            reader: Some(Arc::new(Mutex::new(channel_reader))),
            disable_tty_echo: Arc::new(Mutex::new(false)),
            channel_send: send,
            channel_recv: recv,
            initial_lines: VecDeque::from(initial_lines.to_vec()),
            prompted_toggle: prompted_toggle.clone(),
            test_input_lines: 0,
        }
    }
}

unsafe impl Send for ChannelShellInputReader {}

impl ReplShellInputReader for ChannelShellInputReader {
    fn reader(&self) -> &Option<Arc<Mutex<Box<dyn BufRead + Send>>>> {
        &self.reader
    }
    fn channel_receiver(&self) -> &Receiver<io::Result<String>> {
        &self.channel_recv
    }
    fn prompted_toggle(&mut self) -> &mut Arc<AtomicBool> {
        &mut self.prompted_toggle
    }
    fn clone_disable_tty_echo(&self) -> Arc<Mutex<bool>> {
        self.disable_tty_echo.clone()
    }
    fn clone_channel_sender(&self) -> Sender<io::Result<String>> {
        self.channel_send.clone()
    }
    fn initial_lines(&mut self) -> &mut VecDeque<String> {
        &mut self.initial_lines
    }
    fn test_input_lines(&self) -> i32 {
        self.test_input_lines
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::{mock, predicate};
    use std::io::{Cursor, Read};
    use std::sync::mpsc::{self, TryRecvError};
    use std::thread;
    use std::time::Duration;

    use crate::testutils::ChannelWriter;

    // mocks/dummies/...
    // =================

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

    mock! {
        pub ShellInputReader {}
        impl ReplShellInputReader for ShellInputReader {
            fn reader(&self) -> &Option<Arc<Mutex<Box<dyn BufRead + Send>>>>;
            fn channel_receiver(&self) -> &Receiver<io::Result<String>>;
            fn prompted_toggle(&mut self) -> &mut Arc<AtomicBool>;
            fn clone_disable_tty_echo(&self) -> Arc<Mutex<bool>>;
            fn clone_channel_sender(&self) -> Sender<io::Result<String>>;
            fn initial_lines(&mut self) -> &mut VecDeque<String>;
            fn spawn_line_reader(&self);
            fn next_line(&mut self) -> Result<Option<String>, AppError>;
            fn test_input_lines(&self) -> i32;
        }
        unsafe impl Send for ShellInputReader {}
    }

    mock! {
        pub ShellOutputWriter {}
        impl ReplShellOutputWriter for ShellOutputWriter {
            fn prompted_toggle(&self) -> &Arc<AtomicBool>;
            fn writer(&mut self) -> &mut Option<Box<dyn Write + Send>>;
            fn write_shell_prompt(&mut self, include_welcome: bool) -> Result<(), AppError>;
        }
        impl Write for ShellOutputWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
            fn flush(&mut self) -> io::Result<()>;
        }
        unsafe impl Send for ShellOutputWriter {}
    }

    pub struct TestShellOutputWriter {
        writer: Option<Box<dyn Write + Send>>,
        prompted_toggle: Arc<AtomicBool>,
    }

    impl TestShellOutputWriter {
        pub fn new(writer: Option<Box<dyn Write + Send>>) -> Self {
            Self {
                writer,
                prompted_toggle: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Write for TestShellOutputWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let writer = self.writer.as_mut().unwrap();
            writer.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            let writer = self.writer.as_mut().unwrap();
            writer.flush()
        }
    }

    impl ReplShellOutputWriter for TestShellOutputWriter {
        fn prompted_toggle(&self) -> &Arc<AtomicBool> {
            &self.prompted_toggle
        }

        fn writer(&mut self) -> &mut Option<Box<dyn Write + Send>> {
            &mut self.writer
        }
    }

    pub struct TestShellInputReader {
        reader: Option<Arc<Mutex<Box<dyn BufRead + Send>>>>,
        disable_tty_echo: Arc<Mutex<bool>>,
        channel_send: Sender<io::Result<String>>,
        channel_recv: Receiver<io::Result<String>>,
        initial_lines: VecDeque<String>,
        prompted_toggle: Arc<AtomicBool>,
        test_input_lines: i32,
    }

    impl TestShellInputReader {
        pub fn new(
            reader: Option<Arc<Mutex<Box<dyn BufRead + Send>>>>,
            initial_lines: &[String],
            prompted_toggle: &Arc<AtomicBool>,
        ) -> TestShellInputReader {
            let (send, recv) = mpsc::channel();
            TestShellInputReader {
                reader,
                disable_tty_echo: Arc::new(Mutex::new(false)),
                channel_send: send,
                channel_recv: recv,
                initial_lines: VecDeque::from(initial_lines.to_vec()),
                prompted_toggle: prompted_toggle.clone(),
                test_input_lines: 0,
            }
        }
    }

    impl ReplShellInputReader for TestShellInputReader {
        fn reader(&self) -> &Option<Arc<Mutex<Box<dyn BufRead + Send>>>> {
            &self.reader
        }
        fn channel_receiver(&self) -> &Receiver<io::Result<String>> {
            &self.channel_recv
        }
        fn prompted_toggle(&mut self) -> &mut Arc<AtomicBool> {
            &mut self.prompted_toggle
        }
        fn clone_disable_tty_echo(&self) -> Arc<Mutex<bool>> {
            self.disable_tty_echo.clone()
        }
        fn clone_channel_sender(&self) -> Sender<io::Result<String>> {
            self.channel_send.clone()
        }
        fn initial_lines(&mut self) -> &mut VecDeque<String> {
            &mut self.initial_lines
        }
        fn test_input_lines(&self) -> i32 {
            self.test_input_lines
        }
    }

    //  tests
    //  =====

    #[test]
    fn replshellout_default_write_shell_prompt_with_welcome() {
        let expected_output = format!(
            "{} v{} {}\n{}",
            SHELL_MSG_APP_TITLE, SHELL_MSG_APP_VERSION, SHELL_MSG_APP_HELP, SHELL_PROMPT
        )
        .into_bytes();

        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut shell_output = TestShellOutputWriter {
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
    fn replshellout_default_write_shell_prompt_with_welcome_where_1st_write_fails() {
        let mut shell_writer = MockWriter::new();
        shell_writer
            .expect_write_all()
            .with(predicate::always())
            .times(1)
            .returning(|_| Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
        shell_writer.expect_flush().never();

        let mut shell_output = TestShellOutputWriter {
            writer: Some(Box::new(shell_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }

        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst))
    }

    #[test]
    fn replshellout_default_write_shell_prompt_with_welcome_where_2nd_write_fails() {
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

        let mut shell_output = TestShellOutputWriter {
            writer: Some(Box::new(shell_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }

        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst))
    }

    #[test]
    fn replshellout_default_write_shell_prompt_with_welcome_where_flush_fails() {
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

        let mut shell_output = TestShellOutputWriter {
            writer: Some(Box::new(shell_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if shell_output.write_shell_prompt(true).is_ok() {
            panic!("Unexpected successful result");
        }

        assert!(!shell_output.prompted_toggle.load(Ordering::SeqCst))
    }

    #[test]
    fn replshellout_default_write_shell_prompt_without_welcome() {
        let expected_output = SHELL_PROMPT.to_string().into_bytes();

        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut shell_output = TestShellOutputWriter {
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

    fn replshellinp_default_process_next_line_when_no_lines(is_password_input: bool) {
        let cursor: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(Cursor::new(vec![]))));
        let lines_channel = mpsc::channel();

        process_next_line(&Some(cursor), is_password_input, &lines_channel.0);

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
        assert!(actual_lines.first().unwrap().is_empty());
    }

    #[test]
    fn replshellinp_default_process_next_line_when_non_pwd_input_and_no_lines() {
        replshellinp_default_process_next_line_when_no_lines(false);
    }

    fn replshellinp_default_process_next_line_when_2_lines(is_password_input: bool) {
        let cursor: Arc<Mutex<Box<dyn BufRead + Send>>> = Arc::new(Mutex::new(Box::new(
            Cursor::new("line1\nline2\n".as_bytes().to_vec()),
        )));
        let lines_channel = mpsc::channel();

        process_next_line(&Some(cursor.clone()), is_password_input, &lines_channel.0);
        process_next_line(&Some(cursor), is_password_input, &lines_channel.0);

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
    fn replshellinp_default_process_next_line_when_non_pwd_input_and_2_lines() {
        replshellinp_default_process_next_line_when_2_lines(false);
    }

    #[test]
    fn replshellinp_default_process_next_line_when_eof_read_error() {
        let mut reader = Box::new(MockReader::new());
        reader
            .expect_read_line()
            .with(predicate::always())
            .times(1)
            .returning(|_| Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
        let reader: Box<dyn BufRead + Send> = Box::new(reader);

        let lines_channel = mpsc::channel();

        process_next_line(&Some(Arc::new(Mutex::new(reader))), false, &lines_channel.0);

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
    fn replshellinp_default_spawn_line_reader_when_2_lines() {
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> = Arc::new(Mutex::new(Box::new(
            Cursor::new("line1\nline2\n".as_bytes().to_vec()),
        )));
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let mut input_reader =
            TestShellInputReader::new(Some(reader), vec![].as_slice(), &prompted_toggle);
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
    fn replshellinp_default_spawn_line_reader_when_2_lines_for_channel_reader() {
        let (reader_send, reader_recv) = mpsc::channel();
        reader_send.send("line1".as_bytes().to_vec()).unwrap();
        reader_send.send("line2".as_bytes().to_vec()).unwrap();

        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let mut input_reader = ChannelShellInputReader::new(reader_recv, &[], &prompted_toggle);
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
    fn replshellinp_default_next_line_when_no_lines() {
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(Cursor::new(vec![]))));
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec![];

        let mut input_reader =
            TestShellInputReader::new(Some(reader), initial_lines.as_slice(), &prompted_toggle);

        match input_reader.next_line() {
            Ok(line) => {
                if let Some(line_val) = line {
                    panic!("Unexpected line received: line={}", &line_val);
                }
            }
            Err(err) => panic!("Unexpected next line result: err={:?}", &err),
        }
    }

    #[test]
    fn replshellinp_default_next_line_when_2_lines() {
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(Cursor::new(vec![]))));
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec![];

        let mut input_reader =
            TestShellInputReader::new(Some(reader), initial_lines.as_slice(), &prompted_toggle);

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
    fn replshellinp_default_next_line_when_interleaved_initial_and_channel_lines() {
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(Cursor::new(vec![]))));
        let prompted_toggle = Arc::new(AtomicBool::new(false));
        let initial_lines = vec!["init_line1".to_string(), "init_line2".to_string()];

        let mut input_reader =
            TestShellInputReader::new(Some(reader), initial_lines.as_slice(), &prompted_toggle);

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
    fn replshellinp_default_next_line_when_io_error_line() {
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(Cursor::new(vec![]))));
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec![];

        let mut input_reader =
            TestShellInputReader::new(Some(reader), initial_lines.as_slice(), &prompted_toggle);

        let line_channel_sender = input_reader.clone_channel_sender();
        line_channel_sender
            .send(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
            .unwrap();

        if let Ok(line) = input_reader.next_line() {
            panic!("Unexpected successful received line: line={:?}", &line);
        }
    }

    #[test]
    fn chanshellout_new() {
        let (iosrc_channel_send, _iosrc_channel_recv) = mpsc::channel();
        let shell_output = ChannelShellOutputWriter::new(iosrc_channel_send);

        assert!(shell_output.writer.is_some());
        assert!(!shell_output.prompted_toggle().load(Ordering::SeqCst));
    }

    #[test]
    fn chanshellout_prompted_toggle() {
        let (iosrc_channel_send, _iosrc_channel_recv) = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: iosrc_channel_send,
        };

        let shell_output = ChannelShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(true)),
        };

        assert!(shell_output
            .prompted_toggle()
            .as_ref()
            .load(Ordering::SeqCst));
    }

    #[test]
    fn shellout_writer() {
        let (iosrc_channel_send, iosrc_channel_recv) = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: iosrc_channel_send,
        };

        let mut shell_output = ChannelShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(true)),
        };

        let writer = shell_output.writer().as_mut();
        assert!(writer.is_some());

        let write_result = writer.unwrap().write_all("hi".as_bytes());
        if let Err(err) = write_result {
            panic!("Unexpected write result: err={:?}", &err);
        }

        let mut output_data: Vec<u8> = vec![];
        loop {
            let output_result = iosrc_channel_recv.try_recv();
            if let Err(err) = output_result {
                if let TryRecvError::Empty = err {
                    break;
                }
                panic!("Unexpected output result: err={:?}", &err);
            }
            output_data.append(&mut output_result.unwrap());
        }

        assert_eq!(output_data, "hi".as_bytes());
    }

    #[test]
    fn shellout_default_write_and_flush() {
        let expected_output = "hi".as_bytes();

        let (iosrc_channel_send, iosrc_channel_recv) = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: iosrc_channel_send,
        };

        let mut shell_output = ChannelShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(true)),
        };

        if let Err(err) = shell_output.write(expected_output) {
            panic!("Unexpected write result: err={:?}", &err);
        }

        if let Err(err) = shell_output.flush() {
            panic!("Unexpected flush result: err={:?}", &err);
        }

        let mut output_data: Vec<u8> = vec![];

        loop {
            let output_result = iosrc_channel_recv.try_recv();
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
    fn shellinp_new() {
        let (_iosrc_channel_send, iosrc_channel_recv) = mpsc::channel();
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec!["line1".to_string(), "line2".to_string()];

        let input_reader = ChannelShellInputReader::new(
            iosrc_channel_recv,
            initial_lines.as_slice(),
            &prompted_toggle,
        );

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

    #[test]
    fn shellinp_accessors() {
        let (iosrc_channel_send, iosrc_channel_recv) = mpsc::channel();
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(ChannelReader::new(iosrc_channel_recv))));
        let (send, recv) = mpsc::channel();
        let mut input_reader = ChannelShellInputReader {
            reader: Some(reader.clone()),
            disable_tty_echo: Arc::new(Mutex::new(true)),
            channel_send: send,
            channel_recv: recv,
            initial_lines: VecDeque::new(),
            prompted_toggle: Arc::new(AtomicBool::new(true)),
            test_input_lines: 0,
        };

        iosrc_channel_send.send(vec![b'h', b'i']).unwrap();

        let reader = input_reader.reader();
        let mut read_line = String::new();
        let read_result = reader
            .clone()
            .unwrap()
            .lock()
            .unwrap()
            .read_line(&mut read_line);
        assert!(read_result.is_ok());
        assert_eq!(read_line, "hi\n".to_string());

        let channel_recv = input_reader.channel_receiver();
        let channel_send = input_reader.clone_channel_sender();
        if let Err(err) = channel_send.send(Ok("hi".to_string())) {
            panic!("Unexpected channel send result: err={:?}", &err);
        }
        match channel_recv.try_recv() {
            Ok(msg_result) => match msg_result {
                Ok(msg) => assert_eq!(msg, "hi"),
                Err(err) => panic!("Unexpected channel recv message result: err={:?}", &err),
            },
            Err(err) => panic!("Unexpected channel recv result: err={:?}", &err),
        }

        assert!(input_reader.prompted_toggle().load(Ordering::SeqCst));

        assert!(*input_reader.clone_disable_tty_echo().lock().unwrap());

        assert!(input_reader.initial_lines().is_empty());

        assert_eq!(input_reader.test_input_lines(), 0);
    }
}
