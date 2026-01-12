use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use trust0_common::client::replshell_io::{ReplShellInputReader, ReplShellOutputWriter};
use trust0_common::error::AppError;

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
    /// ShellOutputWriter constructor
    ///
    /// # Arguments
    ///
    /// * `writer` - A [`Write`] object used to send shell output. If None, will use STDOUT
    ///
    /// # Returns
    ///
    /// A newly constructed [`ShellOutputWriter`] object.
    ///
    pub fn new(writer: Option<Box<dyn Write + Send>>) -> Self {
        Self {
            writer: writer.or(Some(Box::new(io::stdout()))),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Write for ShellOutputWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.as_mut().unwrap().flush()
    }
}

impl ReplShellOutputWriter for ShellOutputWriter {
    fn prompted_toggle(&self) -> &Arc<AtomicBool> {
        &self.prompted_toggle
    }

    fn writer(&mut self) -> &mut Option<Box<dyn Write + Send>> {
        &mut self.writer
    }
}

/// Handles REPL shell's input
pub struct ShellInputReader {
    /// Input reader
    reader: Option<Arc<Mutex<Box<dyn BufRead + Send>>>>,
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
}

impl ShellInputReader {
    /// ShellInputReader constructor
    ///
    /// # Arguments
    ///
    /// * `reader` - A [`BufRead`] used to read input. If None, will use STDIN
    /// * `initial_lines` - A vector of initial input lines to use upon shell readiness
    /// * `prompted_toggle` - Shell output prompt toggler
    ///
    /// # Returns
    ///
    /// A newly constructed [`ShellInputReader`] object.
    ///
    pub fn new(
        reader: Option<Box<dyn BufRead + Send>>,
        initial_lines: &[String],
        prompted_toggle: &Arc<AtomicBool>,
    ) -> Self {
        let (send, recv) = mpsc::channel();

        ShellInputReader {
            reader: reader.map(|r| Arc::new(Mutex::new(r))),
            disable_tty_echo: Arc::new(Mutex::new(false)),
            channel_send: send,
            channel_recv: recv,
            initial_lines: VecDeque::from(initial_lines.to_vec()),
            prompted_toggle: prompted_toggle.clone(),
        }
    }
}

unsafe impl Send for ShellInputReader {}

impl ReplShellInputReader for ShellInputReader {
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
        0
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::mock;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::TryRecvError;
    use trust0_common::testutils::ChannelWriter;

    // mocks, dummies, ...
    // ===================

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
    fn shellout_prompted_toggle() {
        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let shell_output = ShellOutputWriter {
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
        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        let writer = shell_output.writer().as_mut();
        assert!(writer.is_some());

        let write_result = writer.unwrap().write_all("hi".as_bytes());
        if let Err(err) = write_result {
            panic!("Unexpected write result: err={:?}", &err);
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

        assert_eq!(output_data, "hi".as_bytes());
    }

    #[test]
    fn shellout_default_write_and_flush() {
        let expected_output = "hi".as_bytes();

        let output_channel = mpsc::channel();
        let channel_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut shell_output = ShellOutputWriter {
            writer: Some(Box::new(channel_writer)),
            prompted_toggle: Arc::new(AtomicBool::new(false)),
        };

        if let Err(err) = shell_output.write(expected_output) {
            panic!("Unexpected write result: err={:?}", &err);
        }

        if let Err(err) = shell_output.flush() {
            panic!("Unexpected flush result: err={:?}", &err);
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
    fn shellinp_new() {
        let reader: Box<dyn BufRead + Send> = Box::new(Cursor::new(vec![]));
        let prompted_toggle = Arc::new(AtomicBool::new(true));
        let initial_lines = vec!["line1".to_string(), "line2".to_string()];

        let input_reader =
            ShellInputReader::new(Some(reader), initial_lines.as_slice(), &prompted_toggle);

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
        let reader: Arc<Mutex<Box<dyn BufRead + Send>>> =
            Arc::new(Mutex::new(Box::new(Cursor::new("hi".as_bytes().to_vec()))));
        let (send, recv) = mpsc::channel();
        let mut input_reader = ShellInputReader {
            reader: Some(reader.clone()),
            disable_tty_echo: Arc::new(Mutex::new(true)),
            channel_send: send,
            channel_recv: recv,
            initial_lines: VecDeque::from(vec!["hi2".to_string()]),
            prompted_toggle: Arc::new(AtomicBool::new(true)),
        };

        let reader = input_reader.reader();
        let mut read_line = String::new();
        let read_result = reader
            .clone()
            .unwrap()
            .lock()
            .unwrap()
            .read_line(&mut read_line);
        assert!(read_result.is_ok());
        assert_eq!(read_line, "hi".to_string());

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

        assert_eq!(
            input_reader.initial_lines(),
            &VecDeque::from(vec!["hi2".to_string()])
        );

        assert_eq!(input_reader.test_input_lines(), 0);
    }
}
