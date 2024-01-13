use std::io::{self, stdin, stdout, BufRead, Write};

use trust0_common::error::AppError;

const APP_TITLE: &str = "Trust0 SDP Password Hasher";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(windows)]
pub const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
pub const LINE_ENDING: &str = "\n";

/// Handles console input, output
pub struct Console {
    reader: Box<dyn BufRead>,
    writer: Box<dyn Write>,
}

impl Console {
    /// Console constructor
    /// If reader or writer object is not given, will use STDIN and STDOUT respectively
    pub fn new(reader: Option<Box<dyn BufRead>>, writer: Option<Box<dyn Write>>) -> Self {
        Self {
            reader: reader.unwrap_or(Box::new(stdin().lock())),
            writer: writer.unwrap_or(Box::new(stdout())),
        }
    }
}

impl ConsoleIO for Console {
    fn write_title(&mut self) -> Result<(), AppError> {
        self.write_data(
            format!("{} v{}{}", APP_TITLE, APP_VERSION, LINE_ENDING).as_bytes(),
            true,
        )
    }

    fn write_data(&mut self, data: &[u8], flush_output: bool) -> Result<(), AppError> {
        self.write_all(data).map_err(|err| {
            AppError::GenWithMsgAndErr("Error writing data".to_string(), Box::new(err))
        })?;
        if flush_output {
            self.flush().map_err(|err| {
                AppError::GenWithMsgAndErr("Error flushing data".to_string(), Box::new(err))
            })
        } else {
            Ok(())
        }
    }

    fn read_next_line(&mut self, is_password_input: bool) -> Result<String, AppError> {
        match is_password_input {
            true => match rpassword::read_password() {
                Ok(line) => Ok(line),
                Err(err) => Err(AppError::GenWithMsgAndErr(
                    "Error reading console (pwd) line".to_string(),
                    Box::new(err),
                )),
            },
            false => {
                let mut line: String = String::new();
                match self.reader.read_line(&mut line) {
                    Ok(_) => Ok(line.trim_end().to_string()),
                    Err(err) => Err(AppError::GenWithMsgAndErr(
                        "Error reading console line".to_string(),
                        Box::new(err),
                    )),
                }
            }
        }
    }
}

pub trait ConsoleIO {
    /// Display application title
    fn write_title(&mut self) -> Result<(), AppError>;

    /// Write content
    fn write_data(&mut self, data: &[u8], flush_output: bool) -> Result<(), AppError>;

    /// Blocking read for next input line, which will be sent to channel for processing
    fn read_next_line(&mut self, is_password_input: bool) -> Result<String, AppError>;
}

impl Write for Console {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use std::io::Cursor;
    use std::sync::mpsc;
    use std::sync::mpsc::TryRecvError;
    use trust0_common::testutils::ChannelWriter;

    #[test]
    fn console_new() {
        let output_channel = mpsc::channel();
        let reader: Box<dyn BufRead> = Box::new(Cursor::new(vec![]));
        let writer: Box<dyn Write> = Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        });

        let _ = Console::new(None, None);
        let _ = Console::new(Some(reader), Some(writer));
    }

    #[test]
    fn console_write_title() {
        let output_channel = mpsc::channel();
        let reader: Box<dyn BufRead> = Box::new(Cursor::new(vec![]));
        let writer: Box<dyn Write> = Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        });
        let mut console = Console { reader, writer };

        if let Err(err) = console.write_title() {
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

        let expected_output = format!("{} v{}{}", APP_TITLE, APP_VERSION, LINE_ENDING).into_bytes();

        assert_eq!(output_data, expected_output);
    }

    #[test]
    fn console_read_next_line_when_2_lines_and_non_pwd_input() {
        let output_channel = mpsc::channel();
        let reader: Box<dyn BufRead> = Box::new(Cursor::new("line1\nline2\n".as_bytes().to_vec()));
        let writer: Box<dyn Write> = Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        });
        let mut console = Console { reader, writer };

        let mut actual_lines = vec![];
        loop {
            match console.read_next_line(false) {
                Ok(line) => {
                    if line.is_empty() {
                        break;
                    }
                    actual_lines.push(line)
                }
                Err(err) => panic!(
                    "Unexpected line result: recvd={:?}, err={:?}",
                    &actual_lines, &err
                ),
            }
        }

        assert_eq!(actual_lines.len(), 2);
        assert_eq!(actual_lines, vec!["line1", "line2"]);
    }
}
