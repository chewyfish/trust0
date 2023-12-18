use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum AppError {
    AddrParse(std::net::AddrParseError),
    General(String),
    GenWithCode(u16),
    GenWithCodeAndErr(u16, Box<dyn Error + Send + Sync + 'static>),
    GenWithCodeAndMsg(u16, String),
    GenWithCodeAndMsgAndErr(u16, String, Box<dyn Error + Send + Sync + 'static>),
    GenWithErr(Box<dyn Error + Send + Sync + 'static>),
    GenWithMsgAndErr(String, Box<dyn Error + Send + Sync + 'static>),
    Io(io::Error),
    IoWithMsg(String, io::Error),
    Tls(rustls::Error),
    WouldBlock,
    StreamEOF,
}

impl AppError {
    /// Return intrinsic error code (if avail)
    pub fn get_code(&self) -> Option<u16> {
        match self {
            AppError::GenWithCode(code) => Some(*code),
            AppError::GenWithCodeAndErr(code, _) => Some(*code),
            AppError::GenWithCodeAndMsg(code, _) => Some(*code),
            AppError::GenWithCodeAndMsgAndErr(code, _, _) => Some(*code),
            _ => None,
        }
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            AppError::AddrParse(ref err) => err.fmt(f),
            AppError::General(ref msg) => msg.fmt(f),
            AppError::GenWithCode(code) => write!(f, "Response: code={}", code),
            AppError::GenWithCodeAndErr(code, ref err) => {
                write!(f, "Response: code={}, err={:?}", code, err)
            }
            AppError::GenWithCodeAndMsg(code, ref msg) => {
                write!(f, "Response: code={}, msg={}", code, msg)
            }
            AppError::GenWithCodeAndMsgAndErr(code, ref msg, ref err) => {
                write!(f, "Response: code={}, msg={}, err={:?}", code, msg, err)
            }
            AppError::GenWithErr(ref err) => err.fmt(f),
            AppError::GenWithMsgAndErr(ref msg, ref err) => {
                write!(f, "Error: msg={}, err={:?}", msg, err)
            }
            AppError::Io(ref err) => err.fmt(f),
            AppError::IoWithMsg(ref msg, ref err) => {
                write!(f, "IO Error: msg={}, err={:?}", msg, err)
            }
            AppError::Tls(ref err) => err.fmt(f),
            AppError::WouldBlock => write!(f, "WouldBlock Error"),
            AppError::StreamEOF => write!(f, "StreamEOF Error"),
        }
    }
}

impl Error for AppError {}

impl From<Box<dyn Error + Send + Sync + 'static>> for AppError {
    fn from(err: Box<dyn Error + Send + Sync + 'static>) -> AppError {
        AppError::GenWithErr(err)
    }
}
impl From<io::Error> for AppError {
    fn from(err: io::Error) -> AppError {
        AppError::Io(err)
    }
}
impl From<rustls::Error> for AppError {
    fn from(err: rustls::Error) -> AppError {
        AppError::Tls(err)
    }
}
impl From<std::net::AddrParseError> for AppError {
    fn from(err: std::net::AddrParseError) -> AppError {
        AppError::AddrParse(err)
    }
}
