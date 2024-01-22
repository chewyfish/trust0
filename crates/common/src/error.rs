use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

/// Sanctioned error type used across workspace
#[derive(Debug)]
pub enum AppError {
    /// Address parse error
    AddrParse(std::net::AddrParseError),
    /// Error containing a message
    General(String),
    /// Error representing by a code (number)
    GenWithCode(u16),
    /// Error with a code and an [`Error`] object
    GenWithCodeAndErr(u16, Box<dyn Error + Send + Sync + 'static>),
    /// Error with a code and a message
    GenWithCodeAndMsg(u16, String),
    /// Error with a code, message and an [`Error`] object
    GenWithCodeAndMsgAndErr(u16, String, Box<dyn Error + Send + Sync + 'static>),
    /// Error containing an [`Error`] object
    GenWithErr(Box<dyn Error + Send + Sync + 'static>),
    /// Error with a message and an [`Error`] object
    GenWithMsgAndErr(String, Box<dyn Error + Send + Sync + 'static>),
    /// IO error
    Io(io::Error),
    /// IO error with a message
    IoWithMsg(String, io::Error),
    /// TLS-related error
    Tls(rustls::Error),
    /// Indicates IO would block error
    WouldBlock,
    /// Indicates a (TCP) stream EOF
    StreamEOF,
}

impl AppError {
    /// Return intrinsic error code (if avail)
    ///
    /// # Returns
    ///
    /// A code for this error. If not appropriate for this error type, returns `None`.
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

/// Unit tests
#[cfg(test)]
mod test {
    use super::*;
    use AppError as AE;

    fn assert_error_code(error: &AppError, code: u16) {
        assert!(error.get_code().is_some());
        assert_eq!(error.get_code().unwrap(), code);
    }

    fn assert_formatted_debug(error: &AppError, expected_str: &str) {
        assert_eq!(format!("{:?}", &error), expected_str.to_string());
    }

    fn assert_formatted_display(error: &AppError, expected_str: &str) {
        assert_eq!(error.to_string(), expected_str.to_string());
    }

    #[test]
    fn apperror_get_code() {
        let bad_addr_parse: Result<std::net::IpAddr, std::net::AddrParseError> =
            "127.0.0.1:8080".parse();
        let addr_parse_err = bad_addr_parse.err().unwrap();
        assert!(AE::AddrParse(addr_parse_err.clone()).get_code().is_none());
        assert!(AE::General("g1".to_string()).get_code().is_none());
        assert_error_code(&AE::GenWithCode(111), 111);
        assert_error_code(
            &AE::GenWithCodeAndErr(112, Box::new(addr_parse_err.clone())),
            112,
        );
        assert_error_code(&AE::GenWithCodeAndMsg(113, "gwcam1".to_string()), 113);
        assert_error_code(
            &AE::GenWithCodeAndMsgAndErr(
                114,
                "gwcamae1".to_string(),
                Box::new(addr_parse_err.clone()),
            ),
            114,
        );
        assert!(AE::GenWithErr(Box::new(addr_parse_err.clone()))
            .get_code()
            .is_none());
        assert!(
            AE::GenWithMsgAndErr("gwmae1".to_string(), Box::new(addr_parse_err.clone()))
                .get_code()
                .is_none()
        );
        assert!(AE::Io(io::Error::new(io::ErrorKind::Other, "ioe1"))
            .get_code()
            .is_none());
        assert!(AE::IoWithMsg(
            "iwm1".to_string(),
            io::Error::new(io::ErrorKind::Other, "ioe2")
        )
        .get_code()
        .is_none());
        assert!(AE::Tls(rustls::Error::General("re1".to_string()))
            .get_code()
            .is_none());
        assert!(AE::WouldBlock.get_code().is_none());
        assert!(AE::StreamEOF.get_code().is_none());
    }

    #[test]
    fn apperror_formatted_debug() {
        let bad_addr_parse: Result<std::net::IpAddr, std::net::AddrParseError> =
            "127.0.0.1:8080".parse();
        let addr_parse_err = bad_addr_parse.err().unwrap();
        assert_formatted_debug(
            &AE::AddrParse(addr_parse_err.clone()),
            "AddrParse(AddrParseError(Ip))",
        );
        assert_formatted_debug(&AE::General("g1".to_string()), "General(\"g1\")");
        assert_formatted_debug(&AE::GenWithCode(111), "GenWithCode(111)");
        assert_formatted_debug(
            &AE::GenWithCodeAndErr(112, Box::new(addr_parse_err.clone())),
            "GenWithCodeAndErr(112, AddrParseError(Ip))",
        );
        assert_formatted_debug(
            &AE::GenWithCodeAndMsg(113, "gwcam1".to_string()),
            "GenWithCodeAndMsg(113, \"gwcam1\")",
        );
        assert_formatted_debug(
            &AE::GenWithCodeAndMsgAndErr(
                114,
                "gwcamae1".to_string(),
                Box::new(addr_parse_err.clone()),
            ),
            "GenWithCodeAndMsgAndErr(114, \"gwcamae1\", AddrParseError(Ip))",
        );
        assert_formatted_debug(
            &AE::GenWithErr(Box::new(addr_parse_err.clone())),
            "GenWithErr(AddrParseError(Ip))",
        );
        assert_formatted_debug(
            &AE::GenWithMsgAndErr("gwmae1".to_string(), Box::new(addr_parse_err.clone())),
            "GenWithMsgAndErr(\"gwmae1\", AddrParseError(Ip))",
        );
        assert_formatted_debug(
            &AE::Io(io::Error::new(io::ErrorKind::Other, "ioe1")),
            "Io(Custom { kind: Other, error: \"ioe1\" })",
        );
        assert_formatted_debug(
            &AE::IoWithMsg(
                "iwm1".to_string(),
                io::Error::new(io::ErrorKind::Other, "ioe2"),
            ),
            "IoWithMsg(\"iwm1\", Custom { kind: Other, error: \"ioe2\" })",
        );
        assert_formatted_debug(
            &AE::Tls(rustls::Error::General("re1".to_string())),
            "Tls(General(\"re1\"))",
        );
        assert_formatted_debug(&AE::WouldBlock, "WouldBlock");
        assert_formatted_debug(&AE::StreamEOF, "StreamEOF");
    }

    #[test]
    fn apperror_formatted_display() {
        let bad_addr_parse: Result<std::net::IpAddr, std::net::AddrParseError> =
            "127.0.0.1:8080".parse();
        let addr_parse_err = bad_addr_parse.err().unwrap();
        assert_formatted_display(
            &AE::AddrParse(addr_parse_err.clone()),
            "invalid IP address syntax",
        );
        assert_formatted_display(&AE::General("g1".to_string()), "g1");
        assert_formatted_display(&AE::GenWithCode(111), "Response: code=111");
        assert_formatted_display(
            &AE::GenWithCodeAndErr(112, Box::new(addr_parse_err.clone())),
            "Response: code=112, err=AddrParseError(Ip)",
        );
        assert_formatted_display(
            &AE::GenWithCodeAndMsg(113, "gwcam1".to_string()),
            "Response: code=113, msg=gwcam1",
        );
        assert_formatted_display(
            &AE::GenWithCodeAndMsgAndErr(
                114,
                "gwcamae1".to_string(),
                Box::new(addr_parse_err.clone()),
            ),
            "Response: code=114, msg=gwcamae1, err=AddrParseError(Ip)",
        );
        assert_formatted_display(
            &AE::GenWithErr(Box::new(addr_parse_err.clone())),
            "invalid IP address syntax",
        );
        assert_formatted_display(
            &AE::GenWithMsgAndErr("gwmae1".to_string(), Box::new(addr_parse_err.clone())),
            "Error: msg=gwmae1, err=AddrParseError(Ip)",
        );
        assert_formatted_display(
            &AE::Io(io::Error::new(io::ErrorKind::Other, "ioe1")),
            "ioe1",
        );
        assert_formatted_display(
            &AE::IoWithMsg(
                "iwm1".to_string(),
                io::Error::new(io::ErrorKind::Other, "ioe2"),
            ),
            "IO Error: msg=iwm1, err=Custom { kind: Other, error: \"ioe2\" }",
        );
        assert_formatted_display(
            &AE::Tls(rustls::Error::General("re1".to_string())),
            "unexpected error: re1",
        );
        assert_formatted_display(&AE::WouldBlock, "WouldBlock Error");
        assert_formatted_display(&AE::StreamEOF, "StreamEOF Error");
    }

    #[test]
    fn apperror_from() {
        let bad_addr_parse: Result<std::net::IpAddr, std::net::AddrParseError> =
            "127.0.0.1:8080".parse();
        let error: Box<dyn Error + Send + Sync + 'static> = Box::new(bad_addr_parse.err().unwrap());
        let app_error = error.into();
        match app_error {
            AE::GenWithErr(_) => {}
            _ => panic!("Unexpected from result for Box<Error>: err={:?}", app_error),
        }

        let error = io::Error::new(io::ErrorKind::Other, "ioe2");
        let app_error = error.into();
        match app_error {
            AE::Io(_) => {}
            _ => panic!("Unexpected from result for io::Error: err={:?}", app_error),
        }

        let error = rustls::Error::General("re1".to_string());
        let app_error = error.into();
        match app_error {
            AE::Tls(_) => {}
            _ => panic!(
                "Unexpected from result for rustls::Error: err={:?}",
                app_error
            ),
        }

        let bad_addr_parse: Result<std::net::IpAddr, std::net::AddrParseError> =
            "127.0.0.1:8080".parse();
        let app_error = bad_addr_parse.err().unwrap().into();
        match app_error {
            AE::AddrParse(_) => {}
            _ => panic!(
                "Unexpected from result for AddrParseError: err={:?}",
                app_error
            ),
        }
    }
}
