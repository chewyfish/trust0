use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::Duration;
use std::{io, thread};

use anyhow::Result;
use rustls::StreamOwned;

use crate::error::AppError;
use crate::logging::error;
use crate::net::stream_utils;
use crate::net::stream_utils::StreamReaderWriter;
use crate::{control, target};

pub const READ_BLOCK_SIZE: usize = 1024;

/// Encapsulates key connection objects
pub type TlsClientConnection = StreamOwned<rustls::ClientConnection, TcpStream>;

/// Connection event message channel
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Request to close connection
    Closing,
    /// Connection closed event
    Closed,
    /// Request to send data on connection
    Write(Vec<u8>),
}

impl ConnectionEvent {
    /// Create multiple producer, single consumer message channel
    pub fn create_channel() -> (Sender<ConnectionEvent>, Receiver<ConnectionEvent>) {
        mpsc::channel()
    }
}

/// TLS server connection which has been initiated by the client.
pub struct Connection {
    /// Connection visitor pattern object
    visitor: Box<dyn ConnectionVisitor>,
    /// Corresponding TLS connection object
    tls_conn: Option<TlsClientConnection>,
    /// Corresponding TLS connection object (alternative version used in testing)
    #[allow(dead_code)]
    tls_conn_alt: Option<Box<dyn StreamReaderWriter>>,
    /// Corresponding TCP connection stream
    tcp_stream: Option<TcpStream>,
    /// Session connection addresses
    session_addrs: control::tls::message::ConnectionAddrs,
    /// Event message channel
    event_channel: (Sender<ConnectionEvent>, Receiver<ConnectionEvent>),
    /// Connection closed state value
    closed: bool,
}

impl Connection {
    /// Connection constructor
    ///
    /// # Arguments
    ///
    /// * `visitor` - Connection visitor pattern object
    /// * `tls_conn` - Corresponding TLS connection object
    /// * `session_addrs` - Address pair (client, gateway) used to denote session
    ///
    /// # Returns
    ///
    /// A [`Result`] of a newly constructed [`Connection`] object.
    /// Error is returned if there are issues cloning the TCP stream.
    ///
    pub fn new(
        mut visitor: Box<dyn ConnectionVisitor>,
        tls_conn: TlsClientConnection,
        session_addrs: &control::tls::message::ConnectionAddrs,
    ) -> Result<Self, AppError> {
        let event_channel = ConnectionEvent::create_channel();
        visitor.on_connected(&event_channel.0)?;

        let tcp_stream = stream_utils::clone_std_tcp_stream(&tls_conn.sock)?;

        Ok(Self {
            visitor,
            tls_conn: Some(tls_conn),
            tls_conn_alt: None,
            tcp_stream: Some(tcp_stream),
            session_addrs: session_addrs.clone(),
            event_channel,
            closed: false,
        })
    }

    /// Connection 'closed' state accessor
    ///
    /// # Returns
    ///
    /// Whether or not the connection is closed.
    ///
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Connection 'closed' state mutator
    ///
    /// # Arguments
    ///
    /// * `closed` - Connection closed state value to set for object's corresponding state attribute
    ///
    pub fn set_closed(&mut self, closed: bool) {
        self.closed = closed;
    }

    /// Connection 'tcp_stream' (immutable) accessor
    ///
    /// # Returns
    ///
    /// A reference to the TCP stream object. Assumes value is present, otherwise will panic.
    ///
    pub fn get_tcp_stream(&self) -> &TcpStream {
        self.tcp_stream.as_ref().unwrap()
    }

    /// Connection 'session_addrs' accessor
    ///
    /// # Returns
    ///
    /// A reference to the TLS session address pair (client, gateway)
    ///
    pub fn get_session_addrs(&self) -> &control::tls::message::ConnectionAddrs {
        &self.session_addrs
    }

    /// Get event channel sender
    ///
    /// # Returns
    ///
    /// A clone of the event message channel sender.
    ///
    pub fn clone_event_channel_sender(&self) -> Sender<ConnectionEvent> {
        self.event_channel.0.clone()
    }

    /// Poll connection events loop
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the connection processing loop.
    ///
    pub fn poll_connection(&mut self) -> Result<(), AppError> {
        loop {
            // Read connection data (if avail)
            if let Err(err) = self.read() {
                error(&target!(), &format!("{:?}", err));
            }

            // Polling cycle handler
            if let Err(err) = self.visitor.on_polling_cycle() {
                error(&target!(), &format!("{:?}", err));
            }

            // Poll connection event
            'EVENTS: loop {
                match self.event_channel.1.try_recv() {
                    // Handle write request
                    Ok(ConnectionEvent::Write(data)) => {
                        if let Err(err) = self.write(&data) {
                            error(&target!(), &format!("{:?}", err));
                        }
                    }

                    // Handle connection shutdown
                    Ok(ConnectionEvent::Closing) => {
                        if let Err(err) = self.shutdown() {
                            error(&target!(), &format!("{:?}", err));
                            self.closed = true;
                            break;
                        }
                    }

                    Ok(ConnectionEvent::Closed) => break,

                    // No event
                    Err(TryRecvError::Empty) => break,

                    // Channel closed
                    Err(TryRecvError::Disconnected) => break 'EVENTS,
                }

                thread::sleep(Duration::from_millis(10));
            }

            if self.closed {
                break;
            }

            // End of poll cycle
            thread::sleep(Duration::from_millis(50));
        }

        Ok(())
    }

    /// Read and process connection content
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a byte vector of data read from TCP stream.
    /// If connection would block, then not data is returned.
    ///
    pub fn read(&mut self) -> Result<Vec<u8>, AppError> {
        let mut return_buffer = vec![];
        let mut error: Option<AppError> = None;

        // Attempt connection read
        match self.read_tls_conn() {
            Ok(buffer) => {
                if !buffer.is_empty() {
                    match self.visitor.on_connection_read(&buffer) {
                        Ok(()) => {}
                        Err(err) => error = Some(err),
                    }
                    return_buffer = buffer;
                }
            }

            Err(err) => error = Some(err),
        }

        // Handle connection error
        if error.is_some() {
            self.event_channel
                .0
                .send(ConnectionEvent::Closing)
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending closing event".to_string(),
                        Box::new(err),
                    )
                })?;
            return Err(error.unwrap());
        }

        Ok(return_buffer)
    }

    /// Write content to client connection
    ///
    /// # Arguments
    ///
    /// * `buffer` - A byte array of data to write to TCP stream.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of write operation.
    ///
    pub fn write(&mut self, buffer: &[u8]) -> Result<(), AppError> {
        let mut error: Option<AppError> = None;

        // Attempt connection write
        match self.write_tls_conn(buffer) {
            Ok(()) => {}
            Err(err) => error = Some(err),
        }

        // Handle connection error
        if error.is_some() {
            self.event_channel
                .0
                .send(ConnectionEvent::Closing)
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending closing event".to_string(),
                        Box::new(err),
                    )
                })?;
            return Err(error.unwrap());
        }

        Ok(())
    }

    /// Shut down TLS connection
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of shutdown operation.
    ///
    pub fn shutdown(&mut self) -> Result<(), AppError> {
        if self.closed {
            return Ok(());
        }

        match self.tcp_stream.as_ref().unwrap().shutdown(Shutdown::Both) {
            Err(err) if io::ErrorKind::NotConnected != err.kind() => {
                return Err(AppError::GenWithMsgAndErr(
                    "Error shutting down TLS connection".to_string(),
                    Box::new(err),
                ))
            }
            _ => {}
        }

        self.closed = true;

        if let Err(err) = self
            .event_channel
            .0
            .send(ConnectionEvent::Closed)
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error sending closed event".to_string(), Box::new(err))
            })
        {
            error(&target!(), &format!("{:?}", err));
        }

        self.visitor.on_shutdown()
    }

    /// Read client connection content
    fn read_tls_conn(&mut self) -> Result<Vec<u8>, AppError> {
        let mut buffer = Vec::new();
        let mut buff_chunk = [0; READ_BLOCK_SIZE];
        loop {
            let bytes_read = match self.read_stream(&mut buff_chunk) {
                Ok(bytes_read) => bytes_read,

                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    self.event_channel
                        .0
                        .send(ConnectionEvent::Closing)
                        .map_err(|err| {
                            AppError::GenWithMsgAndErr(
                                "Error sending closing event".to_string(),
                                Box::new(err),
                            )
                        })?;
                    break;
                }

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,

                Err(err) => {
                    return Err(AppError::GenWithMsgAndErr(
                        "Error reading from TLS connection".to_string(),
                        Box::new(err),
                    ))
                }
            };
            if bytes_read < READ_BLOCK_SIZE {
                buffer.append(&mut buff_chunk[..bytes_read].to_vec());
                break;
            }
            buffer.append(&mut buff_chunk.to_vec());
        }

        Ok(buffer)
    }

    /// Read stream content implementation
    #[cfg(not(test))]
    #[inline(always)]
    fn read_stream(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.as_mut().unwrap().read(buffer)
    }
    #[cfg(test)]
    #[inline(always)]
    fn read_stream(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.tls_conn_alt.as_mut().unwrap().read(buffer)
    }

    /// Write content to client connection
    fn write_tls_conn(&mut self, buffer: &[u8]) -> Result<(), AppError> {
        match self.write_stream(buffer) {
            Ok(()) => {}

            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => self
                .event_channel
                .0
                .send(ConnectionEvent::Closing)
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending closing event".to_string(),
                        Box::new(err),
                    )
                })?,

            Err(err) if err.kind() == io::ErrorKind::WouldBlock => self
                .event_channel
                .0
                .send(ConnectionEvent::Write(buffer.to_vec()))
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending write event".to_string(),
                        Box::new(err),
                    )
                })?,

            Err(err) => {
                return Err(AppError::GenWithMsgAndErr(
                    "Error writing to TLS connection".to_string(),
                    Box::new(err),
                ))
            }
        }

        Ok(())
    }

    /// Write stream content implementation
    #[cfg(not(test))]
    #[inline(always)]
    fn write_stream(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.tls_conn.as_mut().unwrap().write_all(buffer)
    }
    #[cfg(test)]
    #[inline(always)]
    fn write_stream(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.tls_conn_alt.as_mut().unwrap().write_all(buffer)
    }
}

unsafe impl Send for Connection {}

impl From<Connection> for TlsClientConnection {
    fn from(val: Connection) -> Self {
        val.tls_conn.unwrap()
    }
}

/// Visitor pattern used to customize connection implementation strategy.
pub trait ConnectionVisitor: Send {
    /// Session connected event handler
    ///
    /// # Arguments
    ///
    /// * `event_channel_sender` - A clone of the event message channel sender
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of function call.
    ///
    fn on_connected(
        &mut self,
        _event_channel_sender: &Sender<ConnectionEvent>,
    ) -> Result<(), AppError> {
        Ok(())
    }

    /// Incoming connection content processing event handler
    ///
    /// # Arguments
    ///
    /// * `data` - Data byte array, which was read from TCP stream
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of function call.
    ///
    fn on_connection_read(&mut self, _data: &[u8]) -> Result<(), AppError> {
        Ok(())
    }

    /// Polling cycle tick handler
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of function call.
    ///
    fn on_polling_cycle(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Connection shutdown event handler
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of function call.
    ///
    fn on_shutdown(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Send error response message to client
    ///
    /// # Arguments
    ///
    /// * `err` - Processing error to handle
    ///
    fn send_error_response(&mut self, err: &AppError);
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::net::tls_client::client_std::tests::create_tls_client_config;
    use mockall::{mock, predicate};
    use pki_types::ServerName;
    use std::io::ErrorKind;
    use std::sync::Arc;

    pub fn create_simple_connection() -> Connection {
        Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: None,
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel: mpsc::channel(),
            closed: false,
        }
    }

    // mocks
    // =====

    mock! {
        pub ConnVisit {}
        impl ConnectionVisitor for ConnVisit {
            fn on_connected(&mut self, _event_channel_sender: &Sender<ConnectionEvent>) -> Result<(), AppError>;
            fn on_connection_read(&mut self, _data: &[u8]) -> Result<(), AppError>;
            fn on_polling_cycle(&mut self) -> Result<(), AppError>;
            fn on_shutdown(&mut self) -> Result<(), AppError>;
            fn send_error_response(&mut self, err: &AppError);
        }
    }

    // tests
    // =====

    #[test]
    fn connevt_create_channel() {
        let _ = ConnectionEvent::create_channel();
    }

    #[test]
    fn conn_new() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let session_addrs = ("addr1".to_string(), "addr2".to_string());

        let mut visitor = MockConnVisit::new();
        visitor
            .expect_on_connected()
            .with(predicate::always())
            .return_once(|_| Ok(()));

        let result = Connection::new(
            Box::new(visitor),
            StreamOwned::new(
                rustls::ClientConnection::new(
                    Arc::new(create_tls_client_config().unwrap()),
                    ServerName::try_from("localhost".to_string()).unwrap(),
                )
                .unwrap(),
                stream_utils::clone_std_tcp_stream(&connected_tcp_stream.client_stream.0).unwrap(),
            ),
            &session_addrs,
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let conn = result.unwrap();

        assert!(conn.tcp_stream.is_some());
        assert_eq!(conn.session_addrs, session_addrs);
        assert!(!conn.closed);
    }

    #[test]
    fn conn_accessors_and_mutators() {
        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_utils::tests::MockStreamReadWrite::new())),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel: mpsc::channel(),
            closed: false,
        };

        assert_eq!(
            conn.get_session_addrs(),
            &("addr1".to_string(), "addr2".to_string())
        );
        assert!(!conn.is_closed());
        conn.set_closed(true);
        assert!(conn.is_closed());
        let _ = conn.clone_event_channel_sender();
    }

    #[test]
    fn conn_poll_connection_when_1st_loop_iteration_errors() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        stream_rw
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(100));
        let mut visitor = MockConnVisit::new();
        visitor
            .expect_on_connection_read()
            .times(1)
            .with(predicate::always())
            .return_once(|_| Err(AppError::StreamEOF));
        visitor
            .expect_on_polling_cycle()
            .times(1)
            .return_once(|| Err(AppError::StreamEOF));
        visitor.expect_on_shutdown().times(1).return_once(|| Ok(()));
        let event_channel = mpsc::channel();
        let mut conn = Connection {
            visitor: Box::new(visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: Some(
                stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0).unwrap(),
            ),
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        if let Err(err) = conn.poll_connection() {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(conn_evt) => panic!("Unexpected queued connection event: evt={:?}", &conn_evt),
            Err(err) if TryRecvError::Disconnected == err => {
                panic!("Unexpected event channel recv result: err={:?}", &err)
            }
            Err(_) => {}
        }

        assert!(conn.closed);
    }
    #[test]
    fn conn_poll_connection_when_2nd_loop_iteration_errors() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        stream_rw
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(100));
        stream_rw
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(100));
        stream_rw
            .expect_write_all()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(()));
        let mut visitor = MockConnVisit::new();
        visitor
            .expect_on_connection_read()
            .times(1)
            .return_once(|_| Ok(()));
        visitor
            .expect_on_connection_read()
            .times(1)
            .return_once(|_| Err(AppError::StreamEOF));
        visitor
            .expect_on_polling_cycle()
            .times(1)
            .return_once(|| Ok(()));
        visitor
            .expect_on_polling_cycle()
            .times(1)
            .return_once(|| Err(AppError::StreamEOF));
        visitor.expect_on_shutdown().times(1).return_once(|| Ok(()));
        let event_channel = mpsc::channel();
        let event_channel_sender = event_channel.0.clone();
        let mut conn = Connection {
            visitor: Box::new(visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: Some(
                stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0).unwrap(),
            ),
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        event_channel_sender
            .send(ConnectionEvent::Write("data1".as_bytes().to_vec()))
            .unwrap();

        if let Err(err) = conn.poll_connection() {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(conn_evt) => panic!("Unexpected queued connection event: evt={:?}", &conn_evt),
            Err(err) if TryRecvError::Disconnected == err => {
                panic!("Unexpected event channel recv result: err={:?}", &err)
            }
            Err(_) => {}
        }

        assert!(conn.closed);
    }

    #[test]
    fn conn_read_when_no_data_to_read() {
        let conn_visitor = MockConnVisit::new();
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    AppError::General("not readable".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(result.unwrap().is_empty());

        match conn.event_channel.1.try_recv() {
            Ok(event) => panic!("Unexpected conn event recvd: evt={:?}", event),
            Err(err) => {
                if let TryRecvError::Empty = err {
                } else {
                    panic!("Unexpected conn event channel result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn conn_read_when_data_to_read() {
        let event_channel = mpsc::channel();
        let readable_bytes = "hello".as_bytes().to_vec();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let readable_bytes_copy = readable_bytes.clone();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(move |b| {
                for i in 0..readable_bytes_copy.len() {
                    b[i] = *readable_bytes_copy.get(i).unwrap();
                }
                Ok(readable_bytes_copy.len())
            });

        let readable_bytes_copy = readable_bytes.clone();
        let mut conn_visitor = MockConnVisit::new();
        conn_visitor
            .expect_on_connection_read()
            .with(predicate::eq(readable_bytes_copy))
            .times(1)
            .return_once(|_| Ok(()));

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let recvd_bytes = result.unwrap();
        assert_eq!(recvd_bytes.len(), readable_bytes.len());
        assert_eq!(
            String::from_utf8(recvd_bytes.clone()).unwrap(),
            String::from_utf8(readable_bytes.clone()).unwrap()
        );

        match conn.event_channel.1.try_recv() {
            Ok(event) => panic!("Unexpected conn event recvd: evt={:?}", event),
            Err(err) => {
                if let TryRecvError::Empty = err {
                } else {
                    panic!("Unexpected conn event channel result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn conn_read_when_peer_connection_closed() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    AppError::General("connection closed".to_string()),
                ))
            });

        let mut conn_visitor = MockConnVisit::new();
        conn_visitor.expect_on_connection_read().never();

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let recvd_bytes = result.unwrap();
        assert_eq!(recvd_bytes.len(), 0);

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }
    }

    /*
    #[test]
    fn conn_read_when_error_while_reading() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::Other,
                    AppError::General("error1".to_string()),
                ))
            });

        let mut conn_visitor = MockConnVisit::new();
        conn_visitor.expect_on_connection_read().never();

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Ok(recvd_bytes) = result {
            panic!("Unexpected successful result: buffer={:?}", &recvd_bytes);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn conn_write_when_stream_not_writable() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    AppError::General("not writable".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Write(_) = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => panic!("Unexpected conn event channel result: err={:?}", &err),
        }
    }
     */

    #[test]
    fn conn_read_when_eof_error_while_reading() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    AppError::General("eof".to_string()),
                ))
            });

        let mut conn_visitor = MockConnVisit::new();
        conn_visitor.expect_on_connection_read().never();

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn conn_read_when_blockable_error_while_reading() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    AppError::General("not readable".to_string()),
                ))
            });

        let mut conn_visitor = MockConnVisit::new();
        conn_visitor.expect_on_connection_read().never();

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Write(_) = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) if TryRecvError::Disconnected == err => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
            Err(_) => {}
        }
    }

    #[test]
    fn conn_read_when_other_error_while_reading() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = [0; READ_BLOCK_SIZE];
        stream_rw
            .expect_read()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::Other,
                    AppError::General("error1".to_string()),
                ))
            });

        let mut conn_visitor = MockConnVisit::new();
        conn_visitor.expect_on_connection_read().never();

        let mut conn = Connection {
            visitor: Box::new(conn_visitor),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.read();

        if let Ok(recvd_bytes) = result {
            panic!("Unexpected successful result: buffer={:?}", &recvd_bytes);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn conn_write_when_eof_io_error_while_writing() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    AppError::General("eof".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => panic!("Unexpected conn event channel result: err={:?}", &err),
        }
    }

    #[test]
    fn conn_write_when_blockable_io_error_while_writing() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    AppError::General("not writable".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Write(_) = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => panic!("Unexpected conn event channel result: err={:?}", &err),
        }
    }

    #[test]
    fn conn_write_when_other_io_error_while_writing() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::Other,
                    AppError::General("error1".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => panic!("Unexpected conn event channel result: err={:?}", &err),
        }
    }

    #[test]
    fn conn_write_when_successfully_written() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| Ok(()));

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => panic!("Unexpected conn event recvd: evt={:?}", event),
            Err(err) => {
                if let TryRecvError::Empty = err {
                } else {
                    panic!("Unexpected conn event channel result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn conn_write_when_peer_connection_closed() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    AppError::General("connection closed".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn conn_write_when_error_while_reading() {
        let event_channel = mpsc::channel();

        let mut stream_rw = stream_utils::tests::MockStreamReadWrite::new();
        let buffer = "hello".as_bytes();
        stream_rw
            .expect_write_all()
            .with(predicate::eq(buffer))
            .times(1)
            .return_once(|_| {
                Err(io::Error::new(
                    ErrorKind::Other,
                    AppError::General("error1".to_string()),
                ))
            });

        let mut conn = Connection {
            visitor: Box::new(MockConnVisit::new()),
            tls_conn: None,
            tls_conn_alt: Some(Box::new(stream_rw)),
            tcp_stream: None,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            closed: false,
        };

        let result = conn.write(buffer);

        if let Ok(()) = result {
            panic!("Unexpected successful result");
        }

        match conn.event_channel.1.try_recv() {
            Ok(event) => {
                if let ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }
    }

    #[test]
    fn connvisit_trait_defaults() {
        struct ConnVisitImpl {
            err_response: String,
        }
        impl ConnectionVisitor for ConnVisitImpl {
            fn send_error_response(&mut self, err: &AppError) {
                self.err_response = err.to_string();
            }
        }

        let mut conn_visitor = ConnVisitImpl {
            err_response: String::new(),
        };

        if let Err(err) = conn_visitor.on_connected(&mpsc::channel().0) {
            panic!("Unexpected 'on_connected' result: err={:?}", &err);
        }
        if let Err(err) = conn_visitor.on_connection_read(&[0x10]) {
            panic!("Unexpected 'on_connection_read' result: err={:?}", &err);
        }
        if let Err(err) = conn_visitor.on_polling_cycle() {
            panic!("Unexpected 'on_polling_cycle' result: err={:?}", &err);
        }
        if let Err(err) = conn_visitor.on_shutdown() {
            panic!("Unexpected 'on_shutdown' result: err={:?}", &err);
        }
        conn_visitor.send_error_response(&AppError::StreamEOF);
        assert_eq!(conn_visitor.err_response, "StreamEOF Error".to_string());
    }
}
