use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::Duration;
use std::{io, thread};

use crate::crypto::alpn;
use anyhow::Result;
use pki_types::CertificateDer;
use rustls::{self, StreamOwned};

use crate::error::AppError;
use crate::logging::error;
use crate::net::stream_utils;
use crate::net::stream_utils::StreamReaderWriter;
use crate::{control, sync, target};

const READ_BLOCK_SIZE: usize = 1024;

/// Encapsulates key TLS server connection objects
pub type TlsServerConnection = StreamOwned<rustls::ServerConnection, TcpStream>;

/// TLS connection trait to wrap key rustls server connection functions, attributes
pub trait TlsConnection {
    /// Retrieves the certificate chain used by the peer to authenticate.
    fn peer_certificates(&self) -> Option<Vec<CertificateDer<'_>>>;

    /// Retrieves the protocol agreed with the peer via ALPN.
    fn alpn_protocol(&self) -> Option<Vec<u8>>;
}

impl TlsConnection for TlsServerConnection {
    /// Returns connection's peer's certificate(s)
    ///
    /// # Returns
    ///
    /// An (optional) vector of peer certificates.
    ///
    fn peer_certificates(&self) -> Option<Vec<CertificateDer<'_>>> {
        self.conn.peer_certificates().map(|certs| certs.to_vec())
    }

    /// Returns connection's ALPN protocol(s)
    ///
    /// # Returns
    ///
    /// An (optional) vector of connection's ALPN protocols (as byte vectors).
    ///
    fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.conn
            .alpn_protocol()
            .map(|proto_bytes| proto_bytes.to_vec())
    }
}

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

/// TLS client connection which has been accepted by the server, and is currently being served.
pub struct Connection {
    /// Connection visitor pattern object
    visitor: Box<dyn ConnectionVisitor>,
    /// Corresponding TLS connection object
    tls_conn: Option<TlsServerConnection>,
    /// Corresponding TLS connection object (alternative version used in testing)
    #[allow(dead_code)]
    tls_conn_alt: Option<Box<dyn StreamReaderWriter>>,
    /// Corresponding TCP connection stream
    tcp_stream: Option<TcpStream>,
    /// Session connection addresses
    session_addrs: control::tls::message::ConnectionAddrs,
    /// Event message channel
    event_channel: (Sender<ConnectionEvent>, Receiver<ConnectionEvent>),
    /// Connection ALPN protocol
    alpn_protocol: alpn::Protocol,
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
    /// * `alpn_protocol` - ALPN protocol for connection
    ///
    /// # Returns
    ///
    /// A [`Result`] of a newly constructed [`Connection`] object.
    /// Error is returned if there are issues cloning the TCP stream.
    //
    pub fn new(
        mut visitor: Box<dyn ConnectionVisitor>,
        tls_conn: TlsServerConnection,
        session_addrs: &control::tls::message::ConnectionAddrs,
        alpn_protocol: &alpn::Protocol,
    ) -> Result<Self, AppError> {
        let event_channel = mpsc::channel();
        visitor.on_connected(&event_channel.0)?;

        let tcp_stream = stream_utils::clone_std_tcp_stream(&tls_conn.sock, "net-tls-server")?;

        Ok(Self {
            visitor,
            tls_conn: Some(tls_conn),
            tls_conn_alt: None,
            tcp_stream: Some(tcp_stream),
            session_addrs: session_addrs.clone(),
            event_channel,
            alpn_protocol: alpn_protocol.clone(),
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

    /// Connection 'tls_conn' (immutable) accessor
    ///
    /// # Returns
    ///
    /// A reference to the TLS connection object. Assumes value is present, otherwise will panic.
    ///
    pub fn get_tls_conn_as_ref(&self) -> &TlsServerConnection {
        self.tls_conn.as_ref().unwrap()
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

    /// Connection 'alpn_protocol' accessor
    ///
    /// # Returns
    ///
    /// A reference to the connection's ALPN protocol.
    ///
    pub fn get_alpn_protocol(&self) -> &alpn::Protocol {
        &self.alpn_protocol
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

            // Custom polling cycle handler
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

                    // Handle connection shutdown request
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

    /// Read and process client connection content
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
            sync::send_mpsc_channel_message(
                &self.event_channel.0,
                ConnectionEvent::Closing,
                Box::new(|| "Error sending closing event:".to_string()),
            )?;
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
            sync::send_mpsc_channel_message(
                &self.event_channel.0,
                ConnectionEvent::Closing,
                Box::new(|| "Error sending closing event:".to_string()),
            )?;
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
                return Err(AppError::General(format!(
                    "Error shutting down TLS connection: err={:?}",
                    &err
                )));
            }
            _ => {}
        }

        self.closed = true;

        if let Err(err) = sync::send_mpsc_channel_message(
            &self.event_channel.0,
            ConnectionEvent::Closed,
            Box::new(|| "Error sending closed event:".to_string()),
        ) {
            error(&target!(), &format!("{:?}", &err));
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
                    sync::send_mpsc_channel_message(
                        &self.event_channel.0,
                        ConnectionEvent::Closing,
                        Box::new(|| "Error sending closing event:".to_string()),
                    )?;
                    break;
                }

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,

                Err(err) => {
                    return Err(AppError::General(format!(
                        "Error reading from TLS connection: err={:?}",
                        &err
                    )));
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

            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                sync::send_mpsc_channel_message(
                    &self.event_channel.0,
                    ConnectionEvent::Closing,
                    Box::new(|| "Error sending closing event:".to_string()),
                )?
            }

            Err(err) if err.kind() == io::ErrorKind::WouldBlock => sync::send_mpsc_channel_message(
                &self.event_channel.0,
                ConnectionEvent::Write(buffer.to_vec()),
                Box::new(|| "Error sending write event:".to_string()),
            )?,

            Err(err) => {
                return Err(AppError::General(format!(
                    "Error writing to TLS connection: err={:?}",
                    &err
                )));
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

impl From<Connection> for TlsServerConnection {
    fn from(value: Connection) -> Self {
        value.tls_conn.unwrap()
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
    use crate::net::tls_server::server_std::tests::create_tls_server_config;
    use mockall::{mock, predicate};
    use std::io::ErrorKind;
    use std::sync::Arc;

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

    // utils
    // =====

    pub fn create_connection(
        visitor: Box<dyn ConnectionVisitor>,
        tls_conn: Option<TlsServerConnection>,
        tls_conn_alt: Option<Box<dyn StreamReaderWriter>>,
        tcp_stream: Option<TcpStream>,
        event_channel: (Sender<ConnectionEvent>, Receiver<ConnectionEvent>),
        alpn_protocol: alpn::Protocol,
        closed: bool,
    ) -> Connection {
        Connection {
            visitor,
            tls_conn,
            tls_conn_alt,
            tcp_stream,
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            alpn_protocol,
            closed,
        }
    }

    // tests
    // =====

    #[test]
    fn connevt_create_channel() {
        let _ = crate::net::tls_client::conn_std::ConnectionEvent::create_channel();
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
                rustls::ServerConnection::new(Arc::new(create_tls_server_config().unwrap()))
                    .unwrap(),
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.server_stream.0,
                    "test-net-tls-server",
                )
                .unwrap(),
            ),
            &session_addrs,
            &alpn::Protocol::ControlPlane,
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let conn = result.unwrap();

        assert!(conn.tcp_stream.is_some());
        assert_eq!(conn.session_addrs, session_addrs);
        assert_eq!(conn.alpn_protocol, alpn::Protocol::ControlPlane);
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
            alpn_protocol: alpn::Protocol::ControlPlane,
            closed: false,
        };

        assert_eq!(
            conn.get_session_addrs(),
            &("addr1".to_string(), "addr2".to_string())
        );
        assert!(!conn.is_closed());
        conn.set_closed(true);
        assert!(conn.is_closed());
        assert_eq!(conn.get_alpn_protocol(), &alpn::Protocol::ControlPlane);
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
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.server_stream.0,
                    "test-net-tls-server",
                )
                .unwrap(),
            ),
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            alpn_protocol: alpn::Protocol::ControlPlane,
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
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.server_stream.0,
                    "test-net-tls-server",
                )
                .unwrap(),
            ),
            session_addrs: ("addr1".to_string(), "addr2".to_string()),
            event_channel,
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
            alpn_protocol: alpn::Protocol::ControlPlane,
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
    fn convisit_trait_defaults() {
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
