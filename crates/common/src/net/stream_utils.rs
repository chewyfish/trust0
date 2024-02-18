use log::error;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{io, thread};

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::error::AppError;

const TCP_READ_BLOCK_SIZE: usize = 1024;
const UDP_RECV_BUFFER_SIZE: usize = 64 * 1024;

/// Represents a stream, which implements [`io::Read`] and [`io::Write`]
pub trait StreamReaderWriter: io::Read + io::Write + Send {}

impl StreamReaderWriter for std::net::TcpStream {}
impl StreamReaderWriter for StreamOwned<ClientConnection, std::net::TcpStream> {}
impl StreamReaderWriter for StreamOwned<ServerConnection, std::net::TcpStream> {}

/// Read TCP stream content
///
/// # Arguments
///
/// * `stream_reader` - Stream to read from
///
/// # Returns
///
/// A [`Result`] containing a data byte vector read from given stream.
///
pub fn read_tcp_stream(
    stream_reader: &mut Arc<Mutex<Box<dyn StreamReaderWriter>>>,
) -> Result<Vec<u8>, AppError> {
    let mut buffer = Vec::new();
    let mut buff_chunk = [0; TCP_READ_BLOCK_SIZE];
    loop {
        let bytes_read = match stream_reader.lock().unwrap().read(&mut buff_chunk) {
            Ok(bytes_read) => bytes_read,

            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(AppError::StreamEOF)
            }
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => return Err(AppError::StreamEOF),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                return Err(AppError::StreamEOF)
            }
            Err(err) => {
                return Err(AppError::GenWithMsgAndErr(
                    "Error reading from stream".to_string(),
                    Box::new(err),
                ))
            }
        };

        if bytes_read < TCP_READ_BLOCK_SIZE {
            buffer.append(&mut buff_chunk[..bytes_read].to_vec());
            break;
        }

        buffer.append(&mut buff_chunk.to_vec());
    }

    Ok(buffer)
}

/// Write TCP stream content
///
/// * `stream_writer` - Stream to write to
/// * `buffer` - Data byte array to write to stream
///
/// # Returns
///
/// A [`Result`] indicating success/failure of write operation.
///
pub fn write_tcp_stream(
    stream_writer: &mut Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    buffer: &[u8],
) -> Result<(), AppError> {
    match stream_writer.lock().unwrap().write_all(buffer) {
        Ok(()) => Ok(()),

        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(AppError::WouldBlock),
        Err(err) => Err(AppError::GenWithMsgAndErr(
            "Error writing to stream".to_string(),
            Box::new(err),
        )),
    }
}

/// Read (MIO) UDP socket content
///
/// # Arguments
///
/// * `udp_socket` - (MIO) UDP socket, which can receive messages
///
/// # Returns
///
/// A [`Result`] containing a tuple of the remote socket address and the data byte vector read from given socket.
///
pub fn read_mio_udp_socket(
    udp_socket: &mio::net::UdpSocket,
) -> Result<(std::net::SocketAddr, Vec<u8>), AppError> {
    let mut buffer = [0; UDP_RECV_BUFFER_SIZE];

    match udp_socket.recv_from(&mut buffer) {
        Ok((bytes_read, socket_addr)) => Ok((socket_addr, buffer[..bytes_read].to_vec())),

        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(AppError::WouldBlock),
        Err(err) => Err(AppError::GenWithMsgAndErr(
            format!("Error reading from udp socket: socket={:?}", &udp_socket),
            Box::new(err),
        )),
    }
}

/// Write UDP socket content
///
/// # Arguments
///
/// * `udp_socket` - (MIO) UDP socket to send messages from
///
/// # Returns
///
/// A [`Result`] indicating success/failure of write operation.
///
pub fn write_mio_udp_socket(
    udp_socket: &mio::net::UdpSocket,
    buffer: &[u8],
) -> Result<(), AppError> {
    match udp_socket.send(buffer) {
        Ok(_) => Ok(()),

        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(AppError::WouldBlock),
        Err(err) => Err(AppError::GenWithMsgAndErr(
            format!("Error writing to udp socket: socket={:?}", &udp_socket),
            Box::new(err),
        )),
    }
}

/// Clone std TcpStream
///
/// # Arguments
///
/// * `tcp_stream` - TCP stream to clone
///
/// # Returns
///
/// A [`Result`] containing the cloned TCP stream.
///
pub fn clone_std_tcp_stream(
    tcp_stream: &std::net::TcpStream,
) -> Result<std::net::TcpStream, AppError> {
    tcp_stream.try_clone().map_err(|err| {
        AppError::GenWithMsgAndErr(
            format!("Error trying to clone tcp stream: stream={:?}", &tcp_stream),
            Box::new(err),
        )
    })
}

/// Clone std UdpSocket
///
/// # Arguments
///
/// * `udp_stream` - UDP socket to clone
///
/// # Returns
///
/// A [`Result`] containing the cloned UDP socket.
///
pub fn clone_std_udp_socket(
    udp_socket: &std::net::UdpSocket,
) -> Result<std::net::UdpSocket, AppError> {
    udp_socket.try_clone().map_err(|err| {
        AppError::GenWithMsgAndErr(
            format!("Error trying to clone udp socket: socket={:?}", &udp_socket),
            Box::new(err),
        )
    })
}

/// Connected TCP stream pair creator
pub struct ConnectedTcpStream {
    /// TCP listener used in creating the connected TCP streams
    pub listener: Arc<std::net::TcpListener>,
    /// The TCP stream for the server (of the connected stream pair)
    pub server_stream: (std::net::TcpStream, std::net::SocketAddr),
    /// The TCP stream for the client (of the connected stream pair)
    pub client_stream: (std::net::TcpStream, std::net::SocketAddr),
}

impl ConnectedTcpStream {
    /// ConnectedTcpStream constructor, create a connected socket pair
    ///
    /// # Returns
    ///
    /// A [`anyhow::Result`] of a newly created [`ConnectedTcpStream`] object.
    ///
    pub fn new() -> anyhow::Result<Self> {
        // spawn server listener
        let listener = Arc::new(std::net::TcpListener::bind("127.0.0.1:0")?);
        let listener_copy = listener.clone();
        let server_thread: JoinHandle<io::Result<(std::net::TcpStream, std::net::SocketAddr)>> =
            thread::spawn(move || listener_copy.accept());

        // connect to server
        let server_addr: std::net::SocketAddr = listener.local_addr()?;
        let client_stream = std::net::TcpStream::connect(server_addr)?;

        // join server thread
        let server_stream = server_thread.join().unwrap()?;

        // instantiate ConnectedTcpStream
        Ok(Self {
            listener,
            server_stream,
            client_stream: (client_stream, server_addr),
        })
    }
}

impl Drop for ConnectedTcpStream {
    fn drop(&mut self) {
        if let Err(err) = self.server_stream.0.shutdown(std::net::Shutdown::Both) {
            error!(
                "Error shutting down connected tcp stream server: err={:?}",
                &err
            );
        }
        if let Err(err) = self.client_stream.0.shutdown(std::net::Shutdown::Both) {
            error!(
                "Error shutting down connected tcp stream client: err={:?}",
                &err
            );
        }
    }
}

/// Connected UDP socket pair creator
pub struct ConnectedUdpSocket {
    /// The UDP socket for the server (of the connected socket pair)
    pub server_socket: (std::net::UdpSocket, std::net::SocketAddr),
    /// The UDP socket for the server (of the connected socket pair)
    pub client_socket: (std::net::UdpSocket, std::net::SocketAddr),
}

impl ConnectedUdpSocket {
    /// ConnectedUdpStream constructor, create a connected socket pair
    ///
    /// # Returns
    ///
    /// A [`anyhow::Result`] of a newly created [`ConnectedUdpSocket`] object.
    ///
    pub fn new() -> anyhow::Result<Self> {
        // bind server/client socket
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let server_addr: std::net::SocketAddr = server_socket.local_addr()?;
        let client_addr: std::net::SocketAddr = client_socket.local_addr()?;

        // connect to server
        client_socket.connect(server_addr)?;

        // instantiate ConnectedUdpSocket
        Ok(Self {
            server_socket: (server_socket, server_addr),
            client_socket: (client_socket, client_addr),
        })
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::{mock, predicate};

    // mocks
    // =====

    mock! {
        pub StreamReader {}
        impl io::Read for StreamReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
        }
    }

    mock! {
        pub StreamWriter {}
        impl io::Write for StreamWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
            fn flush(&mut self) -> io::Result<()>;
            fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
        }
    }

    mock! {
        pub StreamReadWrite {}
        impl io::Read for StreamReadWrite {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
        }
        impl io::Write for StreamReadWrite {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
            fn flush(&mut self) -> io::Result<()>;
            fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
        }
        impl StreamReaderWriter for StreamReadWrite {}
    }

    // tests
    // =====

    #[test]
    fn streamutl_read_tcp_stream_when_read_full_buf_once_then_would_block_error() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|buf| {
                buf.copy_from_slice([0x01u8; TCP_READ_BLOCK_SIZE].as_slice());
                Ok(TCP_READ_BLOCK_SIZE)
            });
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Err(io::ErrorKind::WouldBlock.into()));
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        match read_tcp_stream(&mut stream_reader) {
            Ok(data) => assert_eq!(data, [0x01u8; 1024].to_vec()),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn streamutl_read_tcp_stream_when_read_non_full_buf() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|buf| {
                buf[0] = 0x01u8;
                Ok(1)
            });
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        match read_tcp_stream(&mut stream_reader) {
            Ok(data) => assert_eq!(data, vec![0x01u8]),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn read_tcp_stream_when_would_block_error() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Err(io::ErrorKind::WouldBlock.into()));
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        match read_tcp_stream(&mut stream_reader) {
            Ok(data) => assert!(data.is_empty()),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn streamutl_read_tcp_stream_when_eof_error() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Err(io::ErrorKind::UnexpectedEof.into()));
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        match read_tcp_stream(&mut stream_reader) {
            Ok(data) => panic!("Unexpected successful result: data={:?}", &data),
            Err(err) => match err {
                AppError::StreamEOF => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            },
        }
    }

    #[test]
    fn read_tcp_stream_when_pipe_error() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Err(io::ErrorKind::BrokenPipe.into()));
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        match read_tcp_stream(&mut stream_reader) {
            Ok(data) => panic!("Unexpected successful result: data={:?}", &data),
            Err(err) => match err {
                AppError::StreamEOF => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            },
        }
    }

    #[test]
    fn streamutl_read_tcp_stream_when_connected_error() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Err(io::ErrorKind::NotConnected.into()));
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        match read_tcp_stream(&mut stream_reader) {
            Ok(data) => panic!("Unexpected successful result: data={:?}", &data),
            Err(err) => match err {
                AppError::StreamEOF => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            },
        }
    }

    #[test]
    fn read_tcp_stream_when_other_error() {
        let mut stream_reader = MockStreamReadWrite::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Err(io::ErrorKind::Other.into()));
        let mut stream_reader: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_reader)));

        if let Ok(data) = read_tcp_stream(&mut stream_reader) {
            panic!("Unexpected successful result: data={:?}", &data);
        }
    }

    #[test]
    fn streamutl_write_tcp_stream_when_successful() {
        let data = vec![0x01u8];
        let mut stream_writer = MockStreamReadWrite::new();
        stream_writer
            .expect_write_all()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Ok(()));
        let mut stream_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_writer)));

        if let Err(err) = write_tcp_stream(&mut stream_writer, data.as_slice()) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn streamutl_write_tcp_stream_when_would_block_error() {
        let data = vec![0x01u8];
        let mut stream_writer = MockStreamReadWrite::new();
        stream_writer
            .expect_write_all()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Err(io::ErrorKind::WouldBlock.into()));
        let mut stream_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_writer)));

        if let Err(err) = write_tcp_stream(&mut stream_writer, data.as_slice()) {
            match err {
                AppError::WouldBlock => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            }
        } else {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn streamutl_write_tcp_stream_when_eof_error() {
        let data = vec![0x01u8];
        let mut stream_writer = MockStreamReadWrite::new();
        stream_writer
            .expect_write_all()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Err(io::ErrorKind::UnexpectedEof.into()));
        let mut stream_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_writer)));

        if let Err(err) = write_tcp_stream(&mut stream_writer, data.as_slice()) {
            match err {
                AppError::StreamEOF => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            }
        } else {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn streamutl_write_tcp_stream_when_pipe_error() {
        let data = vec![0x01u8];
        let mut stream_writer = MockStreamReadWrite::new();
        stream_writer
            .expect_write_all()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Err(io::ErrorKind::BrokenPipe.into()));
        let mut stream_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_writer)));

        if let Err(err) = write_tcp_stream(&mut stream_writer, data.as_slice()) {
            match err {
                AppError::StreamEOF => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            }
        } else {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn streamutl_write_tcp_stream_when_connected_error() {
        let data = vec![0x01u8];
        let mut stream_writer = MockStreamReadWrite::new();
        stream_writer
            .expect_write_all()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Err(io::ErrorKind::NotConnected.into()));
        let mut stream_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_writer)));

        if let Err(err) = write_tcp_stream(&mut stream_writer, data.as_slice()) {
            match err {
                AppError::StreamEOF => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            }
        } else {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn streamutl_write_tcp_stream_when_other_error() {
        let data = vec![0x01u8];
        let mut stream_writer = MockStreamReadWrite::new();
        stream_writer
            .expect_write_all()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Err(io::ErrorKind::Other.into()));
        let mut stream_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>> =
            Arc::new(Mutex::new(Box::new(stream_writer)));

        if write_tcp_stream(&mut stream_writer, data.as_slice()).is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn streamutl_read_mio_udp_socket_when_would_block() {
        let connected_udp_socket = ConnectedUdpSocket::new().unwrap();
        let udp_socket = connected_udp_socket.client_socket.0;
        udp_socket.set_nonblocking(true).unwrap();
        let udp_socket = mio::net::UdpSocket::from_std(udp_socket);

        if let Err(err) = read_mio_udp_socket(&udp_socket) {
            match err {
                AppError::WouldBlock => {}
                _ => panic!("Unexpected result: err={:?}", &err),
            }
        } else {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn streamutl_write_mio_udp_socket_when_would_block() {
        let connected_udp_socket = ConnectedUdpSocket::new().unwrap();
        let udp_socket = connected_udp_socket.client_socket.0;
        udp_socket.set_nonblocking(true).unwrap();
        let udp_socket = mio::net::UdpSocket::from_std(udp_socket);

        if let Err(err) = write_mio_udp_socket(&udp_socket, vec![0x01u8].as_slice()) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
