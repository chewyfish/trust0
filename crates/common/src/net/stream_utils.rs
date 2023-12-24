use std::io;
use std::sync::{Arc, Mutex};

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::error::AppError;

const TCP_READ_BLOCK_SIZE: usize = 1024;
const UDP_RECV_BUFFER_SIZE: usize = 64 * 1024;

pub trait StreamReaderWriter: io::Read + io::Write + Send {}

impl StreamReaderWriter for std::net::TcpStream {}
impl StreamReaderWriter for StreamOwned<ClientConnection, std::net::TcpStream> {}
impl StreamReaderWriter for StreamOwned<ServerConnection, std::net::TcpStream> {}

/// Read TCP stream content
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

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use anyhow::Result;
    use log::error;
    use mockall::mock;
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::thread;
    use std::thread::JoinHandle;

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

    // utils
    // =====

    /// Connected TCP stream pair creator
    pub struct ConnectedTcpStream {
        pub listener: Arc<TcpListener>,
        pub server_stream: (TcpStream, SocketAddr),
        pub client_stream: (TcpStream, SocketAddr),
    }

    impl ConnectedTcpStream {
        /// ConnectedTcpStream constructor, create a connected socket pair
        pub fn new() -> Result<Self> {
            // spawn server listener
            let listener = Arc::new(TcpListener::bind("127.0.0.1:0")?);
            let listener_copy = listener.clone();
            let server_thread: JoinHandle<io::Result<(TcpStream, SocketAddr)>> =
                thread::spawn(move || {
                    let res = listener_copy.accept();
                    res
                });

            // connect to server
            let server_addr: SocketAddr = listener.local_addr()?;
            let client_stream = TcpStream::connect(server_addr.clone())?;

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
            if let Err(err) = self.server_stream.0.shutdown(Shutdown::Both) {
                error!(
                    "Error shutting down connected tcp stream server: err={:?}",
                    &err
                );
            }
            if let Err(err) = self.client_stream.0.shutdown(Shutdown::Both) {
                error!(
                    "Error shutting down connected tcp stream client: err={:?}",
                    &err
                );
            }
        }
    }

    /// Connected UDP socket pair creator
    pub struct ConnectedUdpSocket {
        pub server_socket: (UdpSocket, SocketAddr),
        pub client_socket: (UdpSocket, SocketAddr),
    }

    impl ConnectedUdpSocket {
        /// ConnectedUdpStream constructor, create a connected socket pair
        pub fn new() -> Result<Self> {
            // bind server/client socket
            let server_socket = UdpSocket::bind("127.0.0.1:0")?;
            let client_socket = UdpSocket::bind("127.0.0.1:0")?;
            let server_addr: SocketAddr = server_socket.local_addr()?;
            let client_addr: SocketAddr = client_socket.local_addr()?;

            // connect to server
            client_socket.connect(server_addr.clone())?;

            // instantiate ConnectedUdpSocket
            Ok(Self {
                server_socket: (server_socket, server_addr),
                client_socket: (client_socket, client_addr),
            })
        }
    }
}
