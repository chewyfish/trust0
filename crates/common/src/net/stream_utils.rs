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
pub fn read_tcp_stream(stream_reader: &mut Arc<Mutex<Box<dyn StreamReaderWriter>>>) -> Result<Vec<u8>, AppError> {

    let mut buffer = Vec::new();
    let mut buff_chunk = [0; TCP_READ_BLOCK_SIZE];
    loop {
        let bytes_read = match stream_reader.lock().unwrap().read(&mut buff_chunk) {

            Ok(bytes_read) => bytes_read,

            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Err(AppError::StreamEOF),
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => return Err(AppError::StreamEOF),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => return Err(AppError::StreamEOF),
            Err(err) => return Err(AppError::GenWithMsgAndErr("Error reading from stream".to_string(), Box::new(err)))
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
pub fn write_tcp_stream(stream_writer: &mut Arc<Mutex<Box<dyn StreamReaderWriter>>>, buffer: &[u8]) -> Result<(), AppError> {

    match stream_writer.lock().unwrap().write_all(buffer) {

        Ok(()) => Ok(()),

        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(AppError::WouldBlock),
        Err(err) => Err(AppError::GenWithMsgAndErr("Error writing to stream".to_string(), Box::new(err)))
    }
}

/// Read (MIO) UDP socket content
pub fn read_mio_udp_socket(udp_socket: &mio::net::UdpSocket) -> Result<(std::net::SocketAddr, Vec<u8>), AppError> {

    let mut buffer = [0; UDP_RECV_BUFFER_SIZE];

    match udp_socket.recv_from(&mut buffer) {

        Ok((bytes_read, socket_addr)) => Ok((socket_addr, buffer[..bytes_read].to_vec())),

        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(AppError::WouldBlock),
        Err(err) => Err(AppError::GenWithMsgAndErr(format!("Error reading from udp socket: socket={:?}", &udp_socket), Box::new(err)))
    }
}

/// Write UDP socket content
pub fn write_mio_udp_socket(udp_socket: &mio::net::UdpSocket, buffer: &[u8]) -> Result<(), AppError> {

    match udp_socket.send(&buffer) {

        Ok(_) => Ok(()),

        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Err(AppError::StreamEOF),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(AppError::WouldBlock),
        Err(err) => Err(AppError::GenWithMsgAndErr(format!("Error writing to udp socket: socket={:?}", &udp_socket), Box::new(err)))
    }
}

/// Clone std TcpStream
pub fn clone_std_tcp_stream(tcp_stream: &std::net::TcpStream)
    -> Result<std::net::TcpStream, AppError> {

    tcp_stream.try_clone().map_err(|err|
        AppError::GenWithMsgAndErr(format!("Error trying to clone tcp stream: stream={:?}", &tcp_stream), Box::new(err)))
}

/// Clone std UdpSocket
pub fn clone_std_udp_socket(udp_socket: &std::net::UdpSocket)
    -> Result<std::net::UdpSocket, AppError> {

    udp_socket.try_clone().map_err(|err|
        AppError::GenWithMsgAndErr(format!("Error trying to clone udp socket: socket={:?}", &udp_socket), Box::new(err)))
}
