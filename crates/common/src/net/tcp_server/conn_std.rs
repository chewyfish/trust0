use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::{io, thread};
use std::time::Duration;

use anyhow::Result;

use crate::error::AppError;
use crate::logging::error;
use crate::target;

const READ_BLOCK_SIZE: usize = 1024;

/// Connection event message channel
pub enum ConnectionEvent {
    Closing,
    Closed,
    Write(Vec<u8>)
}

impl ConnectionEvent {

    /// Create multiple producer, single consumer message channel
    pub fn create_channel() -> (Sender<ConnectionEvent>, Receiver<ConnectionEvent>) {
        mpsc::channel()
    }
}

/// This is a TCP client connection which has been accepted by the server, and is currently being served.
pub struct Connection {
    visitor: Box<dyn ConnectionVisitor>,
    tcp_stream: TcpStream,
    event_channel: (Sender<ConnectionEvent>, Receiver<ConnectionEvent>),
    closed: bool
}

impl Connection {

    /// Connection constructor
    pub fn new(
        mut visitor: Box<dyn ConnectionVisitor>,
        tcp_stream: TcpStream
    ) -> Result<Self, AppError> {

        let event_channel = ConnectionEvent::create_channel();
        visitor.set_event_channel_sender(event_channel.0.clone())?;
        visitor.on_connected()?;

        Ok(Self {
            visitor,
            tcp_stream,
            event_channel,
            closed: false
        })
    }

    /// Connection 'closed' state accessor
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Connection 'closed' state mutator
    pub fn set_closed(&mut self, closed: bool) {
        self.closed = closed;
    }

    /// Connection 'tcp_stream' (immutable) accessor
    pub fn get_tcp_stream_as_ref(&self) -> &TcpStream {
        &self.tcp_stream
    }

    /// Connection 'tcp_stream' (mutable) accessor
    pub fn get_tcp_stream_as_mut(&mut self) -> &mut TcpStream {
        &mut self.tcp_stream
    }

    /// Get copy of event channel sender
    pub fn clone_event_channel_sender(&self) -> Sender<ConnectionEvent> {
        self.event_channel.0.clone()
    }

    /// Poll connection events loop
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
            'EVENTS:
            loop {
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
                        }
                    }

                    Ok(ConnectionEvent::Closed) => break,

                    // No event
                    Err(TryRecvError::Empty) => break,

                    // Channel closed
                    Err(TryRecvError::Disconnected) => break 'EVENTS
                }

                let _ = thread::sleep(Duration::from_millis(10));
            }

            if self.closed { break; }

            // End of poll cycle
            let _ = thread::sleep(Duration::from_millis(50));
        }

        Ok(())
    }

    /// Read and process client connection content
    pub fn read(&mut self) -> Result<Vec<u8>, AppError> {

        let mut return_buffer = vec![];
        let mut error: Option<AppError> = None;

        // Attempt connection read
        match self.read_tcp_stream() {

            Ok(buffer) => {
                if !buffer.is_empty() {
                    match self.visitor.on_connection_read(&buffer) {
                        Ok(()) => {}
                        Err(err) => error = Some(err)
                    }
                    return_buffer = buffer;
                }
            }

            Err(err) => error = Some(err)
        }

        // Handle connection error
        if error.is_some() {
            self.event_channel.0.send(ConnectionEvent::Closing).map_err(|err|
                AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err)))?;
            return Err(error.unwrap());
        }

        Ok(return_buffer)
    }

    /// Write content to client connection
    pub fn write(&mut self, buffer: &[u8]) -> Result<(), AppError> {

        let mut error: Option<AppError> = None;

        // Attempt connection write
        match self.write_tcp_stream(buffer) {
            Ok(()) => {}
            Err(err) => error = Some(err)
        }

        // Handle connection error
        if error.is_some() {
            self.event_channel.0.send(ConnectionEvent::Closing).map_err(|err|
                AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err)))?;
            return Err(error.unwrap());
        }

        Ok(())
    }

    /// Shut down TCP connection
    pub fn shutdown(&mut self) -> Result<(), AppError> {

        if self.closed {
            return Ok(())
        }

        self.tcp_stream.shutdown(Shutdown::Both).map_err(|err|
            AppError::GenWithMsgAndErr("Error shutting down TCP connection".to_string(), Box::new(err)))?;

        self.closed = true;

        if let Err(err) = self.event_channel.0.send(ConnectionEvent::Closed).map_err(|err|
            AppError::GenWithMsgAndErr("Error sending closed event".to_string(), Box::new(err))) {
            error(&target!(), &format!("{:?}", err));
        }

        self.visitor.on_shutdown()
    }

    /// Read client connection content
    fn read_tcp_stream(&mut self) -> Result<Vec<u8>, AppError> {

        let mut buffer = Vec::new();
        let mut buff_chunk = [0; READ_BLOCK_SIZE];
        loop {
            let bytes_read = match self.tcp_stream.read(&mut buff_chunk) {

                Ok(bytes_read) => bytes_read,

                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    self.event_channel.0.send(ConnectionEvent::Closing).map_err(|err|
                        AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err)))?;
                    break
                }

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,

                Err(err) => return Err(AppError::GenWithMsgAndErr("Error reading from TCP connection".to_string(), Box::new(err)))
            };
            if bytes_read < READ_BLOCK_SIZE {
                buffer.append(&mut buff_chunk[..bytes_read].to_vec());
                break;
            }
            buffer.append(&mut buff_chunk.to_vec());
        }

        Ok(buffer)
    }

    /// Write content to client connection
    fn write_tcp_stream(&mut self, buffer: &[u8]) -> Result<(), AppError> {

        match self.tcp_stream.write_all(buffer) {

            Ok(()) => {}

            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof =>
                self.event_channel.0.send(ConnectionEvent::Closing).map_err(|err|
                    AppError::GenWithMsgAndErr("Error sending closing event".to_string(), Box::new(err)))?,

            Err(err) if err.kind() == io::ErrorKind::WouldBlock =>
                self.event_channel.0.send(ConnectionEvent::Write(buffer.to_vec())).map_err(|err|
                    AppError::GenWithMsgAndErr("Error sending write event".to_string(), Box::new(err)))?,

            Err(err) => return Err(AppError::GenWithMsgAndErr("Error writing to TCP connection".to_string(), Box::new(err)))
        }

        Ok(())
    }
}

unsafe impl Send for Connection {}

impl Into<TcpStream> for Connection {
    fn into(self) -> TcpStream {
        self.tcp_stream
    }
}

/// Visitor pattern used to customize connection implementation strategy.
pub trait ConnectionVisitor : Send {

    /// Session connected
    fn on_connected(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Setup event channel sender
    fn set_event_channel_sender(&mut self, _event_channel_sender: Sender<ConnectionEvent>) -> Result<(), AppError> {
        Ok(())
    }

    /// Incoming connection content processing event handler
    fn on_connection_read(&mut self, _data: &Vec<u8>) -> Result<(), AppError> {
        Ok(())
    }

    /// Polling cycle tick handler
    fn on_polling_cycle(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Connection shutdown event handler
    fn on_shutdown(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Send error response message to client
    fn send_error_response(&mut self, err: &AppError);
}
