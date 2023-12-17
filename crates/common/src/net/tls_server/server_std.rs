use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::{io, thread};
use std::time::Duration;

use anyhow::Result;
use rustls::server::{Accepted, Acceptor};

use crate::net::tls_server::conn_std::{self, TlsServerConnection};
use crate::error::AppError;
use crate::logging::{error, info};
use crate::target;

/// This is a TLS server, which will listen/accept client connections
///
/// It has a TCP-level stream, a TLS-level connection state, and some other state/metadata.
pub struct Server {
    visitor: Arc<Mutex<dyn ServerVisitor>>,
    _server_port: u16,
    tcp_listener: Option<TcpListener>,
    listen_addr: String,
    polling: bool,
    closing: bool,
    closed: bool
}

impl Server {

    /// Server constructor
    pub fn new(
        visitor: Arc<Mutex<dyn ServerVisitor>>,
        server_port: u16
    ) -> Self {

        Self {
            visitor,
            _server_port: server_port,
            tcp_listener: None,
            listen_addr: format!("[::]:{}", server_port),
            polling: false,
            closing: false,
            closed: false
        }
    }

    /// Bind/listen on port
    pub fn bind_listener(&mut self) -> Result<(), AppError> {

        let server_addr: SocketAddr = self.listen_addr.parse()?;

        let tcp_listener = TcpListener::bind(server_addr).map_err(|err|
            AppError::GenWithMsgAndErr(
                format!("Error setting up listener: server_addr={:?}", &server_addr),
                Box::new(err)))?;
        tcp_listener.set_nonblocking(true).map_err(|err|
            AppError::GenWithMsgAndErr(
                format!("Failed making listener non-blocking: server_addr={:?}", &server_addr),
                Box::new(err)))?;

        self.tcp_listener = Some(tcp_listener);
        self.listen_addr = format!("{:?}", &server_addr);
        self.closing = false;
        self.closed = false;
        self.polling = false;

        info(&target!(), &format!("Server started: addr={:?}", &server_addr));

        self.visitor.lock().unwrap().on_listening()
    }

    /// Request shutdown for poller and listener
    pub fn shutdown(&mut self) {

        if !self.polling {
            self.perform_shutdown();
        } else {
            self.polling = false;
        }
    }

    /// Request shutdown for poller
    pub fn stop_poller(&mut self) {

        self.polling = false;
    }

    /// Poll and dispatch new listener connections
    pub fn poll_new_connections(&mut self) -> Result<(), AppError> {

        self.assert_listening()?;

        if self.polling {
            return Err(AppError::General(format!("Already polling for new connections: server_addr={:?}", &self.listen_addr)));
        }

        self.polling = true;

        info(&target!(), &format!("Polling connections started: server_addr={:?}", &self.listen_addr));

        loop {

            // Accept new connection (non-blocking
            if let Err(err) = self.accept() {
                match err {
                    AppError::WouldBlock => {},
                    _ => error(&target!(), &format!("{:?}", err))
                }
            }

            // Check if shutdown requested
            if self.visitor.lock().unwrap().get_shutdown_requested() {
                self.polling = false;
                self.closing = true;
            }

            if !self.polling {
                break;
            }

            // Add delay between accepts
            thread::sleep(Duration::from_millis(30));
        }

        info(&target!(), &format!("Polling connections ended: server_addr={:?}", &self.listen_addr));

        if self.closing {
            self.perform_shutdown();
        }

        Ok(())
    }

    /// Spawn a thread to handle connection processing
    pub fn spawn_connection_processor(mut connection: conn_std::Connection) {

        thread::spawn(move || {

            let result = {
                let mut result: Option<Result<(), AppError>> = None;

                let peer_addr: String;
                if let Ok(socket_addr) = connection.get_tls_conn_as_ref().sock.peer_addr() {
                    peer_addr = format!("{:?}", socket_addr);
                } else {
                    peer_addr = "(unknown)".to_string();
                }

                // Poll connection events
                if let Err(err) = connection.poll_connection() {
                    result = Some(Err(err));
                }

                // Shutdown connection (if needed)
                if let Err(err) = connection.shutdown() {
                    if result.is_none() {
                        result = Some(Err(err));
                    }
                }

                info(&target!(), &format!("Client disconnected: peer_addr={}", &peer_addr));

                result.unwrap_or(Ok(()))
            };

            if let Err(err) = result {
                error(&target!(), &format!("{:?}", err));
            }
        });
    }

    /// shutdown for poller and listener
    fn perform_shutdown(&mut self) {

        self.closing = true;
        self.closed = true;
        self.polling = false;
        self.tcp_listener = None;

        info(&target!(), &format!("Server shutdown: server_addr={:?}", &self.listen_addr));
    }

    /// New connection acceptance processor
    fn accept(&mut self) -> Result<(), AppError> {

        // Accept new connection
        let (mut tcp_stream, peer_addr) = self.tcp_listener.as_ref().unwrap().accept().map_err(|err| {
            if err.kind() == io::ErrorKind::WouldBlock {
                AppError::WouldBlock
            } else {
                AppError::GenWithMsgAndErr(
                    format!("Error accepting connection: server_addr={:?}", &self.listen_addr),
                    Box::new(err))
            }
        })?;

        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut tcp_stream).unwrap();
            if let Some(accepted) = acceptor.accept().map_err(|err|
                AppError::GenWithMsgAndErr(
                    format!("Error reading TLS client hello: server_addr={:?}, peer_addr={:?}", &self.listen_addr, &peer_addr),
                    Box::new(err.clone())))? {
                break accepted;
            }
        };

        let tls_server_config = Arc::new(self.visitor.lock().unwrap().on_tls_handshaking(&accepted)?);

        let mut tls_srv_conn = accepted.into_connection(tls_server_config).map_err(|err|
            AppError::GenWithMsgAndErr(
                format!("Error creating TLS server connection: server_addr={:?}, peer_addr={:?}", &self.listen_addr, &peer_addr),
                Box::new(err)))?;

        let _ = tls_srv_conn.complete_io(&mut tcp_stream).map_err(|err|
            AppError::GenWithMsgAndErr(
                format!("Error completing TLS server connection: server_addr={:?}, peer_addr={:?}", &self.listen_addr, &peer_addr),
                Box::new(err)))?;

        tcp_stream.set_nonblocking(true).map_err(|err|
            AppError::GenWithMsgAndErr(
                format!("Failed making socket non-blocking: server_addr={:?}, peer_addr={:?}", &self.listen_addr, &peer_addr),Box::new(err)))?;

        let tls_conn = rustls::StreamOwned::new(tls_srv_conn, tcp_stream);

        let connection = self.visitor.lock().unwrap().create_client_conn(tls_conn)?;

        info(&target!(), &format!("Client connected: peer_addr={:?}", &peer_addr));

        self.visitor.lock().unwrap().on_conn_accepted(connection)?;

        Ok(())
    }

    fn assert_listening(&self) -> Result<(), AppError> {
        if self.tcp_listener.is_none() {
            return Err(AppError::General("Gateway not listening".to_string()))
        }
        Ok(())
    }
}

unsafe impl Send for Server {}

/// Visitor pattern used to customize server implementation strategy.
pub trait ServerVisitor : Send {

    /// TLS client connection factory
    fn create_client_conn(&mut self, tls_conn: TlsServerConnection) -> Result<conn_std::Connection, AppError>;

    /// Server listener bound
    fn on_listening(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Connection TLS handshaking
    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<rustls::ServerConfig, AppError>;

    /// Connection accepted
    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        Server::spawn_connection_processor(connection);
        Ok(())
    }

    /// Returns whether listener shutdown is required
    fn get_shutdown_requested(&self) -> bool {
        false
    }
}
