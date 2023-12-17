use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use anyhow::Result;
use pki_types::ServerName;

use crate::net::tls_client::conn_std;
use crate::net::tls_client::conn_std::TlsClientConnection;
use crate::error::AppError;
use crate::logging::info;
use crate::target;

/// This is a TLS client, which will connect to a server and expose IO methods
///
/// It has a TCP-level stream, a TLS-level connection state, and some other state/metadata.
pub struct Client {
    visitor: Box<dyn ClientVisitor>,
    tls_client_config: Arc<rustls::ClientConfig>,
    server_host: String,
    server_port: u16,
    connection: Option<conn_std::Connection>,
}

impl Client {

    /// Client constructor
    pub fn new(
        visitor: Box<dyn ClientVisitor>,
        tls_client_config: rustls::ClientConfig,
        server_host: String,
        server_port: u16
    ) -> Self {

        Self {
            visitor,
            tls_client_config: Arc::new(tls_client_config),
            server_host,
            server_port,
            connection: None
        }
    }

    /// Connection accessor
    pub fn get_connection(&self) -> &Option<conn_std::Connection> {
        &self.connection
    }

    /// Connect to server
    pub fn connect(&mut self) -> Result<(), AppError> {

        let server_host = ServerName::try_from(self.server_host.to_string()).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to resolve server host: host={}", &self.server_host), Box::new(err)))?;

        let server_addr = (self.server_host.clone(), self.server_port).to_socket_addrs()?
            .next()
            .ok_or(AppError::General(format!("Unable to create socket addr: host={}, port={}", &self.server_host, self.server_port)))?;

        let mut tls_cli_conn = rustls::ClientConnection::new(self.tls_client_config.clone(), server_host.clone()).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Error setting up TLS client connection: server={:?}", &server_host), Box::new(err)))?;

        let mut tcp_stream = TcpStream::connect(server_addr).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Error establishing TCP connection: addr={:?}", &server_addr), Box::new(err)))?;

        let _ = tls_cli_conn.complete_io(&mut tcp_stream).map_err(|err|
            AppError::GenWithMsgAndErr("Error completing TLS client connection".to_string(), Box::new(err)))?;

        tcp_stream.set_nonblocking(true).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed making socket non-blocking: addr={}", &server_addr),Box::new(err)))?;

        let tls_conn = rustls::StreamOwned::new(tls_cli_conn, tcp_stream);

        let connection = self.visitor.create_server_conn(tls_conn)?;

        info(&target!(), &format!("Connected: addr={:?}", server_addr));

        self.visitor.on_connected()?;

        self.connection = Some(connection);

        Ok(())
    }

    /// Poll connection events
    pub fn poll_connection(&mut self) -> Result<(), AppError> {

        self.assert_connected()?;
        self.connection.as_mut().unwrap().poll_connection()
    }

    fn assert_connected(&self) -> Result<(), AppError> {
        if self.connection.is_none() {
            return Err(AppError::General("Client not connected".to_string()))
        }
        Ok(())
    }
}

unsafe impl Send for Client {}

impl From<Client> for TlsClientConnection {
    fn from(value: Client) -> Self {
        value.connection.unwrap().into()
    }
}

/// Visitor pattern used to customize client implementation strategy.
pub trait ClientVisitor : Send {

    /// TLS server connection factory
    fn create_server_conn(&mut self, tls_conn: TlsClientConnection) -> Result<conn_std::Connection, AppError>;

    /// Session connected
    fn on_connected(&mut self) -> Result<(), AppError> {
        Ok(())
    }
}
