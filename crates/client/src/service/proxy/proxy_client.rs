use trust0_common::error::AppError;
use trust0_common::net::tls_client::{client_std, conn_std};

/// tls_client::std_client::Client strategy visitor pattern implementation
pub struct ClientVisitor {
}

impl ClientVisitor {

    /// ClientVisitor constructor
    pub fn new() -> Self {
        Self {}
    }
}

impl client_std::ClientVisitor for ClientVisitor {

    fn create_server_conn(&mut self, tls_conn: conn_std::TlsClientConnection) -> Result<conn_std::Connection, AppError> {

        let conn_visitor = ServerConnVisitor::new()?;
        let connection = conn_std::Connection::new(Box::new(conn_visitor), tls_conn)?;

        Ok(connection)
    }
}

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {
}

impl ServerConnVisitor {

    /// ServerConnVisitor constructor
    pub fn new() -> Result<Self, AppError> {

        Ok(Self {})
    }
}

impl conn_std::ConnectionVisitor for ServerConnVisitor {

    fn send_error_response(&mut self, _err: &AppError) {}
}

unsafe impl Send for ServerConnVisitor {}
