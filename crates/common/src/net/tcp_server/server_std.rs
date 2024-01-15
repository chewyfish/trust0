use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

use anyhow::Result;

use crate::error::AppError;
use crate::logging::{error, info};
use crate::net::tcp_server::conn_std;
use crate::target;

/// This is a TCP server, which will listen/accept client connections
pub struct Server {
    visitor: Arc<Mutex<dyn ServerVisitor>>,
    _server_port: u16,
    tcp_listener: Option<TcpListener>,
    listen_addr: String,
    polling: bool,
    closing: bool,
    closed: bool,
}

impl Server {
    /// Server constructor
    pub fn new(visitor: Arc<Mutex<dyn ServerVisitor>>, server_port: u16) -> Self {
        Self {
            visitor,
            _server_port: server_port,
            tcp_listener: None,
            listen_addr: format!("[::]:{}", server_port),
            polling: false,
            closing: false,
            closed: false,
        }
    }

    /// Bind/listen on port
    pub fn bind_listener(&mut self) -> Result<(), AppError> {
        let server_addr: SocketAddr = self.listen_addr.parse()?;

        let tcp_listener = TcpListener::bind(server_addr).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Error setting up listener: server_addr={:?}", &server_addr),
                Box::new(err),
            )
        })?;
        tcp_listener.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making listener non-blocking: server_addr={:?}",
                    &server_addr
                ),
                Box::new(err),
            )
        })?;

        self.tcp_listener = Some(tcp_listener);
        self.listen_addr = format!("{:?}", &server_addr);
        self.closing = false;
        self.closed = false;
        self.polling = false;

        info(
            &target!(),
            &format!("Server started: addr={:?}", &server_addr),
        );

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
            return Err(AppError::General(format!(
                "Already polling for new connections: server_addr={:?}",
                &self.listen_addr
            )));
        }

        self.polling = true;

        info(
            &target!(),
            &format!(
                "Polling connections started: server_addr={:?}",
                &self.listen_addr
            ),
        );

        loop {
            // Accept new connection (non-blocking)
            if let Err(err) = self.accept() {
                match err {
                    AppError::WouldBlock => {}
                    _ => error(&target!(), &format!("{:?}", err)),
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

        info(
            &target!(),
            &format!(
                "Polling connections ended: server_addr={:?}",
                &self.listen_addr
            ),
        );

        if self.closing {
            self.perform_shutdown();
        }

        Ok(())
    }

    /// shutdown for poller and listener
    fn perform_shutdown(&mut self) {
        self.closing = true;
        self.closed = true;
        self.polling = false;
        self.tcp_listener = None;

        info(
            &target!(),
            &format!("Server shutdown: server_addr={:?}", &self.listen_addr),
        );
    }

    /// New connection acceptance processor
    fn accept(&mut self) -> Result<(), AppError> {
        // Accept new connection
        let (tcp_stream, peer_addr) =
            self.tcp_listener
                .as_ref()
                .unwrap()
                .accept()
                .map_err(|err| {
                    if err.kind() == io::ErrorKind::WouldBlock {
                        AppError::WouldBlock
                    } else {
                        AppError::GenWithMsgAndErr(
                            format!(
                                "Error accepting connection: server_addr={:?}",
                                &self.listen_addr
                            ),
                            Box::new(err),
                        )
                    }
                })?;

        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making socket non-blocking: server_addr={:?}, peer_addr={:?}",
                    &self.listen_addr, &peer_addr
                ),
                Box::new(err),
            )
        })?;

        let connection = self
            .visitor
            .lock()
            .unwrap()
            .create_client_conn(tcp_stream)?;

        info(
            &target!(),
            &format!("Client connected: peer_addr={:?}", &peer_addr),
        );

        self.visitor.lock().unwrap().on_conn_accepted(connection)?;

        Ok(())
    }

    /// Spawn a thread to handle connection processing
    fn spawn_connection_processor(mut connection: conn_std::Connection) {
        thread::spawn(move || {
            let result = {
                let mut result: Option<Result<(), AppError>> = None;

                let peer_addr: String;
                if let Ok(socket_addr) = connection.get_tcp_stream_as_ref().peer_addr() {
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

                info(
                    &target!(),
                    &format!("Client disconnected: peer_addr={}", &peer_addr),
                );

                result.unwrap_or(Ok(()))
            };

            if let Err(err) = result {
                error(&target!(), &format!("{:?}", err));
            }
        });
    }

    fn assert_listening(&self) -> Result<(), AppError> {
        if self.tcp_listener.is_none() {
            return Err(AppError::General("Gateway not listening".to_string()));
        }
        Ok(())
    }
}

unsafe impl Send for Server {}

/// Visitor pattern used to customize server implementation strategy.
pub trait ServerVisitor: Send {
    /// TCP client connection factory
    fn create_client_conn(
        &mut self,
        tcp_stream: TcpStream,
    ) -> Result<conn_std::Connection, AppError>;

    /// Server listener bound
    fn on_listening(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    /// Connection accepted
    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        Server::spawn_connection_processor(connection);
        Ok(())
    }

    /// Returns whether listener shutdown is required
    fn get_shutdown_requested(&self) -> bool;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::net::stream_utils;
    use crate::net::tcp_server::conn_std::tests::MockConnVisit;
    use mockall::{mock, predicate};
    use std::sync::mpsc;

    // mocks
    // =====

    mock! {
        pub ServerVisit {}
        impl ServerVisitor for ServerVisit {
            fn create_client_conn(&mut self, tcp_stream: TcpStream) -> Result<conn_std::Connection, AppError>;
            fn on_listening(&mut self) -> Result<(), AppError>;
            fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError>;
            fn get_shutdown_requested(&self) -> bool;
        }
    }

    // tests
    // ====

    #[test]
    fn server_new() {
        let server = Server::new(Arc::new(Mutex::new(MockServerVisit::new())), 1234);

        assert_eq!(server._server_port, 1234);
        assert!(server.tcp_listener.is_none());
        assert_eq!(server.listen_addr, "[::]:1234");
        assert!(!server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_bind_listener() {
        let mut visitor = MockServerVisit::new();
        visitor
            .expect_on_listening()
            .times(1)
            .return_once(|| Ok(()));
        let mut server = Server {
            visitor: Arc::new(Mutex::new(visitor)),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        if let Err(err) = server.bind_listener() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server.tcp_listener.is_some());
        assert!(!server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_not_listening() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        if let Ok(()) = server.poll_new_connections() {
            panic!("Unexpected successful result");
        }

        assert!(server.tcp_listener.is_none());
        assert!(!server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_already_polling() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: Some(tcp_listener),
            listen_addr: "127.0.0.1:0".to_string(),
            polling: true,
            closing: false,
            closed: false,
        };

        if let Ok(()) = server.poll_new_connections() {
            panic!("Unexpected successful result");
        }

        assert!(server.tcp_listener.is_some());
        assert!(server.polling);
        assert!(!server.closing);
        assert!(!server.closed);
    }

    #[test]
    fn server_poll_new_connections_when_2nd_iteration_shutdown_request() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let mut visitor = MockServerVisit::new();
        visitor
            .expect_get_shutdown_requested()
            .times(1)
            .return_once(|| false);
        visitor
            .expect_get_shutdown_requested()
            .times(1)
            .return_once(|| true);
        let mut server = Server {
            visitor: Arc::new(Mutex::new(visitor)),
            _server_port: 1234,
            tcp_listener: Some(tcp_listener),
            listen_addr: "127.0.0.1:0".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        if let Err(err) = server.poll_new_connections() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server.tcp_listener.is_none());
        assert!(!server.polling);
        assert!(server.closing);
        assert!(server.closed);
    }

    #[test]
    fn server_assert_listening_when_not_listening() {
        let server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        if let Ok(()) = server.assert_listening() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn server_shutdown_when_not_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: false,
            closing: false,
            closed: false,
        };

        server.shutdown();

        assert_eq!(server.closing, true);
        assert_eq!(server.closed, true);
        assert_eq!(server.polling, false);
        assert!(server.tcp_listener.is_none());
    }

    #[test]
    fn server_shutdown_when_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: true,
            closing: false,
            closed: false,
        };

        server.shutdown();

        assert_eq!(server.closing, false);
        assert_eq!(server.closed, false);
        assert_eq!(server.polling, false);
        assert!(server.tcp_listener.is_none());
    }

    #[test]
    fn server_stop_poller_when_polling() {
        let mut server = Server {
            visitor: Arc::new(Mutex::new(MockServerVisit::new())),
            _server_port: 1234,
            tcp_listener: None,
            listen_addr: "addr1".to_string(),
            polling: true,
            closing: false,
            closed: false,
        };

        server.stop_poller();

        assert_eq!(server.polling, false);
    }

    #[test]
    fn server_spawn_connection_processor_when_no_errors() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let mut stream_reader = stream_utils::tests::MockStreamReader::new();
        stream_reader
            .expect_read()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(100));
        let mut conn_visitor = MockConnVisit::new();
        conn_visitor
            .expect_on_connection_read()
            .times(1)
            .with(predicate::always())
            .return_once(|_| Err(AppError::StreamEOF));
        conn_visitor
            .expect_on_polling_cycle()
            .times(1)
            .return_once(|| Err(AppError::StreamEOF));
        conn_visitor
            .expect_on_shutdown()
            .times(1)
            .return_once(|| Ok(()));
        let event_channel = mpsc::channel();
        let conn = conn_std::tests::create_connection(
            Box::new(conn_visitor),
            Some(
                stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0).unwrap(),
            ),
            Box::new(stream_reader),
            Box::new(stream_utils::tests::MockStreamWriter::new()),
            event_channel,
            false,
        );

        Server::spawn_connection_processor(conn);
    }
}
