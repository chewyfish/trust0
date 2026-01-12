use anyhow::Result;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::client::control::controller::{ControlPlane, MessageProcessor};
use crate::client::replshell_io::{ReplShellInputReader, ReplShellOutputWriter};
use crate::client::service::ClientControlServiceMgr;
use crate::error::AppError;
use crate::logging::error;
use crate::net::tls_client::conn_std;
use crate::target;

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {
    /// Channel sender for connection events
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    /// Control plane processor
    message_processor: Box<dyn MessageProcessor>,
}

impl ServerConnVisitor {
    /// ServerConnVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `repl_shell_input` - REPL shell input reader
    /// * `repl_shell_output` - REPL shell output writer
    /// * `service_mgr` - Service manager object
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ServerConnVisitor`] object.
    ///
    pub fn new(
        repl_shell_input: &Arc<Mutex<Box<dyn ReplShellInputReader>>>,
        repl_shell_output: &Arc<Mutex<Box<dyn ReplShellOutputWriter>>>,
        service_mgr: &Arc<Mutex<Box<dyn ClientControlServiceMgr>>>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            event_channel_sender: None,
            message_processor: Box::new(ControlPlane::new(
                repl_shell_input,
                repl_shell_output,
                service_mgr,
            )?),
        })
    }
}

impl conn_std::ConnectionVisitor for ServerConnVisitor {
    fn on_connected(
        &mut self,
        event_channel_sender: &Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError> {
        self.event_channel_sender = Some(event_channel_sender.clone());
        self.message_processor.on_connected(event_channel_sender)
    }

    fn on_connection_read(&mut self, data: &[u8]) -> Result<(), AppError> {
        self.message_processor.process_inbound_messages(data)
    }

    fn on_polling_cycle(&mut self) -> Result<(), AppError> {
        self.message_processor.process_outbound_messages()
    }

    fn send_error_response(&mut self, err: &AppError) {
        error(&target!(), &format!("{:?}", err));
    }
}

unsafe impl Send for ServerConnVisitor {}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::client::control::controller::tests::MockGwMsgProcessor;
    use crate::client::replshell_io::tests::{MockShellInputReader, MockShellOutputWriter};
    use crate::client::service::tests::MockClientControlSvcMgr;
    use crate::net::tls_client::conn_std::ConnectionVisitor;
    use mockall::{mock, predicate};
    use std::sync::mpsc;

    // mocks
    // =====

    // mocks
    // =====

    mock! {
        pub ConnVisit {}
        impl conn_std::ConnectionVisitor for ConnVisit {
            fn on_connected(&mut self, _event_channel_sender: &Sender<conn_std::ConnectionEvent>) -> Result<(), AppError>;
            fn on_connection_read(&mut self, _data: &[u8]) -> Result<(), AppError>;
            fn on_polling_cycle(&mut self) -> Result<(), AppError>;
            fn on_shutdown(&mut self) -> Result<(), AppError>;
            fn send_error_response(&mut self, err: &AppError);
        }
    }

    // tests
    // =====

    #[test]
    fn srvconnvis_new() {
        let service_mgr: Arc<Mutex<Box<dyn ClientControlServiceMgr>>> =
            Arc::new(Mutex::new(Box::new(MockClientControlSvcMgr::new())));
        match ServerConnVisitor::new(
            &Arc::new(Mutex::new(Box::new(MockShellInputReader::new()))),
            &Arc::new(Mutex::new(Box::new(MockShellOutputWriter::new()))),
            &service_mgr,
        ) {
            Ok(server_conn_visitor) => assert!(server_conn_visitor.event_channel_sender.is_none()),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn srvconnvis_on_connected() {
        let mut msg_processor = MockGwMsgProcessor::new();
        msg_processor
            .expect_on_connected()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(()));

        let mut server_conn_visitor = ServerConnVisitor {
            event_channel_sender: None,
            message_processor: Box::new(msg_processor),
        };

        let result = server_conn_visitor.on_connected(&mpsc::channel().0);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server_conn_visitor.event_channel_sender.is_some());
    }

    #[test]
    fn srvconnvis_on_connection_read_when_simple_ping_response() {
        let event_channel = mpsc::channel();

        let data = vec![65, 66, 67];

        let mut msg_processor = MockGwMsgProcessor::new();
        msg_processor
            .expect_process_inbound_messages()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Ok(()));

        let mut server_conn_visitor = ServerConnVisitor {
            event_channel_sender: Some(event_channel.0),
            message_processor: Box::new(msg_processor),
        };

        if let Err(err) = server_conn_visitor.on_connection_read(data.as_slice()) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn srvconnvis_on_polling_cycle_when_no_pending_line() {
        let event_channel = mpsc::channel();

        let mut msg_processor = MockGwMsgProcessor::new();
        msg_processor
            .expect_process_outbound_messages()
            .times(1)
            .return_once(|| Ok(()));

        let mut server_conn_visitor = ServerConnVisitor {
            event_channel_sender: Some(event_channel.0),
            message_processor: Box::new(msg_processor),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn srvconnvis_send_error_response() {
        let event_channel = mpsc::channel();
        let msg_processor = MockGwMsgProcessor::new();

        let mut server_conn_visitor = ServerConnVisitor {
            event_channel_sender: Some(event_channel.0),
            message_processor: Box::new(msg_processor),
        };

        server_conn_visitor.send_error_response(&AppError::General(
            "Testing client connection error response".to_string(),
        ));
    }
}
