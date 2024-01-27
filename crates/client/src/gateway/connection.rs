use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::config::AppConfig;
use crate::gateway::controller::{ControlPlane, MessageProcessor};
use crate::service::manager::ServiceMgr;
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::net::tls_client::conn_std;
use trust0_common::target;

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {
    _app_config: Arc<AppConfig>,
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    message_processor: Box<dyn MessageProcessor>,
}

impl ServerConnVisitor {
    /// ServerConnVisitor constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            _app_config: app_config.clone(),
            event_channel_sender: None,
            message_processor: Box::new(ControlPlane::new(app_config.clone(), &service_mgr)),
        })
    }
}

impl conn_std::ConnectionVisitor for ServerConnVisitor {
    fn on_connected(
        &mut self,
        event_channel_sender: Sender<conn_std::ConnectionEvent>,
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
mod tests {

    use super::*;
    use crate::gateway::controller;
    use crate::{config, service};
    use mockall::predicate;
    use std::sync::mpsc;
    use trust0_common::net::tls_client::conn_std::ConnectionVisitor;

    #[test]
    fn srvconnvis_new() {
        match ServerConnVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            Arc::new(Mutex::new(service::manager::tests::MockSvcMgr::new())),
        ) {
            Ok(server_conn_visitor) => assert!(server_conn_visitor.event_channel_sender.is_none()),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn srvconnvis_on_connected() {
        let app_config = config::tests::create_app_config(None).unwrap();

        let mut msg_processor = controller::tests::MockGwMsgProcessor::new();
        msg_processor
            .expect_on_connected()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(()));

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            event_channel_sender: None,
            message_processor: Box::new(msg_processor),
        };

        let result = server_conn_visitor.on_connected(mpsc::channel().0);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(server_conn_visitor.event_channel_sender.is_some());
    }

    #[test]
    fn srvconnvis_on_connection_read_when_simple_ping_response() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let event_channel = mpsc::channel();

        let data = vec![65, 66, 67];

        let mut msg_processor = controller::tests::MockGwMsgProcessor::new();
        msg_processor
            .expect_process_inbound_messages()
            .with(predicate::eq(data.clone()))
            .times(1)
            .return_once(|_| Ok(()));

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            event_channel_sender: Some(event_channel.0),
            message_processor: Box::new(msg_processor),
        };

        if let Err(err) = server_conn_visitor.on_connection_read(data.as_slice()) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn srvconnvis_on_polling_cycle_when_no_pending_line() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let event_channel = mpsc::channel();

        let mut msg_processor = controller::tests::MockGwMsgProcessor::new();
        msg_processor
            .expect_process_outbound_messages()
            .times(1)
            .return_once(|| Ok(()));

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            event_channel_sender: Some(event_channel.0),
            message_processor: Box::new(msg_processor),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn srvconnvis_send_error_response() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let event_channel = mpsc::channel();
        let msg_processor = controller::tests::MockGwMsgProcessor::new();

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            event_channel_sender: Some(event_channel.0),
            message_processor: Box::new(msg_processor),
        };

        server_conn_visitor.send_error_response(&AppError::General(
            "Testing client connection error response".to_string(),
        ));
    }
}
