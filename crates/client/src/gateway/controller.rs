mod management;
mod signaling;

use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::ops::DerefMut;
use std::sync::{mpsc, Arc, Mutex};

use crate::config::AppConfig;
use crate::service::manager::ServiceMgr;
use trust0_common::control::pdu::{ControlChannel, MessageFrame};
use trust0_common::error::AppError;
use trust0_common::net::tls_client::conn_std;
use trust0_common::sync;

/// Control plane processor. Handles management and signaling channel messages
pub struct ControlPlane {
    /// Channel sender for connection events
    event_channel_sender: Option<mpsc::Sender<conn_std::ConnectionEvent>>,
    /// Queued outbound PDU messages to be sent to gateway
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Queued inbound PDU messages bytes to be processed
    message_inbox: VecDeque<u8>,
    /// Control plane channel processors
    channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>>,
}

impl ControlPlane {
    /// ControlPlane constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration
    /// * `service_mgr` - Service manager object
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ControlPlane`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
    ) -> Result<Self, AppError> {
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let management_controller = Arc::new(Mutex::new(management::ManagementController::new(
            app_config,
            service_mgr,
            &message_outbox,
        )));
        let signaling_controller = Arc::new(Mutex::new(signaling::SignalingController::new(
            app_config,
            service_mgr,
            &message_outbox,
        )));
        Self::spawn_signaling_event_loop(&signaling_controller)?;

        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(ControlChannel::Management, management_controller);
        channel_processors.insert(ControlChannel::Signaling, signaling_controller);

        Ok(Self {
            event_channel_sender: None,
            message_outbox,
            message_inbox: VecDeque::new(),
            channel_processors,
        })
    }

    #[cfg(not(test))]
    fn spawn_signaling_event_loop(
        signal_controller: &Arc<Mutex<signaling::SignalingController>>,
    ) -> Result<(), AppError> {
        signaling::SignalingController::spawn_event_loop(signal_controller, None)
    }

    #[cfg(test)]
    fn spawn_signaling_event_loop(
        _signal_controller: &Arc<Mutex<signaling::SignalingController>>,
    ) -> Result<(), AppError> {
        Ok(())
    }

    /// Send control plane connection event message
    ///
    /// # Arguments
    ///
    /// * `message` - Connection event message to send
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the send operation.
    ///
    fn send_connection_event_message(
        &self,
        message: conn_std::ConnectionEvent,
    ) -> Result<(), AppError> {
        let event_sender = self.event_channel_sender.as_ref().unwrap();

        if let Err(err) = sync::send_mpsc_channel_message(
            event_sender,
            message,
            Box::new(|| "Error sending connection event:".to_string()),
        ) {
            let _ = event_sender.send(conn_std::ConnectionEvent::Closing);
            return Err(err);
        }

        Ok(())
    }
}

impl MessageProcessor for ControlPlane {
    fn on_connected(
        &mut self,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError> {
        self.event_channel_sender = Some(event_channel_sender.clone());

        for processor in self.channel_processors.values() {
            processor
                .lock()
                .unwrap()
                .deref_mut()
                .on_connected(event_channel_sender)?;
        }

        Ok(())
    }

    fn process_outbound_messages(&mut self) -> Result<(), AppError> {
        // Process management request(s)
        for processor in self.channel_processors.values() {
            processor
                .lock()
                .unwrap()
                .deref_mut()
                .process_outbound_messages()?;
        }

        // Send pending outbound messages to gateway
        while let Some(pdu) = self.message_outbox.lock().unwrap().pop_front() {
            self.send_connection_event_message(conn_std::ConnectionEvent::Write(pdu))?;
        }

        Ok(())
    }

    fn process_inbound_messages(&mut self, message_bytes: &[u8]) -> Result<(), AppError> {
        self.message_inbox
            .append(&mut VecDeque::from(message_bytes.to_vec()));

        loop {
            let gateway_message = match MessageFrame::consume_next_pdu(&mut self.message_inbox)? {
                Some(msg_frame) => msg_frame,
                None => return Ok(()),
            };

            // Process message by channel type
            if let Some(processor) = self.channel_processors.get(&gateway_message.channel) {
                processor
                    .lock()
                    .unwrap()
                    .process_inbound_message(gateway_message)?;
            }
        }
    }
}

/// Control plane inbound/outbound message processor
pub trait MessageProcessor {
    /// Control plane (successfully) connected event handler
    ///
    /// # Arguments
    ///
    /// * `event_channel_sender` - Channel sender for connection event messages
    ///
    fn on_connected(
        &mut self,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError>;

    /// Process potential control plane outbound message(s). Will generate and send message PDUs to gateway if necessary.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_outbound_messages(&mut self) -> Result<(), AppError>;

    /// Process gateway message data bytes. If this (in additional to previous unprocessed inbound message bytes)
    /// doesn't result in a complete PDU, then this will be appended to the buffer for next invocation.
    ///
    /// # Arguments
    ///
    /// * `message_bytes` - PDU message byte array to be included in inbound buffer
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_messages(&mut self, message_bytes: &[u8]) -> Result<(), AppError>;
}

/// Control plane channel (management or signaling) message processor
pub trait ChannelProcessor {
    /// Control plane (successfully) connected event handler
    ///
    /// # Arguments
    ///
    /// * `event_channel_sender` - Channel sender for connection event messages
    ///
    fn on_connected(
        &mut self,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError>;

    /// Process (potential) control plane channel outbound messages.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_outbound_messages(&mut self) -> Result<(), AppError>;

    /// Process gateway message frame.
    ///
    /// # Arguments
    ///
    /// * `message` - PDU message frame (should be appropriate for given channel type)
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_message(&mut self, message: MessageFrame) -> Result<(), AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use crate::service::manager;
    use mockall::{mock, predicate};
    use std::sync::mpsc;
    use std::sync::mpsc::TryRecvError;

    // mocks
    // =====

    mock! {
        pub GwMsgProcessor {}
        impl MessageProcessor for GwMsgProcessor {
            fn on_connected(&mut self, event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>) -> Result<(), AppError>;
            fn process_outbound_messages(&mut self) -> Result<(), AppError>;
            fn process_inbound_messages(&mut self, message_bytes: &[u8]) -> Result<(), AppError>;
        }
    }

    mock! {
        pub ChannelProc {}
        impl ChannelProcessor for ChannelProc {
            fn on_connected(
                &mut self,
                event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
            ) -> Result<(), AppError>;
            fn process_outbound_messages(&mut self) -> Result<(), AppError>;
            fn process_inbound_message(&mut self, message: MessageFrame) -> Result<(), AppError>;
        }
    }

    // tests
    // =====

    #[test]
    fn ctlplane_new() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));

        let result = ControlPlane::new(
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service_mgr,
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let control_plane = result.unwrap();

        assert!(control_plane.event_channel_sender.is_none());
        assert!(control_plane.message_inbox.is_empty());
        assert!(control_plane.message_outbox.lock().unwrap().is_empty());
        assert!(control_plane
            .channel_processors
            .contains_key(&ControlChannel::Management));
        assert!(control_plane
            .channel_processors
            .contains_key(&ControlChannel::Signaling));
    }

    #[test]
    fn ctlplane_send_connection_event_when_no_errors() {
        let event_channel = mpsc::channel();

        let control_plane = ControlPlane {
            event_channel_sender: Some(event_channel.0),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::new(),
            channel_processors: HashMap::new(),
        };

        if let Err(err) = control_plane
            .send_connection_event_message(conn_std::ConnectionEvent::Write(vec![0x20]))
        {
            panic!("Unexpected send result: err={:?}", &err);
        }

        match event_channel.1.try_recv() {
            Ok(msg) => match msg {
                conn_std::ConnectionEvent::Write(data) if data == vec![0x20] => {}
                _ => panic!("Unexpected recv result: msg={:?}", &msg),
            },
            Err(err) => panic!("Unexpected recv result: err={:?}", &err),
        }
    }

    #[test]
    fn ctlplane_send_connection_event_when_error() {
        let control_plane = ControlPlane {
            event_channel_sender: Some(mpsc::channel().0),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::new(),
            channel_processors: HashMap::new(),
        };

        if let Ok(msg) = control_plane
            .send_connection_event_message(conn_std::ConnectionEvent::Write(vec![0x20]))
        {
            panic!("Unexpected successful send result: msg={:?}", &msg);
        }
    }

    #[test]
    fn ctlplane_on_connected() {
        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_on_connected()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(()));
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_on_connected()
            .with(predicate::always())
            .times(1)
            .return_once(|_| Ok(()));
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(
            ControlChannel::Management,
            Arc::new(Mutex::new(mgmt_controller)),
        );
        channel_processors.insert(
            ControlChannel::Signaling,
            Arc::new(Mutex::new(signal_controller)),
        );

        let mut control_plane = ControlPlane {
            event_channel_sender: None,
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::new(),
            channel_processors,
        };

        if let Err(err) = control_plane.on_connected(&mpsc::channel().0) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(control_plane.event_channel_sender.is_some());
    }

    #[test]
    fn ctlplane_process_outbound_messages_when_queued_message() {
        let (channel_sender, channel_receiver) = mpsc::channel();

        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_process_outbound_messages()
            .times(1)
            .return_once(|| Ok(()));
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_process_outbound_messages()
            .times(1)
            .return_once(|| Ok(()));
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(
            ControlChannel::Management,
            Arc::new(Mutex::new(mgmt_controller)),
        );
        channel_processors.insert(
            ControlChannel::Signaling,
            Arc::new(Mutex::new(signal_controller)),
        );

        let expected_pdu = vec![65, 66, 67];

        let mut control_plane = ControlPlane {
            event_channel_sender: Some(channel_sender),
            message_outbox: Arc::new(Mutex::new(VecDeque::from(vec![expected_pdu.clone()]))),
            message_inbox: VecDeque::new(),
            channel_processors,
        };

        let result = control_plane.process_outbound_messages();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match channel_receiver.try_recv() {
            Ok(conn_event) => match conn_event {
                conn_std::ConnectionEvent::Closing => panic!("Unexpected Closing connection event"),
                conn_std::ConnectionEvent::Closed => panic!("Unexpected Closed connection event"),
                conn_std::ConnectionEvent::Write(pdu) => assert_eq!(pdu, expected_pdu),
            },
            Err(err) => panic!("Unexpected channel receive result: err={:?}", &err),
        }
    }

    #[test]
    fn ctlplane_process_outbound_messages_when_no_queued_message() {
        let (channel_sender, channel_receiver) = mpsc::channel();

        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_process_outbound_messages()
            .times(1)
            .return_once(|| Ok(()));
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_process_outbound_messages()
            .times(1)
            .return_once(|| Ok(()));
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(
            ControlChannel::Management,
            Arc::new(Mutex::new(mgmt_controller)),
        );
        channel_processors.insert(
            ControlChannel::Signaling,
            Arc::new(Mutex::new(signal_controller)),
        );

        let mut control_plane = ControlPlane {
            event_channel_sender: Some(channel_sender),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::new(),
            channel_processors,
        };

        let result = control_plane.process_outbound_messages();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        match channel_receiver.try_recv() {
            Ok(conn_event) => panic!(
                "Unexpected connection event message received: evt={:?}",
                &conn_event
            ),
            Err(err) if TryRecvError::Disconnected == err => {
                panic!("Unexpected channel receive result: err={:?}", &err)
            }
            _ => {}
        }
    }

    #[test]
    fn ctlplane_process_inbound_messages_when_insufficient_pdu_bytes() {
        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_process_inbound_message()
            .with(predicate::always())
            .never();
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_process_inbound_message()
            .with(predicate::always())
            .never();
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(
            ControlChannel::Management,
            Arc::new(Mutex::new(mgmt_controller)),
        );
        channel_processors.insert(
            ControlChannel::Signaling,
            Arc::new(Mutex::new(signal_controller)),
        );

        let mut control_plane = ControlPlane {
            event_channel_sender: Some(mpsc::channel().0),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::new(),
            channel_processors,
        };

        let result = control_plane.process_inbound_messages(vec![0, 10, 65, 66, 67].as_slice());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn ctlplane_process_inbound_messages_when_valid_mgmt_pdu() {
        let msg_frame_json =
            r#"{"channel":"Management","code":200,"message":"msg1","context":"Start","data":[1]}"#;
        let mgmt_msg_frame: MessageFrame = serde_json::from_str(msg_frame_json).unwrap();
        let mut mgmt_pdu: Vec<u8> = vec![];
        mgmt_pdu.append(&mut (msg_frame_json.len() as u16).to_be_bytes().to_vec());
        mgmt_pdu.append(&mut msg_frame_json.as_bytes().to_vec());
        let (mgmt_pdu0, mgmt_pdu1) = mgmt_pdu.split_at(mgmt_pdu.len() / 2);

        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_process_inbound_message()
            .with(predicate::eq(mgmt_msg_frame.clone()))
            .times(1)
            .return_once(|_| Ok(()));
        let mut signal_controller = MockChannelProc::new();
        signal_controller.expect_process_inbound_message().never();
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(
            ControlChannel::Management,
            Arc::new(Mutex::new(mgmt_controller)),
        );
        channel_processors.insert(
            ControlChannel::Signaling,
            Arc::new(Mutex::new(signal_controller)),
        );

        let mut control_plane = ControlPlane {
            event_channel_sender: Some(mpsc::channel().0),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::from(mgmt_pdu0.to_vec()),
            channel_processors,
        };

        let result = control_plane.process_inbound_messages(mgmt_pdu1);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn ctlplane_process_inbound_messages_when_non_control_plane_pdu() {
        let msg_frame_json =
            r#"{"channel":"TLS","code":200,"message":"msg1","context":null,"data":[1]}"#;
        let mut tls_pdu: Vec<u8> = vec![];
        tls_pdu.append(&mut (msg_frame_json.len() as u16).to_be_bytes().to_vec());
        tls_pdu.append(&mut msg_frame_json.as_bytes().to_vec());
        let (tls_pdu0, tls_pdu1) = tls_pdu.split_at(tls_pdu.len() / 2);

        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller.expect_process_inbound_message().never();
        let mut signal_controller = MockChannelProc::new();
        signal_controller.expect_process_inbound_message().never();
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(
            ControlChannel::Management,
            Arc::new(Mutex::new(mgmt_controller)),
        );
        channel_processors.insert(
            ControlChannel::Signaling,
            Arc::new(Mutex::new(signal_controller)),
        );

        let mut control_plane = ControlPlane {
            event_channel_sender: Some(mpsc::channel().0),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            message_inbox: VecDeque::from(tls_pdu0.to_vec()),
            channel_processors,
        };

        let result = control_plane.process_inbound_messages(tls_pdu1);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
