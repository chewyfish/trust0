mod certificate_reissue;
mod proxy_connections;

use std::collections::{HashMap, VecDeque};
use std::ops::DerefMut;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::config::AppConfig;
use crate::gateway::controller::signaling::certificate_reissue::CertReissuanceProcessor;
use crate::gateway::controller::signaling::proxy_connections::ProxyConnectionsProcessor;
use crate::gateway::controller::ChannelProcessor;
use crate::service::manager::ServiceMgr;
use trust0_common::control::pdu::MessageFrame;
use trust0_common::control::signaling::event::{EventType, SignalEvent};
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::net::tls_client::conn_std;
use trust0_common::{sync, target};

const EVENT_LOOP_CYCLE_DELAY_MSECS: u64 = 6_000;

/// Process signaling control plane event messages
pub struct SignalingController {
    /// Channel sender for connection events
    event_channel_sender: Option<mpsc::Sender<conn_std::ConnectionEvent>>,
    /// Signaling event processors
    event_processors: HashMap<EventType, Rc<Mutex<dyn SignalingEventHandler>>>,
    /// Signaling event message inbox
    message_inbox: Arc<Mutex<HashMap<EventType, VecDeque<SignalEvent>>>>,
    /// Event loop processing state
    event_loop_processing: Arc<Mutex<bool>>,
}

impl SignalingController {
    /// SignalingController constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    /// * `message_outbox` - Queued PDU responses to be sent to client
    ///
    /// # Returns
    ///
    /// A newly constructed [`SignalingController`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        message_outbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Self {
        let cert_reissue_processor = Rc::new(Mutex::new(CertReissuanceProcessor::new(
            &app_config.console_shell_output,
        )));
        let proxy_conns_processor = Rc::new(Mutex::new(ProxyConnectionsProcessor::new(
            service_mgr,
            message_outbox,
        )));

        let mut event_processors: HashMap<EventType, Rc<Mutex<dyn SignalingEventHandler>>> =
            HashMap::new();
        event_processors.insert(EventType::CertificateReissue, cert_reissue_processor);
        event_processors.insert(EventType::ProxyConnections, proxy_conns_processor);

        Self {
            event_channel_sender: None,
            event_processors,
            message_inbox: Arc::new(Mutex::new(HashMap::from([
                (EventType::CertificateReissue, VecDeque::new()),
                (EventType::ProxyConnections, VecDeque::new()),
            ]))),
            event_loop_processing: Arc::new(Mutex::new(false)),
        }
    }

    /// Spawn thread to start an event loop to process signaling events
    ///
    /// # Arguments
    ///
    /// * `signal_controller` - The [`SignalingController`] to use for the event loop processor
    /// * `loop_cycle_delay` - Duration to sleep each cycle iteration. If not supplied, uses default [`EVENT_LOOP_CYCLE_DELAY_MSECS`].
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating the success/failure of the spawning operation.
    ///
    pub fn spawn_event_loop(
        signal_controller: &Arc<Mutex<SignalingController>>,
        loop_cycle_delay: Option<Duration>,
    ) -> Result<(), AppError> {
        let controller = signal_controller.clone();

        thread::spawn(move || {
            let loop_cycle_delay =
                loop_cycle_delay.unwrap_or(Duration::from_millis(EVENT_LOOP_CYCLE_DELAY_MSECS));
            let loop_processing = controller.lock().unwrap().event_loop_processing.clone();
            let message_inbox = controller.lock().unwrap().message_inbox.clone();
            let event_channel_sender = controller.lock().unwrap().event_channel_sender.clone();
            *loop_processing.lock().unwrap() = true;

            loop {
                if !*loop_processing.lock().unwrap() {
                    break;
                }

                for (event_type, event_processor) in &controller.lock().unwrap().event_processors {
                    if let Err(err) = event_processor.lock().unwrap().on_loop_cycle(
                        message_inbox
                            .lock()
                            .unwrap()
                            .get_mut(event_type)
                            .unwrap()
                            .drain(..)
                            .collect::<VecDeque<_>>(),
                    ) {
                        error(&target!(), &format!("{:?}", &err));

                        *loop_processing.lock().unwrap() = false;

                        if let Err(err) = sync::send_mpsc_channel_message(
                            event_channel_sender.as_ref().unwrap(),
                            conn_std::ConnectionEvent::Closing,
                            Box::new(|| "Error sending closing event:".to_string()),
                        ) {
                            println!("{:?}", &err);
                            error(&target!(), &format!("{:?}", &err));
                        }
                    }
                }

                thread::sleep(loop_cycle_delay);
            }
        });

        Ok(())
    }
}

unsafe impl Send for SignalingController {}

impl Drop for SignalingController {
    fn drop(&mut self) {
        *self.event_loop_processing.lock().unwrap() = false;
    }
}

impl ChannelProcessor for SignalingController {
    fn on_connected(
        &mut self,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError> {
        self.event_channel_sender = Some(event_channel_sender.clone());

        Ok(())
    }

    fn process_outbound_messages(&mut self) -> Result<(), AppError> {
        Ok(())
    }

    fn process_inbound_message(&mut self, message: MessageFrame) -> Result<(), AppError> {
        let signal_event: SignalEvent = message.try_into()?;
        if EventType::General == signal_event.event_type {
            return Ok(());
        }
        self.message_inbox
            .lock()
            .unwrap()
            .deref_mut()
            .get_mut(&signal_event.event_type)
            .unwrap()
            .push_back(signal_event);

        Ok(())
    }
}

/// Control plane signaling event handler
pub trait SignalingEventHandler {
    /// Event loop cycle tick handler. Will pass in any available messages (appropriate for event type)
    ///
    /// # Arguments
    ///
    /// * `signal_events` - Signal message events (should be appropriate for given signaling event type)
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation. Upon failure, the client session
    /// (control plane and all service proxy connections) will be shut down.
    ///
    fn on_loop_cycle(&mut self, signal_events: VecDeque<SignalEvent>) -> Result<(), AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use crate::service::manager::tests::MockSvcMgr;
    use mockall::{mock, predicate};
    use serde_json::json;
    use std::sync::mpsc;
    use trust0_common::control;
    use trust0_common::control::pdu::ControlChannel;

    // mocks
    // =====

    mock! {
        pub SigEvtHandler {}
        impl SignalingEventHandler for SigEvtHandler {
            fn on_loop_cycle(&mut self, signal_events: VecDeque<SignalEvent>) -> Result<(), AppError>;
        }
    }

    // utils
    // =====

    fn create_controller(
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
        cert_reissuance_processor: Rc<Mutex<dyn SignalingEventHandler>>,
        proxy_connections_processor: Rc<Mutex<dyn SignalingEventHandler>>,
    ) -> Result<SignalingController, AppError> {
        Ok(SignalingController {
            event_channel_sender: Some(event_channel_sender),
            event_processors: HashMap::from([
                (EventType::CertificateReissue, cert_reissuance_processor),
                (EventType::ProxyConnections, proxy_connections_processor),
            ]),
            message_inbox: Arc::new(Mutex::new(HashMap::from([
                (EventType::CertificateReissue, VecDeque::new()),
                (EventType::ProxyConnections, VecDeque::new()),
            ]))),
            event_loop_processing: Arc::new(Mutex::new(false)),
        })
    }

    // tests
    // =====

    #[test]
    fn sigcontrol_new() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));
        let _ = SignalingController::new(
            &app_config,
            &service_mgr,
            &Arc::new(Mutex::new(VecDeque::new())),
        );
    }

    #[test]
    fn sigcontrol_spawn_event_loop_when_inbox_has_message() {
        let mut cert_reissue_processor = MockSigEvtHandler::new();
        cert_reissue_processor
            .expect_on_loop_cycle()
            .with(predicate::always())
            .return_once(|_| Ok(()));
        let mut proxy_conns_processor = MockSigEvtHandler::new();
        proxy_conns_processor
            .expect_on_loop_cycle()
            .with(predicate::always())
            .return_once(|_| Ok(()));
        let controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(cert_reissue_processor)),
            Rc::new(Mutex::new(proxy_conns_processor)),
        )
        .unwrap();

        let event_loop_processing = controller.event_loop_processing.clone();
        let message_inbox = controller.message_inbox.clone();
        message_inbox
            .lock()
            .unwrap()
            .get_mut(&EventType::ProxyConnections)
            .unwrap()
            .push_back(SignalEvent::new(
                control::pdu::CODE_OK,
                &None,
                &EventType::ProxyConnections,
                &Some(json!([])),
            ));

        let controller = Arc::new(Mutex::new(controller));

        let result = SignalingController::spawn_event_loop(
            &controller.clone(),
            Some(Duration::from_millis(500)),
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(250));

        if !*event_loop_processing.lock().unwrap() {
            panic!("Event loop processing state not active");
        }

        *event_loop_processing.lock().unwrap() = false;

        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .is_some());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .unwrap()
            .is_empty());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .is_some());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sigcontrol_spawn_event_loop_when_inbox_no_message() {
        let mut cert_reissue_processor = MockSigEvtHandler::new();
        cert_reissue_processor
            .expect_on_loop_cycle()
            .with(predicate::always())
            .return_once(|_| Ok(()));
        let mut proxy_conns_processor = MockSigEvtHandler::new();
        proxy_conns_processor
            .expect_on_loop_cycle()
            .with(predicate::always())
            .return_once(|_| Ok(()));
        let controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(cert_reissue_processor)),
            Rc::new(Mutex::new(proxy_conns_processor)),
        )
        .unwrap();

        let event_loop_processing = controller.event_loop_processing.clone();
        let message_inbox = controller.message_inbox.clone();

        let controller = Arc::new(Mutex::new(controller));

        let result = SignalingController::spawn_event_loop(
            &controller.clone(),
            Some(Duration::from_millis(500)),
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(250));

        if !*event_loop_processing.lock().unwrap() {
            panic!("Event loop processing state not active");
        }

        *event_loop_processing.lock().unwrap() = false;

        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .is_some());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .unwrap()
            .is_empty());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .is_some());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sigcontrol_spawn_event_loop_when_inbox_no_message_and_process_err() {
        let mut cert_reissue_processor = MockSigEvtHandler::new();
        cert_reissue_processor
            .expect_on_loop_cycle()
            .with(predicate::always())
            .return_once(|_| Ok(()));
        let mut proxy_conns_processor = MockSigEvtHandler::new();
        proxy_conns_processor
            .expect_on_loop_cycle()
            .with(predicate::always())
            .return_once(|_| Err(AppError::General("process error".to_string())));
        let event_channel = mpsc::channel();
        let controller = create_controller(
            event_channel.0,
            Rc::new(Mutex::new(cert_reissue_processor)),
            Rc::new(Mutex::new(proxy_conns_processor)),
        )
        .unwrap();

        let event_loop_processing = controller.event_loop_processing.clone();
        let message_inbox = controller.message_inbox.clone();

        let controller = Arc::new(Mutex::new(controller));

        let result = SignalingController::spawn_event_loop(
            &controller.clone(),
            Some(Duration::from_millis(500)),
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(250));

        match event_channel.1.try_recv() {
            Ok(event) => {
                if let conn_std::ConnectionEvent::Closing = event {
                } else {
                    panic!("Unexpected conn event recvd: evt={:?}", event)
                }
            }
            Err(err) => {
                panic!("Unexpected conn event channel result: err={:?}", &err);
            }
        }

        if *event_loop_processing.lock().unwrap() {
            *event_loop_processing.lock().unwrap() = false;
            panic!("Event loop processing state not disabled");
        }

        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .is_some());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .unwrap()
            .is_empty());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .is_some());
        assert!(message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sigcontrol_process_inbound_message_when_wrong_control_channel() {
        let mut controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
        )
        .unwrap();

        let msg_frame = MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &Some("msg1".to_string()),
            &None,
            &Some(json!([])),
        );

        let result = controller.process_inbound_message(msg_frame);

        if let Ok(()) = result {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn sigcontrol_process_inbound_message_when_event_type_is_general() {
        let mut controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
        )
        .unwrap();

        let msg_frame = MessageFrame::new(
            ControlChannel::Signaling,
            control::pdu::CODE_OK,
            &None,
            &Some(json!(EventType::General)),
            &Some(json!([])),
        );

        let result = controller.process_inbound_message(msg_frame);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn sigcontrol_process_inbound_message_when_event_type_is_cert_reissue() {
        let mut controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
        )
        .unwrap();

        let msg_frame = MessageFrame::new(
            ControlChannel::Signaling,
            control::pdu::CODE_OK,
            &None,
            &Some(json!(EventType::CertificateReissue)),
            &Some(json!([])),
        );

        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .is_some());
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .unwrap()
            .is_empty());

        let result = controller.process_inbound_message(msg_frame);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .is_some());
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .unwrap()
            .is_empty());
        assert_eq!(
            controller
                .message_inbox
                .lock()
                .unwrap()
                .get(&EventType::CertificateReissue)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            *controller
                .message_inbox
                .lock()
                .unwrap()
                .get(&EventType::CertificateReissue)
                .unwrap()
                .get(0)
                .unwrap(),
            SignalEvent::new(
                control::pdu::CODE_OK,
                &None,
                &EventType::CertificateReissue,
                &Some(json!([])),
            )
        );
    }

    #[test]
    fn sigcontrol_process_inbound_message_when_event_type_is_proxy_conns() {
        let mut controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
        )
        .unwrap();

        let msg_frame = MessageFrame::new(
            ControlChannel::Signaling,
            control::pdu::CODE_OK,
            &None,
            &Some(json!(EventType::ProxyConnections)),
            &Some(json!([])),
        );

        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .is_some());
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::ProxyConnections)
            .unwrap()
            .is_empty());

        let result = controller.process_inbound_message(msg_frame);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .is_some());
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .unwrap()
            .is_empty());
        assert_eq!(
            controller
                .message_inbox
                .lock()
                .unwrap()
                .get(&EventType::ProxyConnections)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            *controller
                .message_inbox
                .lock()
                .unwrap()
                .get(&EventType::ProxyConnections)
                .unwrap()
                .get(0)
                .unwrap(),
            SignalEvent::new(
                control::pdu::CODE_OK,
                &None,
                &EventType::ProxyConnections,
                &Some(json!([])),
            )
        );
    }
}
