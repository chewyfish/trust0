mod certificate_reissue;
mod proxy_connections;

use std::collections::{HashMap, VecDeque};
use std::ops::DerefMut;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::client::controller::signaling::certificate_reissue::CertReissuanceProcessor;
use crate::client::controller::signaling::proxy_connections::ProxyConnectionsProcessor;
use crate::client::controller::{ChannelProcessor, ControlPlane};
use crate::client::device::Device;
use crate::config::AppConfig;
use crate::service::manager::ServiceMgr;
use trust0_common::control::pdu::{ControlChannel, MessageFrame};
use trust0_common::control::signaling::event::{EventType, SignalEvent};
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::net::tls_server::conn_std;
use trust0_common::{sync, target};

pub const EVENT_LOOP_CYCLE_DELAY_MSECS: u64 = 6_000;

/// Process signaling control plane event messages
pub struct SignalingController {
    /// Channel sender for connection events
    event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
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
    /// * `event_channel_sender` - Channel sender for connection events
    /// * `user` - User model object
    /// * `device` - Certificate device context
    /// * `message_outbox` - Queued PDU responses to be sent to client
    ///
    /// # Returns
    ///
    /// A newly constructed [`SignalingController`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
        device: &Device,
        message_outbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Self {
        let mut event_processors: HashMap<EventType, Rc<Mutex<dyn SignalingEventHandler>>> =
            HashMap::new();
        let mut message_inbox: HashMap<EventType, VecDeque<SignalEvent>> = HashMap::new();

        if app_config.ca_enabled {
            let cert_reissue_processor = Rc::new(Mutex::new(CertReissuanceProcessor::new(
                app_config,
                message_outbox,
                device,
            )));
            event_processors.insert(EventType::CertificateReissue, cert_reissue_processor);
            message_inbox.insert(EventType::CertificateReissue, VecDeque::new());
        }

        let device_id = device.get_id();

        let proxy_conns_processor = Rc::new(Mutex::new(ProxyConnectionsProcessor::new(
            service_mgr,
            device_id.as_str(),
            message_outbox,
        )));
        event_processors.insert(EventType::ProxyConnections, proxy_conns_processor);
        message_inbox.insert(EventType::ProxyConnections, VecDeque::new());

        Self {
            event_channel_sender: event_channel_sender.clone(),
            event_processors,
            message_inbox: Arc::new(Mutex::new(message_inbox)),
            event_loop_processing: Arc::new(Mutex::new(false)),
        }
    }

    /// Spawn thread to start an event loop to process signaling events
    ///
    /// # Arguments
    ///
    /// * `channel_processors` - Control plane channel processors
    /// * `signal_controller` - The [`SignalingController`] to use for the event loop processor
    /// * `loop_cycle_delay` - Duration to sleep each cycle iteration. If not supplied, uses default [`EVENT_LOOP_CYCLE_DELAY_MSECS`].
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating the success/failure of the spawning operation.
    ///
    pub fn spawn_event_loop(
        channel_processors: &HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>>,
        signal_controller: &Arc<Mutex<SignalingController>>,
        loop_cycle_delay: Option<Duration>,
    ) -> Result<(), AppError> {
        let channel_processors = channel_processors.clone();
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

                let is_authenticated = ControlPlane::is_authenticated(&channel_processors);

                for (event_type, event_processor) in &controller.lock().unwrap().event_processors {
                    if let Err(err) = event_processor.lock().unwrap().on_loop_cycle(
                        message_inbox
                            .lock()
                            .unwrap()
                            .get_mut(event_type)
                            .unwrap()
                            .drain(..)
                            .collect::<VecDeque<_>>(),
                        is_authenticated,
                    ) {
                        error(&target!(), &format!("{:?}", &err));

                        *loop_processing.lock().unwrap() = false;

                        if let Err(err) = sync::send_mpsc_channel_message(
                            &event_channel_sender,
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

    fn is_authenticated(&self) -> Option<bool> {
        None
    }
}

/// Control plane signaling event handler
pub trait SignalingEventHandler {
    /// Event loop cycle tick handler. Will pass in any available messages (appropriate for event type)
    ///
    /// # Arguments
    ///
    /// * `signal_events` - Signal message events (should be appropriate for given signaling event type)
    /// * `is_authenticated` - Current (secondary) authentication state
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation. Upon failure, the client session
    /// (control plane and all service proxy connections) will be shut down.
    ///
    fn on_loop_cycle(
        &mut self,
        signal_events: VecDeque<SignalEvent>,
        is_authenticated: bool,
    ) -> Result<(), AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::client::controller::tests::{create_device, MockChannelProc};
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
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
            fn on_loop_cycle(
                &mut self,
                signal_events: VecDeque<SignalEvent>,
                is_authenticated: bool,
            ) -> Result<(), AppError>;
        }
    }

    // utils
    // =====

    fn create_controller(
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
        certificate_reissue_processor: Rc<Mutex<dyn SignalingEventHandler>>,
        proxy_connections_processor: Rc<Mutex<dyn SignalingEventHandler>>,
    ) -> Result<SignalingController, AppError> {
        Ok(SignalingController {
            event_channel_sender,
            event_processors: HashMap::from([
                (EventType::CertificateReissue, certificate_reissue_processor),
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
    fn sigcontrol_new_with_ca_enabled() {
        let mut app_config = config::tests::create_app_config_with_repos(
            config::GatewayType::Client,
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_enabled = true;
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));

        let controller = SignalingController::new(
            &Arc::new(app_config),
            &service_mgr,
            &mpsc::channel().0,
            &create_device().unwrap(),
            &Arc::new(Mutex::new(VecDeque::new())),
        );

        assert_eq!(controller.event_processors.len(), 2);
        assert!(controller
            .event_processors
            .contains_key(&EventType::CertificateReissue));
        assert!(controller
            .event_processors
            .contains_key(&EventType::ProxyConnections));
        assert_eq!(controller.message_inbox.lock().unwrap().len(), 2);
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .contains_key(&EventType::CertificateReissue));
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .contains_key(&EventType::ProxyConnections));
    }

    #[test]
    fn sigcontrol_new_with_ca_disabled() {
        let mut app_config = config::tests::create_app_config_with_repos(
            config::GatewayType::Client,
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_enabled = false;
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));

        let controller = SignalingController::new(
            &Arc::new(app_config),
            &service_mgr,
            &mpsc::channel().0,
            &create_device().unwrap(),
            &Arc::new(Mutex::new(VecDeque::new())),
        );

        assert_eq!(controller.event_processors.len(), 1);
        assert!(controller
            .event_processors
            .contains_key(&EventType::ProxyConnections));
        assert_eq!(controller.message_inbox.lock().unwrap().len(), 1);
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .contains_key(&EventType::ProxyConnections));
    }

    #[test]
    fn sigcontrol_spawn_event_loop_when_inbox_has_message() {
        let mut cert_reissue_processor = MockSigEvtHandler::new();
        cert_reissue_processor
            .expect_on_loop_cycle()
            .with(predicate::always(), predicate::always())
            .return_once(|_, _| Ok(()));
        let mut proxy_conns_processor = MockSigEvtHandler::new();
        proxy_conns_processor
            .expect_on_loop_cycle()
            .with(predicate::always(), predicate::always())
            .return_once(|_, _| Ok(()));
        let controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(cert_reissue_processor)),
            Rc::new(Mutex::new(proxy_conns_processor)),
        )
        .unwrap();
        let mut mgmt_channel_processor = MockChannelProc::new();
        mgmt_channel_processor
            .expect_is_authenticated()
            .returning(|| Some(true));
        let mgmt_channel_processor: Arc<Mutex<dyn ChannelProcessor>> =
            Arc::new(Mutex::new(mgmt_channel_processor));
        let channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::from([(ControlChannel::Management, mgmt_channel_processor)]);

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
            &channel_processors,
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
            .with(predicate::always(), predicate::always())
            .return_once(|_, _| Ok(()));
        let mut proxy_conns_processor = MockSigEvtHandler::new();
        proxy_conns_processor
            .expect_on_loop_cycle()
            .with(predicate::always(), predicate::always())
            .return_once(|_, _| Ok(()));
        let controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(cert_reissue_processor)),
            Rc::new(Mutex::new(proxy_conns_processor)),
        )
        .unwrap();
        let mut mgmt_channel_processor = MockChannelProc::new();
        mgmt_channel_processor
            .expect_is_authenticated()
            .returning(|| Some(true));
        let mgmt_channel_processor: Arc<Mutex<dyn ChannelProcessor>> =
            Arc::new(Mutex::new(mgmt_channel_processor));
        let channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::from([(ControlChannel::Management, mgmt_channel_processor)]);

        let event_loop_processing = controller.event_loop_processing.clone();
        let message_inbox = controller.message_inbox.clone();

        let controller = Arc::new(Mutex::new(controller));

        let result = SignalingController::spawn_event_loop(
            &channel_processors,
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
            .with(predicate::always(), predicate::always())
            .return_once(|_, _| Ok(()));
        let mut proxy_conns_processor = MockSigEvtHandler::new();
        proxy_conns_processor
            .expect_on_loop_cycle()
            .with(predicate::always(), predicate::always())
            .return_once(|_, _| Err(AppError::General("process error".to_string())));
        let event_channel = mpsc::channel();
        let controller = create_controller(
            event_channel.0,
            Rc::new(Mutex::new(cert_reissue_processor)),
            Rc::new(Mutex::new(proxy_conns_processor)),
        )
        .unwrap();
        let mut mgmt_channel_processor = MockChannelProc::new();
        mgmt_channel_processor
            .expect_is_authenticated()
            .returning(|| Some(true));
        let mgmt_channel_processor: Arc<Mutex<dyn ChannelProcessor>> =
            Arc::new(Mutex::new(mgmt_channel_processor));
        let channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::from([(ControlChannel::Management, mgmt_channel_processor)]);

        let event_loop_processing = controller.event_loop_processing.clone();
        let message_inbox = controller.message_inbox.clone();

        let controller = Arc::new(Mutex::new(controller));

        let result = SignalingController::spawn_event_loop(
            &channel_processors,
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
            .get(&EventType::CertificateReissue)
            .is_some());
        assert!(controller
            .message_inbox
            .lock()
            .unwrap()
            .get(&EventType::CertificateReissue)
            .unwrap()
            .is_empty());
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

    #[test]
    fn sigcontrol_is_authenticated() {
        let controller = create_controller(
            mpsc::channel().0,
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
            Rc::new(Mutex::new(MockSigEvtHandler::new())),
        )
        .unwrap();

        assert!(controller.is_authenticated().is_none());
    }
}
