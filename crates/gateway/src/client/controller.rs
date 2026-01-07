mod management;
mod signaling;

use std::collections::{HashMap, VecDeque};
use std::sync::{mpsc, Arc, Mutex};

use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;

use crate::client::connection::ClientConnVisitor;
use crate::client::device::Device;
use crate::config::AppConfig;
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;
use trust0_common::control::pdu::{ControlChannel, MessageFrame};
use trust0_common::control::tls;
use trust0_common::error::AppError;
use trust0_common::net::tls_server::conn_std::TlsServerConnection;
use trust0_common::net::tls_server::{conn_std, server_std};
use trust0_common::{model, sync};

/// Control plane processor. Handles management and signaling channel messages
pub struct ControlPlane {
    /// Channel sender for connection events
    event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
    /// Queued inbound PDU messages to be processed
    message_inbox: VecDeque<u8>,
    /// Queued outbound PDU messages to be sent to client
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Control plane channel processors
    channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>>,
}

impl ControlPlane {
    /// ControlPlane constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    /// * `access_repo` - Access DB repository
    /// * `service_repo` - Service DB repository
    /// * `user_repo` - User DB repository
    /// * `event_channel_sender` - Channel sender for connection events
    /// * `device` - Certificate device context
    /// * `user` - User model object
    ///
    /// # Returns
    ///
    /// a [`Result`] containing a newly constructed [`ControlPlane`] object.
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        access_repo: &Arc<Mutex<dyn AccessRepository>>,
        service_repo: &Arc<Mutex<dyn ServiceRepository>>,
        user_repo: &Arc<Mutex<dyn UserRepository>>,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
        device: &Device,
        user: &model::user::User,
    ) -> Result<Self, AppError> {
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let management_controller = Arc::new(Mutex::new(management::ManagementController::new(
            app_config,
            service_mgr,
            access_repo,
            service_repo,
            user_repo,
            event_channel_sender,
            device,
            user,
            &message_outbox,
        )?));
        let signaling_controller = Arc::new(Mutex::new(signaling::SignalingController::new(
            app_config,
            service_mgr,
            event_channel_sender,
            device,
            &message_outbox,
        )));
        let mut channel_processors: HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>> =
            HashMap::new();
        channel_processors.insert(ControlChannel::Management, management_controller);
        channel_processors.insert(ControlChannel::Signaling, signaling_controller.clone());

        Self::spawn_signaling_event_loop(&channel_processors, &signaling_controller)?;

        Ok(Self {
            event_channel_sender: event_channel_sender.clone(),
            message_inbox: VecDeque::new(),
            message_outbox,
            channel_processors,
        })
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
    #[cfg(not(test))]
    fn spawn_signaling_event_loop(
        channel_processors: &HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>>,
        signal_controller: &Arc<Mutex<signaling::SignalingController>>,
    ) -> Result<(), AppError> {
        signaling::SignalingController::spawn_event_loop(
            channel_processors,
            signal_controller,
            None,
        )
    }
    #[cfg(test)]
    fn spawn_signaling_event_loop(
        _channel_processors: &HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>>,
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
        if let Err(err) = sync::send_mpsc_channel_message(
            &self.event_channel_sender,
            message,
            Box::new(|| "Error sending connection event:".to_string()),
        ) {
            let _ = self
                .event_channel_sender
                .send(conn_std::ConnectionEvent::Closing);

            return Err(err);
        }

        Ok(())
    }

    /// Returns (secondary) authentication state. Each channel processor can decide this state. If not applicable
    /// for a specific channel processor, it will merely return `None`, which implies that the session
    /// is authenticated (as far as it is concerned).
    ///
    /// # Arguments
    ///
    /// * `channel_processors` - Control plane channel processors
    ///
    /// # Returns
    ///
    /// Whether the session has passed (secondary) authentication.
    ///
    pub fn is_authenticated(
        channel_processors: &HashMap<ControlChannel, Arc<Mutex<dyn ChannelProcessor>>>,
    ) -> bool {
        channel_processors
            .values()
            .all(|processor| processor.lock().unwrap().is_authenticated().unwrap_or(true))
    }
}

unsafe impl Send for ControlPlane {}

impl MessageProcessor for ControlPlane {
    fn process_inbound_messages(&mut self, message_bytes: &[u8]) -> Result<(), AppError> {
        self.message_inbox
            .append(&mut VecDeque::from(message_bytes.to_vec()));

        loop {
            let client_message = match MessageFrame::consume_next_pdu(&mut self.message_inbox)? {
                Some(msg_frame) => msg_frame,
                None => return Ok(()),
            };

            // Process message by channel type
            self.channel_processors
                .get(&client_message.channel)
                .unwrap()
                .lock()
                .unwrap()
                .process_inbound_message(client_message)?;
        }
    }

    fn process_outbound_messages(&mut self) -> Result<(), AppError> {
        // Send pending messages to client
        while let Some(pdu) = self.message_outbox.lock().unwrap().pop_front() {
            self.send_connection_event_message(conn_std::ConnectionEvent::Write(pdu))?;
        }

        Ok(())
    }

    fn is_authenticated(&self) -> bool {
        Self::is_authenticated(&self.channel_processors)
    }
}

pub trait MessageProcessor: Send {
    /// Process given client message bytes.  If this (in additional to previous unprocessed message bytes)
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

    /// Process potential control plane responses(s). Will generate and send response message PDUs if necessary.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_outbound_messages(&mut self) -> Result<(), AppError>;

    /// Returns (secondary) authentication state. Each channel processor can decide this state. If not applicable
    /// for a specific channel processor, it will merely return `None`, which implies that the session
    /// is authenticated (as far as it is concerned).
    ///
    /// # Returns
    ///
    /// Whether the session has passed (secondary) authentication.
    ///
    fn is_authenticated(&self) -> bool;
}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct ControlPlaneServerVisitor {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
}

impl ControlPlaneServerVisitor {
    /// ServerVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    ///
    /// # Returns
    ///
    /// A newly constructed [`ControlPlaneServerVisitor`] object.
    ///
    pub fn new(app_config: &Arc<AppConfig>, service_mgr: &Arc<Mutex<dyn ServiceMgr>>) -> Self {
        Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
        }
    }
}

impl server_std::ServerVisitor for ControlPlaneServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
        _client_msg: Option<tls::message::SessionMessage>,
    ) -> Result<conn_std::Connection, AppError> {
        let mut conn_visitor = ClientConnVisitor::new(&self.app_config, &self.service_mgr);

        let session_addrs = &(
            format!("{:?}", &tls_conn.sock.peer_addr()),
            format!("{:?}", &tls_conn.sock.local_addr()),
        );

        let alpn_protocol = conn_visitor.process_authorization(&tls_conn, None)?;

        let connection = conn_std::Connection::new(
            Box::new(conn_visitor),
            tls_conn,
            session_addrs,
            &alpn_protocol,
        )?;

        Ok(connection)
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        server_std::Server::spawn_connection_processor(connection);

        Ok(())
    }
}

/// Control plane channel (management or signaling) message processor
pub trait ChannelProcessor: Send {
    /// Process control plane channel message.
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

    /// Returns (secondary) authentication state. Non-management processors may return `None`, which implies
    /// that they don't have an answer at the current time. In this case the authentication state should solely
    /// be determined by a unanimous consensus (that is, all must be `true` for the session to be authenticated.
    ///
    /// # Returns
    ///
    /// Whether the session has been authenticated or if the authentication state is unknown.
    ///
    fn is_authenticated(&self) -> Option<bool>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::tests::MockSvcMgr;
    use mockall::{mock, predicate};
    use std::path::PathBuf;
    use std::sync::mpsc::TryRecvError;
    use trust0_common::authn::authenticator::AuthnType;
    use trust0_common::crypto::file::load_certificates;

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];

    // mocks
    // =====

    mock! {
        pub MsgProcessor {}
        impl MessageProcessor for MsgProcessor {
            fn process_inbound_messages(&mut self, message_bytes: &[u8]) -> Result<(), AppError>;
            fn process_outbound_messages(&mut self) -> Result<(), AppError>;
            fn is_authenticated(&self) -> bool;
        }
    }

    mock! {
        pub ChannelProc {}
        impl ChannelProcessor for ChannelProc {
            fn process_inbound_message(&mut self, message: MessageFrame) -> Result<(), AppError>;
            fn is_authenticated(&self) -> Option<bool>;
        }
    }

    // utils
    // =====

    pub fn create_device() -> Result<Device, AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap())?;
        Device::new(certs)
    }

    pub fn create_user() -> model::user::User {
        model::user::User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=".to_string()),
            name: "user100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
        }
    }
    pub fn assert_msg_frame_pdu_equality(
        pending_pdus: &Arc<Mutex<VecDeque<Vec<u8>>>>,
        expected_pdu: Vec<u8>,
        max_msg_size: Option<usize>,
    ) {
        assert!(!pending_pdus.lock().unwrap().is_empty());

        let pdu = pending_pdus.lock().unwrap().get(0).unwrap().clone();
        assert!(pdu.len() >= 3);
        assert!(expected_pdu.len() >= 3);

        let (msg_size, msg) = pdu.split_at(std::mem::size_of::<u16>());
        let pdu_msg_size = u16::from_be_bytes(msg_size.try_into().unwrap());
        let mut pdu_msg = String::from_utf8(msg.to_vec()).unwrap();

        let (expected_msg_size, expected_msg) = expected_pdu.split_at(std::mem::size_of::<u16>());
        let expected_pdu_msg_size = u16::from_be_bytes(expected_msg_size.try_into().unwrap());
        let mut expected_pdu_msg = String::from_utf8(expected_msg.to_vec()).unwrap();

        if max_msg_size.is_some() {
            if pdu_msg.len() > max_msg_size.unwrap() {
                pdu_msg = pdu_msg[0..max_msg_size.unwrap()].to_string();
            }
            if expected_pdu_msg.len() > max_msg_size.unwrap() {
                expected_pdu_msg = expected_pdu_msg[0..max_msg_size.unwrap()].to_string();
            }
        }

        assert_eq!(pdu_msg, expected_pdu_msg);

        if max_msg_size.is_none() {
            assert_eq!(pdu_msg_size, expected_pdu_msg_size);
        }
    }

    pub fn assert_msg_frame_pdu_contains(
        pending_pdus: &Arc<Mutex<VecDeque<Vec<u8>>>>,
        expected_pdu_section: &str,
    ) {
        assert!(!pending_pdus.lock().unwrap().is_empty());

        let pdu = pending_pdus.lock().unwrap().get(0).unwrap().clone();
        assert!(pdu.len() >= 3);

        let (msg_size, msg) = pdu.split_at(std::mem::size_of::<u16>());
        let _pdu_msg_size = u16::from_be_bytes(msg_size.try_into().unwrap());
        let pdu_msg = String::from_utf8(msg.to_vec()).unwrap();

        assert!(pdu_msg.contains(expected_pdu_section));
    }

    // tests
    // =====

    #[test]
    fn ctlplane_new() {
        let mut service_repo = MockServiceRepo::new();
        service_repo
            .expect_get_all()
            .times(1)
            .return_once(|| Ok(vec![]));

        let access_repo: Arc<Mutex<dyn AccessRepository>> =
            Arc::new(Mutex::new(MockAccessRepo::new()));
        let service_repo: Arc<Mutex<dyn ServiceRepository>> = Arc::new(Mutex::new(service_repo));
        let user_repo: Arc<Mutex<dyn UserRepository>> = Arc::new(Mutex::new(MockUserRepo::new()));
        let mut app_config = config::tests::create_app_config_with_repos(
            config::GatewayType::Client,
            user_repo.clone(),
            service_repo.clone(),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            access_repo.clone(),
        )
        .unwrap();
        app_config.mfa_scheme = AuthnType::Insecure;
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));

        let control_plane = ControlPlane::new(
            &Arc::new(app_config),
            &service_mgr,
            &access_repo,
            &service_repo,
            &user_repo,
            &mpsc::channel().0,
            &create_device().unwrap(),
            &create_user(),
        );

        if let Err(err) = control_plane {
            panic!("Unexpected result: err={:?}", &err);
        }

        let control_plane = control_plane.unwrap();

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
            event_channel_sender: event_channel.0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
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
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            channel_processors: HashMap::new(),
        };

        if let Ok(msg) = control_plane
            .send_connection_event_message(conn_std::ConnectionEvent::Write(vec![0x20]))
        {
            panic!("Unexpected successful send result: msg={:?}", &msg);
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
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
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
            .with(predicate::eq(mgmt_msg_frame))
            .times(1)
            .return_once(|_| Ok(()));
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
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::from(mgmt_pdu0.to_vec()),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            channel_processors,
        };

        let result = control_plane.process_inbound_messages(mgmt_pdu1);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn ctlplane_process_inbound_messages_when_valid_signal_pdu() {
        let msg_frame_json = r#"{"channel":"Signaling","code":200,"message":"msg1","context":"ProxyConnections","data":[1]}"#;
        let signal_msg_frame: MessageFrame = serde_json::from_str(msg_frame_json).unwrap();
        let mut signal_pdu: Vec<u8> = vec![];
        signal_pdu.append(&mut (msg_frame_json.len() as u16).to_be_bytes().to_vec());
        signal_pdu.append(&mut msg_frame_json.as_bytes().to_vec());
        let (signal_pdu0, signal_pdu1) = signal_pdu.split_at(signal_pdu.len() / 2);

        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_process_inbound_message()
            .with(predicate::always())
            .never();
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_process_inbound_message()
            .with(predicate::eq(signal_msg_frame))
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
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::from(signal_pdu0.to_vec()),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            channel_processors,
        };

        let result = control_plane.process_inbound_messages(signal_pdu1);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn ctlplane_process_outbound_messages_when_queued_message() {
        let (channel_sender, channel_receiver) = mpsc::channel();

        let expected_pdu = vec![65, 66, 67];

        let mut control_plane = ControlPlane {
            event_channel_sender: channel_sender,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::from(vec![expected_pdu.clone()]))),
            channel_processors: HashMap::new(),
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

        let mut control_plane = ControlPlane {
            event_channel_sender: channel_sender,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            channel_processors: HashMap::new(),
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
    fn ctlplane_is_authenticated_when_authed() {
        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_is_authenticated()
            .times(1)
            .return_once(|| Some(true));
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_is_authenticated()
            .times(1)
            .return_once(|| None);
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

        let control_plane = ControlPlane {
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            channel_processors,
        };

        assert!(control_plane.is_authenticated());
    }

    #[test]
    fn ctlplane_is_authenticated_when_not_authed() {
        let mut mgmt_controller = MockChannelProc::new();
        mgmt_controller
            .expect_is_authenticated()
            .times(0..=1)
            .return_once(|| Some(false));
        let mut signal_controller = MockChannelProc::new();
        signal_controller
            .expect_is_authenticated()
            .times(0..=1)
            .return_once(|| None);
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

        let control_plane = ControlPlane {
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            channel_processors,
        };

        assert!(!control_plane.is_authenticated());
    }
}
