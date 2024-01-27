mod management;

use std::collections::VecDeque;
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
use trust0_common::control::message::{ControlChannel, MessageFrame};
use trust0_common::error::AppError;
use trust0_common::model;
use trust0_common::net::tls_server::conn_std::TlsServerConnection;
use trust0_common::net::tls_server::{conn_std, server_std};

/// Control plane processor. Handles management and signaling channel messages
pub struct ControlPlane {
    /// Application configuration object
    _app_config: Arc<AppConfig>,
    /// Channel sender for connection events
    event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
    /// Queued inbound PDU messages to be processed
    message_inbox: VecDeque<u8>,
    /// Queued outbound PDU messages to be sent to client
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Management channel controller
    management_controller: Box<dyn ChannelProcessor>,
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
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        access_repo: Arc<Mutex<dyn AccessRepository>>,
        service_repo: Arc<Mutex<dyn ServiceRepository>>,
        user_repo: Arc<Mutex<dyn UserRepository>>,
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
        device: Device,
        user: model::user::User,
    ) -> Result<Self, AppError> {
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));
        Ok(Self {
            _app_config: app_config.clone(),
            event_channel_sender: event_channel_sender.clone(),
            message_inbox: VecDeque::new(),
            message_outbox: message_outbox.clone(),
            management_controller: Box::new(management::ManagementController::new(
                app_config,
                service_mgr,
                access_repo,
                service_repo,
                user_repo,
                event_channel_sender,
                device,
                user,
                message_outbox,
            )?),
        })
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
        if let Err(err) = self.event_channel_sender.send(message).map_err(|err| {
            AppError::GenWithMsgAndErr("Error sending connection event".to_string(), Box::new(err))
        }) {
            let _ = self
                .event_channel_sender
                .send(conn_std::ConnectionEvent::Closing);

            return Err(err);
        }

        Ok(())
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
            match &client_message.channel {
                ControlChannel::Management => self
                    .management_controller
                    .process_inbound_messages(client_message)?,

                ControlChannel::Signaling => {}
            }
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
        self.management_controller.is_authenticated()
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

    /// Returns (secondary) authentication state
    ///
    /// # Returns
    ///
    /// Whether or not session has passed (secondary) authentication.
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
    pub fn new(app_config: Arc<AppConfig>, service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {
        Self {
            app_config,
            service_mgr,
        }
    }
}

impl server_std::ServerVisitor for ControlPlaneServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
    ) -> Result<conn_std::Connection, AppError> {
        let mut conn_visitor =
            ClientConnVisitor::new(self.app_config.clone(), self.service_mgr.clone());

        let alpn_protocol = conn_visitor.process_authorization(&tls_conn, None)?;

        let connection =
            conn_std::Connection::new(Box::new(conn_visitor), tls_conn, alpn_protocol)?;

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
pub trait ChannelProcessor {
    /// Process (potential) control plane channel message.
    ///
    /// # Arguments
    ///
    /// * `message` - PDU message frame (should be appropriate for given channel type)
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_messages(&mut self, message: MessageFrame) -> Result<(), AppError>;

    /// Returns (secondary) authentication state
    ///
    /// # Returns
    ///
    /// Whether the session has been authenticated.
    ///
    fn is_authenticated(&self) -> bool;
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
            fn process_inbound_messages(&mut self, message: MessageFrame) -> Result<(), AppError>;
            fn is_authenticated(&self) -> bool;
        }
    }

    // utils
    // =====

    pub fn create_device() -> Result<Device, AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().unwrap().to_string())?;
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

    // tests
    // =====

    #[test]
    fn ctlplane_new() {
        let mut service_repo = MockServiceRepo::new();
        service_repo
            .expect_get_all()
            .times(1)
            .return_once(|| Ok(vec![]));

        let access_repo = Arc::new(Mutex::new(MockAccessRepo::new()));
        let service_repo = Arc::new(Mutex::new(service_repo));
        let user_repo = Arc::new(Mutex::new(MockUserRepo::new()));
        let mut app_config = config::tests::create_app_config_with_repos(
            user_repo.clone(),
            service_repo.clone(),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            access_repo.clone(),
        )
        .unwrap();
        app_config.mfa_scheme = AuthnType::Insecure;

        let control_plane = ControlPlane::new(
            Arc::new(app_config),
            Arc::new(Mutex::new(MockSvcMgr::new())),
            access_repo,
            service_repo,
            user_repo,
            mpsc::channel().0,
            create_device().unwrap(),
            create_user(),
        );

        if let Err(err) = control_plane {
            panic!("Unexpected result: err={:?}", &err);
        }

        let control_plane = control_plane.unwrap();

        assert!(control_plane.message_inbox.is_empty());
        assert!(control_plane.message_outbox.lock().unwrap().is_empty());
    }

    #[test]
    fn ctlplane_send_connection_event_when_no_errors() {
        let event_channel = mpsc::channel();
        let control_plane = ControlPlane {
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: event_channel.0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            management_controller: Box::new(MockChannelProc::new()),
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
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            management_controller: Box::new(MockChannelProc::new()),
        };

        if let Ok(msg) = control_plane
            .send_connection_event_message(conn_std::ConnectionEvent::Write(vec![0x20]))
        {
            panic!("Unexpected successful send result: msg={:?}", &msg);
        }
    }

    #[test]
    fn ctlplane_process_inbound_messages_when_insufficient_pdu_bytes() {
        let mut mgt_controller = MockChannelProc::new();
        mgt_controller
            .expect_process_inbound_messages()
            .with(predicate::always())
            .never();

        let mut control_plane = ControlPlane {
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            management_controller: Box::new(mgt_controller),
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

        let mut mgt_controller = MockChannelProc::new();
        mgt_controller
            .expect_process_inbound_messages()
            .with(predicate::eq(mgmt_msg_frame))
            .times(1)
            .return_once(|_| Ok(()));

        let mut control_plane = ControlPlane {
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::from(mgmt_pdu0.to_vec()),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            management_controller: Box::new(mgt_controller),
        };

        let result = control_plane.process_inbound_messages(mgmt_pdu1);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn ctlplane_process_outbound_messages_when_queued_message() {
        let (channel_sender, channel_receiver) = mpsc::channel();

        let expected_pdu = vec![65, 66, 67];

        let mut control_plane = ControlPlane {
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: channel_sender,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::from(vec![expected_pdu.clone()]))),
            management_controller: Box::new(MockChannelProc::new()),
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
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: channel_sender,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            management_controller: Box::new(MockChannelProc::new()),
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
    fn ctlplane_is_authenticated() {
        let mut mgt_controller = MockChannelProc::new();
        mgt_controller
            .expect_is_authenticated()
            .times(1)
            .return_once(|| true);

        let control_plane = ControlPlane {
            _app_config: Arc::new(
                config::tests::create_app_config_with_repos(
                    Arc::new(Mutex::new(MockUserRepo::new())),
                    Arc::new(Mutex::new(MockServiceRepo::new())),
                    Arc::new(Mutex::new(MockRoleRepo::new())),
                    Arc::new(Mutex::new(MockAccessRepo::new())),
                )
                .unwrap(),
            ),
            event_channel_sender: mpsc::channel().0,
            message_inbox: VecDeque::new(),
            message_outbox: Arc::new(Mutex::new(VecDeque::new())),
            management_controller: Box::new(mgt_controller),
        };

        assert!(control_plane.is_authenticated());
    }
}
