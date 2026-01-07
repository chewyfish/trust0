use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use pki_types::CertificateDer;
use x509_parser::nom::AsBytes;

use crate::client::controller::{ControlPlane, MessageProcessor};
use crate::client::device::Device;
use crate::config::{self, AppConfig};
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::logging::{error, info};
use trust0_common::model::user::{Status, User};
use trust0_common::net::tls_server::conn_std::{self, TlsConnection};
use trust0_common::{crypto, sync, target};

/// tls_server::std_conn::Connection strategy visitor pattern implementation
pub struct ClientConnVisitor {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Access DB repository
    access_repo: Arc<Mutex<dyn AccessRepository>>,
    /// Service DB repository
    service_repo: Arc<Mutex<dyn ServiceRepository>>,
    /// User DB repository
    user_repo: Arc<Mutex<dyn UserRepository>>,
    /// Channel sender for connection events
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    /// Control plane message processor
    message_processor: Option<Arc<Mutex<dyn MessageProcessor>>>,
    /// Connection/certificate device context
    device: Option<Device>,
    /// User model object
    user: Option<User>,
    /// ALPN connection protocol
    protocol: Option<alpn::Protocol>,
}

impl ClientConnVisitor {
    /// ClientConnVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ClientConnVisitor`] object.
    ///
    pub fn new(app_config: &Arc<AppConfig>, service_mgr: &Arc<Mutex<dyn ServiceMgr>>) -> Self {
        let access_repo = Arc::clone(&app_config.access_repo);
        let service_repo = Arc::clone(&app_config.service_repo);
        let user_repo = Arc::clone(&app_config.user_repo);

        Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            access_repo,
            service_repo,
            user_repo,
            event_channel_sender: None,
            message_processor: None,
            device: None,
            user: None,
            protocol: None,
        }
    }

    /// Authorize new connection.
    ///
    /// Will validate:
    /// * Trust0 conforming certificate
    /// * connection type
    /// * user existence and status
    /// * service existence
    /// * accessibliliy of service for user
    ///
    /// If valid, will create device and user from peer certificate.
    ///
    /// # Arguments
    ///
    /// * `tls_conn` - TLS connection object
    /// * `service_id` - Service corresponding to connection
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the ALPN protocol for an authorized connection.
    ///
    pub fn process_authorization(
        &mut self,
        tls_conn: &dyn TlsConnection,
        service_id: Option<i64>,
    ) -> Result<alpn::Protocol, AppError> {
        // Parse certificate context details
        let peer_certificates: Vec<CertificateDer<'static>> = tls_conn
            .peer_certificates()
            .ok_or(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                "Empty client certificate chain".to_string(),
            ))?
            .iter()
            .map(|c| crypto::x509::create_der_certificate(c.as_bytes()))
            .collect();

        let device = Device::new(peer_certificates)?;
        let device_id = device.get_id();
        let serial_num = hex::encode(device.get_cert_serial_num());

        // Validate user
        let user_id = device.get_cert_access_context().user_id;

        if user_id == 0 {
            return Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                format!("Invalid certificate user identity: ser={}", &serial_num),
            ));
        }

        let user = self
            .user_repo
            .lock()
            .unwrap()
            .get(user_id)
            .map_err(|err| {
                AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0500_SYSTEM_ERROR,
                    format!(
                        "Error retrieving user from user repo: user_id={}, ser={}, err={:?}",
                        user_id, &serial_num, err
                    ),
                )
            })?
            .ok_or(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0421_UNKNOWN_USER,
                format!(
                    "User is not found in user repo: user_id={}, ser={}",
                    user_id, &serial_num
                ),
            ))?;

        if user.status != Status::Active {
            return Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0422_INACTIVE_USER,
                format!(
                    "User is not active: user_id={}, ser={}, status={:?}",
                    user_id, &serial_num, user.status
                ),
            ));
        }

        // Determine (ALPN) connection protocol
        let alpn_protocol = Self::parse_alpn_protocol(&tls_conn.alpn_protocol())?;

        // Validate service connection
        if let Some(service_id) = service_id {
            // Ensure active control plane for device
            if !self
                .service_mgr
                .lock()
                .unwrap()
                .has_control_plane_for_device(device_id.as_str(), true)
            {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0427_CONTROL_PLANE_NOT_AUTHENTICATED,
                    format!(
                        "Service proxy connections require an authenticated control plane: user_id={}, dev_id={}, ser={}",
                        user_id, device_id.as_str(), &serial_num
                    ),
                ));
            }

            // Validate requested service
            let invalid_service = match alpn_protocol {
                alpn::Protocol::ControlPlane => true,
                alpn::Protocol::Service(alpn_svc_id) => service_id != alpn_svc_id,
            };

            if invalid_service {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                    format!(
                        "ALPN has wrong service ID: user_id={}, dev_id={}, ser={}, alpn={:?}, svc_id={}",
                        user_id, device_id.as_str(), &serial_num, alpn_protocol, service_id
                    ),
                ));
            }

            // Validate service accessibility for user
            if self
                .access_repo
                .lock()
                .unwrap()
                .get_for_user(service_id, &user)?
                .is_none()
            {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0403_FORBIDDEN,
                    format!(
                        "User is not authorized for service: user_id={}, ser={}, svc_id={}",
                        user_id, &serial_num, service_id
                    ),
                ));
            }
        }
        // Validate control plane connection
        else {
            // Ensure no active control plane for device
            if self
                .service_mgr
                .lock()
                .unwrap()
                .has_control_plane_for_device(device_id.as_str(), false)
            {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0426_CONTROL_PLANE_ALREADY_CONNECTED,
                    format!(
                        "Not allowed to have multiple control planes: user_id={}, dev_id={}, ser={}",
                        user_id,
                        device_id.as_str(),
                        &serial_num
                    ),
                ));
            }
        }

        self.device = Some(device);
        self.user = Some(user);
        self.protocol = Some(alpn_protocol.clone());

        info(
            &target!(),
            &format!(
                "Connection authorized: user_id={}, dev_id={}, ser={}, svc_id={:?}",
                user_id,
                device_id.as_str(),
                &serial_num,
                &service_id
            ),
        );

        Ok(alpn_protocol)
    }

    /// Device accessor
    ///
    /// # Returns
    ///
    /// Device associated to connection (if available).
    ///
    pub fn get_device(&self) -> &Option<Device> {
        &self.device
    }

    #[cfg(test)]
    /// Device mutator
    ///
    /// # Arguments
    ///
    /// * `device` - Optional [`Device`] object to set
    ///
    pub fn set_device(&mut self, device: Option<Device>) {
        self.device = device;
    }

    /// User accessor
    ///
    /// # Returns
    ///
    /// User associated to connection (if available).
    ///
    pub fn get_user(&self) -> &Option<User> {
        &self.user
    }

    #[cfg(test)]
    /// User mutator
    ///
    /// # Arguments
    ///
    /// * `user` - Optional [`User`] object to set
    ///
    pub fn set_user(&mut self, user: Option<User>) {
        self.user = user;
    }

    #[cfg(test)]
    /// Protocol mutator
    ///
    /// # Arguments
    ///
    /// * `protocol` - Optional [`alpn::Protocol`] object to set
    ///
    pub fn set_protocol(&mut self, protocol: Option<alpn::Protocol>) {
        self.protocol = protocol;
    }

    /// Parse TLS ALPN protocol. Should be valid [`alpn::Protocol`] string (as represented as byte vector)
    ///
    /// # Arguments
    ///
    /// * `protocol_name` - Byte vector of a protocol string value
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the corresponding [`alpn::Protocol`] object.
    ///
    pub fn parse_alpn_protocol(
        protocol_name: &Option<Vec<u8>>,
    ) -> Result<alpn::Protocol, AppError> {
        match protocol_name {
            None => Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                "Missing ALPN protocol".to_string(),
            )),

            Some(protocol_name_bytes) => {
                let protocol_name = String::from_utf8_lossy(protocol_name_bytes);
                match alpn::Protocol::parse(protocol_name.as_ref()) {
                    None => Err(AppError::GenWithCodeAndMsg(
                        config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                        format!("Invalid ALPN protocol: proto={}", protocol_name.as_ref()),
                    )),
                    Some(alpn_protocol) => Ok(alpn_protocol),
                }
            }
        }
    }
}

impl conn_std::ConnectionVisitor for ClientConnVisitor {
    fn on_connected(
        &mut self,
        event_channel_sender: &Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError> {
        let device = self.device.as_ref().unwrap();
        let user = self.user.as_ref().unwrap();
        if self
            .protocol
            .as_ref()
            .unwrap()
            .eq(&alpn::Protocol::ControlPlane)
        {
            let message_processor: Arc<Mutex<dyn MessageProcessor>> =
                Arc::new(Mutex::new(ControlPlane::new(
                    &self.app_config,
                    &self.service_mgr,
                    &self.access_repo,
                    &self.service_repo,
                    &self.user_repo,
                    event_channel_sender,
                    device,
                    user,
                )?));
            self.service_mgr
                .lock()
                .unwrap()
                .add_control_plane(device.get_id().as_str(), &message_processor)?;
            self.message_processor = Some(message_processor);
        }
        self.event_channel_sender = Some(event_channel_sender.clone());

        Ok(())
    }

    fn on_connection_read(&mut self, data: &[u8]) -> Result<(), AppError> {
        self.message_processor
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .process_inbound_messages(data)
    }

    fn on_polling_cycle(&mut self) -> Result<(), AppError> {
        self.message_processor
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .process_outbound_messages()
    }

    fn on_shutdown(&mut self) -> Result<(), AppError> {
        if self.device.is_none() {
            return Err(AppError::General(
                "Error shutting down connection, unknown device".to_string(),
            ));
        }
        self.service_mgr
            .lock()
            .unwrap()
            .shutdown_connections(Some(self.device.as_ref().unwrap().get_id()), None)
    }

    fn send_error_response(&mut self, err: &AppError) {
        let resp_msgs = &config::RESPONSE_MSGS;

        let unknown_msg = move |code| {
            format!(
                "{}: ref={}",
                resp_msgs.get(&config::RESPCODE_0520_UNKNOWN_CODE).unwrap(),
                code
            )
        };

        let msg = match err {
            AppError::GenWithCode(code) => resp_msgs
                .get(code)
                .map_or(unknown_msg(code), |m| m.to_string()),
            AppError::GenWithCodeAndMsgAndErr(code, _, _) => resp_msgs
                .get(code)
                .map_or(unknown_msg(code), |m| m.to_string()),
            AppError::GenWithCodeAndErr(code, _) => resp_msgs
                .get(code)
                .map_or(unknown_msg(code), |m| m.to_string()),
            AppError::GenWithCodeAndMsg(code, _) => resp_msgs
                .get(code)
                .map_or(unknown_msg(code), |m| m.to_string()),
            _ => resp_msgs
                .get(&config::RESPCODE_0500_SYSTEM_ERROR)
                .unwrap()
                .to_string(),
        };

        let event_sender = self.event_channel_sender.as_ref().unwrap();

        let msg_copy = msg.clone();
        if let Err(err) = sync::send_mpsc_channel_message(
            event_sender,
            conn_std::ConnectionEvent::Write(
                format!("{}{}", msg, config::LINE_ENDING).into_bytes(),
            ),
            Box::new(move || {
                format!(
                    "Error sending error message response: respmsg={}",
                    &msg_copy
                )
            }),
        ) {
            let _ = event_sender.send(conn_std::ConnectionEvent::Closing);

            error(&target!(), &format!("{:?}", &err));
        }
    }
}

unsafe impl Send for ClientConnVisitor {}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::controller::tests::MockMsgProcessor;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::role_repo::RoleRepository;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::GatewayServiceMgr;
    use crate::testutils::MockTlsSvrConn;
    use mockall::predicate;
    use std::fmt;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use trust0_common::crypto::file::load_certificates;
    use trust0_common::model::access::{EntityType, ServiceAccess};
    use trust0_common::model::user::{Status, User};
    use trust0_common::net::tls_server::conn_std::{ConnectionEvent, ConnectionVisitor};
    use trust0_common::proxy::event::ProxyEvent;
    use trust0_common::proxy::executor::ProxyExecutorEvent;

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];
    const CERTFILE_NON_CLIENT_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "non-client.crt.pem"];

    // ClientConnVisitor tests
    // =======================

    fn create_cliconnvis(
        user_repo: Arc<Mutex<dyn UserRepository>>,
        service_repo: Arc<Mutex<dyn ServiceRepository>>,
        role_repo: Arc<Mutex<dyn RoleRepository>>,
        access_repo: Arc<Mutex<dyn AccessRepository>>,
        device_control_plane: Option<(&str, Arc<Mutex<dyn MessageProcessor>>)>,
    ) -> Result<ClientConnVisitor, AppError> {
        let app_config = Arc::new(config::tests::create_app_config_with_repos(
            config::GatewayType::Client,
            user_repo,
            service_repo,
            role_repo,
            access_repo,
        )?);
        let proxy_tasks_sender: Sender<ProxyExecutorEvent> = mpsc::channel().0;
        let proxy_events_sender: Sender<ProxyEvent> = mpsc::channel().0;
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(GatewayServiceMgr::new(
            &app_config,
            &proxy_tasks_sender,
            &proxy_events_sender,
        )));
        if device_control_plane.is_some() {
            let device_control_plane = device_control_plane.unwrap();
            service_mgr
                .lock()
                .unwrap()
                .add_control_plane(device_control_plane.0, &device_control_plane.1)?;
        }
        Ok(ClientConnVisitor::new(&app_config, &service_mgr))
    }

    fn create_msg_processor(is_authenticated: bool) -> Arc<Mutex<dyn MessageProcessor>> {
        let mut msg_processor = MockMsgProcessor::new();
        msg_processor
            .expect_is_authenticated()
            .times(1)
            .return_once(move || is_authenticated);
        Arc::new(Mutex::new(msg_processor))
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_gooduser_and_goodproto_and_1stcontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();
        let device_id = "C:03e8:100";

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let mut user_repo = MockUserRepo::new();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| {
                Ok(Some(User {
                    user_id: 100,
                    user_name: Some("user1".to_string()),
                    password: Some("pass1".to_string()),
                    name: "".to_string(),
                    status: Status::Active,
                    roles: vec![],
                }))
            });
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Ok(protocol) = &result {
            if let alpn::Protocol::ControlPlane = protocol {
                assert!(cli_conn_visitor.device.is_some());
                assert!(cli_conn_visitor.user.is_some());
                assert_eq!(
                    cli_conn_visitor.device.as_ref().unwrap().get_id().as_str(),
                    device_id
                );
                assert_eq!(cli_conn_visitor.user.as_ref().unwrap().user_id, 100);
                assert!(cli_conn_visitor.protocol.is_some());
                assert_eq!(
                    cli_conn_visitor.protocol.as_ref().unwrap(),
                    &alpn::Protocol::ControlPlane
                );
                return Ok(());
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_gooduser_and_goodproto_and_2ndcontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();
        let device_id = "C:03e8:100";

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let mut user_repo = MockUserRepo::new();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| {
                Ok(Some(User {
                    user_id: 100,
                    user_name: Some("user1".to_string()),
                    password: Some("pass1".to_string()),
                    name: "".to_string(),
                    status: Status::Active,
                    roles: vec![],
                }))
            });
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0426_CONTROL_PLANE_ALREADY_CONNECTED {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_goodsvc_and_gooduser_and_goodproto_and_hascontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::Protocol::create_service_protocol(200)
            .as_bytes()
            .to_vec();
        let device_id = "C:03e8:100";

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Active,
            roles: vec![],
        };

        let mut user_repo = MockUserRepo::new();
        let user_copy = user.clone();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(Some(user_copy)));
        let mut access_repo = MockAccessRepo::new();
        access_repo
            .expect_get_for_user()
            .with(predicate::eq(200), predicate::eq(user.clone()))
            .times(1)
            .return_once(move |_, _| {
                Ok(Some(ServiceAccess {
                    service_id: 200,
                    entity_type: EntityType::User,
                    entity_id: 100,
                }))
            });
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, create_msg_processor(true))),
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(200));
        if let Ok(protocol) = &result {
            if let alpn::Protocol::Service(service_id) = protocol {
                if *service_id == 200 {
                    assert!(cli_conn_visitor.device.is_some());
                    assert!(cli_conn_visitor.user.is_some());
                    assert_eq!(
                        cli_conn_visitor.device.as_ref().unwrap().get_id().as_str(),
                        device_id
                    );
                    assert_eq!(cli_conn_visitor.user.as_ref().unwrap().user_id, 100);
                    assert!(cli_conn_visitor.protocol.is_some());
                    assert_eq!(
                        cli_conn_visitor.protocol.as_ref().unwrap(),
                        &alpn::Protocol::Service(200)
                    );
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_goodsvc_and_gooduser_and_goodproto_and_nocontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::Protocol::create_service_protocol(200)
            .as_bytes()
            .to_vec();

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Active,
            roles: vec![],
        };

        let mut user_repo = MockUserRepo::new();
        let user_copy = user.clone();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(Some(user_copy)));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get_for_user().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(201));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0427_CONTROL_PLANE_NOT_AUTHENTICATED {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_goodsvc_and_gooduser_and_goodproto_and_nonauthed_control(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::Protocol::create_service_protocol(200)
            .as_bytes()
            .to_vec();
        let device_id = "C:03e8:100";

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Active,
            roles: vec![],
        };

        let mut user_repo = MockUserRepo::new();
        let user_copy = user.clone();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(Some(user_copy)));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get_for_user().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, create_msg_processor(false))),
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(201));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0427_CONTROL_PLANE_NOT_AUTHENTICATED {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_wrongsvc_and_gooduser_and_goodproto_and_hascontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::Protocol::create_service_protocol(200)
            .as_bytes()
            .to_vec();
        let device_id = "C:03e8:100";

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Active,
            roles: vec![],
        };

        let mut user_repo = MockUserRepo::new();
        let user_copy = user.clone();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(Some(user_copy)));
        let mut access_repo = MockAccessRepo::new();
        access_repo
            .expect_get_for_user()
            .with(predicate::eq(200), predicate::eq(user.clone()))
            .never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, create_msg_processor(true))),
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(201));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0424_INVALID_ALPN_PROTOCOL {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_goodsvc_and_gooduser_and_wrongproto_and_hascontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();
        let device_id = "C:03e8:100";

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn
            .expect_alpn_protocol()
            .times(1)
            .return_once(move || Some(alpn_proto));

        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Active,
            roles: vec![],
        };

        let mut user_repo = MockUserRepo::new();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(Some(user)));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, create_msg_processor(true))),
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(200));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0424_INVALID_ALPN_PROTOCOL {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_badcert_and_nocontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_NON_CLIENT_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().never();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().never();
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(200));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_baduid_and_nocontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().never();

        let mut user_repo = MockUserRepo::new();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(None));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0421_UNKNOWN_USER {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_inactiveuser_and_nocontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn
            .expect_peer_certificates()
            .times(1)
            .return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().never();

        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Inactive,
            roles: vec![],
        };

        let mut user_repo = MockUserRepo::new();
        user_repo
            .expect_get()
            .with(predicate::eq(100))
            .times(1)
            .return_once(move |_| Ok(Some(user)));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;

        assert!(cli_conn_visitor.device.is_none());
        assert!(cli_conn_visitor.user.is_none());
        assert!(cli_conn_visitor.protocol.is_none());

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0422_INACTIVE_USER {
                    assert!(cli_conn_visitor.device.is_none());
                    assert!(cli_conn_visitor.user.is_none());
                    assert!(cli_conn_visitor.protocol.is_none());
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    // ClientConnVisitor::parse_alpn_protocol tests

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_invalid_value() {
        assert!(
            ClientConnVisitor::parse_alpn_protocol(&Some("INVALID".as_bytes().to_vec())).is_err()
        );
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_no_value() {
        assert!(ClientConnVisitor::parse_alpn_protocol(&None).is_err());
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_control_plane() -> Result<(), AppError> {
        assert_eq!(
            ClientConnVisitor::parse_alpn_protocol(&Some(
                alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec()
            ))?,
            alpn::Protocol::ControlPlane
        );
        Ok(())
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_valid_service() -> Result<(), AppError> {
        let protocol = ClientConnVisitor::parse_alpn_protocol(&Some(
            alpn::Protocol::create_service_protocol(123)
                .as_bytes()
                .to_vec(),
        ))?;
        match protocol {
            alpn::Protocol::Service(service_id) => assert_eq!(service_id, 123),
            _ => panic!("Protocol is not Service(123)"),
        }
        Ok(())
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_invalid_service() {
        assert!(ClientConnVisitor::parse_alpn_protocol(&Some(
            format!("{}{}", alpn::PROTOCOL_SERVICE, "INVALID")
                .as_bytes()
                .to_vec()
        ))
        .is_err());
    }

    #[test]
    fn cliconnvis_on_connection_read_when_valid_data() -> Result<(), AppError> {
        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
            None,
        )?;

        let data = "data1";

        let mut request_procesor = MockMsgProcessor::new();
        request_procesor
            .expect_process_inbound_messages()
            .with(predicate::eq(data.as_bytes()))
            .return_once(|_| Ok(()));
        cli_conn_visitor.message_processor = Some(Arc::new(Mutex::new(request_procesor)));

        if let Err(err) = cli_conn_visitor.on_connection_read(data.as_bytes()) {
            panic!("Unexpected result: err={:?}", &err);
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_on_polling_cycle() -> Result<(), AppError> {
        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
            None,
        )?;

        let mut request_procesor = MockMsgProcessor::new();
        request_procesor
            .expect_process_outbound_messages()
            .return_once(|| Ok(()));
        cli_conn_visitor.message_processor = Some(Arc::new(Mutex::new(request_procesor)));

        if let Err(err) = cli_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_on_shutdown() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;
        cli_conn_visitor.user = Some(User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Inactive,
            roles: vec![],
        });
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().as_ref().unwrap())?;
        cli_conn_visitor.device = Some(Device::new(peer_certs)?);

        assert!(cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_device(device_id, false));

        if let Err(err) = cli_conn_visitor.on_shutdown() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(!cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_device(device_id, false));

        Ok(())
    }

    #[test]
    fn cliconnvis_send_error_response_when_genwithcode_error() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;
        let event_channel = mpsc::channel();
        cli_conn_visitor.event_channel_sender = Some(event_channel.0);

        cli_conn_visitor.send_error_response(&AppError::GenWithCode(
            config::RESPCODE_0423_INVALID_REQUEST,
        ));

        let msg_event = event_channel.1.try_recv();
        if let Err(err) = &msg_event {
            panic!("Unexpected channel recv result: err={:?}", err);
        }
        match msg_event.as_ref().unwrap() {
            ConnectionEvent::Write(data) => assert_eq!(
                String::from_utf8(data.clone()).unwrap(),
                format!("[E0423] Invalid request{}", config::LINE_ENDING)
            ),
            _ => panic!("Unexpected connection event: event={:?}", &msg_event),
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_send_error_response_when_genwithcodeandmsganderr_error() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;
        let event_channel = mpsc::channel();
        cli_conn_visitor.event_channel_sender = Some(event_channel.0);

        cli_conn_visitor.send_error_response(&AppError::GenWithCodeAndMsgAndErr(
            config::RESPCODE_0423_INVALID_REQUEST,
            "msg1".to_string(),
            Box::new(fmt::Error::default()),
        ));

        let msg_event = event_channel.1.try_recv();
        if let Err(err) = &msg_event {
            panic!("Unexpected channel recv result: err={:?}", err);
        }
        match msg_event.as_ref().unwrap() {
            ConnectionEvent::Write(data) => assert_eq!(
                String::from_utf8(data.clone()).unwrap(),
                format!("[E0423] Invalid request{}", config::LINE_ENDING)
            ),
            _ => panic!("Unexpected connection event: event={:?}", &msg_event),
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_send_error_response_when_genwithcodeanderr_error() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;
        let event_channel = mpsc::channel();
        cli_conn_visitor.event_channel_sender = Some(event_channel.0);

        cli_conn_visitor.send_error_response(&AppError::GenWithCodeAndErr(
            config::RESPCODE_0423_INVALID_REQUEST,
            Box::new(fmt::Error::default()),
        ));

        let msg_event = event_channel.1.try_recv();
        if let Err(err) = &msg_event {
            panic!("Unexpected channel recv result: err={:?}", err);
        }
        match msg_event.as_ref().unwrap() {
            ConnectionEvent::Write(data) => assert_eq!(
                String::from_utf8(data.clone()).unwrap(),
                format!("[E0423] Invalid request{}", config::LINE_ENDING)
            ),
            _ => panic!("Unexpected connection event: event={:?}", &msg_event),
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_send_error_response_when_genwithcodeandmsg_error() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;
        let event_channel = mpsc::channel();
        cli_conn_visitor.event_channel_sender = Some(event_channel.0);

        cli_conn_visitor.send_error_response(&AppError::GenWithCodeAndMsg(
            config::RESPCODE_0423_INVALID_REQUEST,
            "msg1".to_string(),
        ));

        let msg_event = event_channel.1.try_recv();
        if let Err(err) = &msg_event {
            panic!("Unexpected channel recv result: err={:?}", err);
        }
        match msg_event.as_ref().unwrap() {
            ConnectionEvent::Write(data) => assert_eq!(
                String::from_utf8(data.clone()).unwrap(),
                format!("[E0423] Invalid request{}", config::LINE_ENDING)
            ),
            _ => panic!("Unexpected connection event: event={:?}", &msg_event),
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_send_error_response_when_other_error() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;
        let event_channel = mpsc::channel();
        cli_conn_visitor.event_channel_sender = Some(event_channel.0);

        cli_conn_visitor.send_error_response(&AppError::General("msg1".to_string()));

        let msg_event = event_channel.1.try_recv();
        if let Err(err) = &msg_event {
            panic!("Unexpected channel recv result: err={:?}", err);
        }
        match msg_event.as_ref().unwrap() {
            ConnectionEvent::Write(data) => assert_eq!(
                String::from_utf8(data.clone()).unwrap(),
                format!("[E0500] System error occurred{}", config::LINE_ENDING)
            ),
            _ => panic!("Unexpected connection event: event={:?}", &msg_event),
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_accessors() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let device_id = "C:03e8:100";

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((device_id, Arc::new(Mutex::new(MockMsgProcessor::new())))),
        )?;

        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap())?;

        let expected_device = Device::new(certs)?;
        let expected_user = User::new(100, None, None, "name100", &Status::Active, &[]);

        cli_conn_visitor.device = Some(expected_device.clone());
        cli_conn_visitor.user = Some(expected_user.clone());

        let device = cli_conn_visitor.get_device();
        let user = cli_conn_visitor.get_user();

        assert!(device.is_some());
        assert!(user.is_some());

        assert_eq!(device.as_ref().unwrap().get_id(), expected_device.get_id());
        assert_eq!(user.as_ref().unwrap(), &expected_user);

        Ok(())
    }
}
