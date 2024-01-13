use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use pki_types::CertificateDer;

use crate::client::controller::{ControlPlane, RequestProcessor};
use crate::client::device::Device;
use crate::config::{self, AppConfig};
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::model::user::{Status, User};
use trust0_common::net::tls_server::conn_std::{self, TlsConnection};
use trust0_common::{crypto, target};

/// tls_server::std_conn::Connection strategy visitor pattern implementation
pub struct ClientConnVisitor {
    app_config: Arc<AppConfig>,
    access_repo: Arc<Mutex<dyn AccessRepository>>,
    service_repo: Arc<Mutex<dyn ServiceRepository>>,
    user_repo: Arc<Mutex<dyn UserRepository>>,
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    request_processor: Option<Arc<Mutex<dyn RequestProcessor>>>,
    device: Option<Device>,
    user: Option<User>,
    protocol: Option<alpn::Protocol>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
}

impl ClientConnVisitor {
    /// ClientConnVisitor constructor
    pub fn new(app_config: Arc<AppConfig>, service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {
        let access_repo = Arc::clone(&app_config.access_repo);
        let service_repo = Arc::clone(&app_config.service_repo);
        let user_repo = Arc::clone(&app_config.user_repo);

        Self {
            app_config: app_config.clone(),
            access_repo,
            service_repo,
            user_repo,
            event_channel_sender: None,
            request_processor: None,
            device: None,
            user: None,
            protocol: None,
            service_mgr,
        }
    }

    /// Create device and user from peer certificate
    pub fn process_authorization(
        &mut self,
        tls_conn: &dyn TlsConnection,
        service_id: Option<u64>,
    ) -> Result<alpn::Protocol, AppError> {
        // Parse certificate context details
        let peer_certificates: Vec<CertificateDer<'static>> = tls_conn
            .peer_certificates()
            .ok_or(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                "Empty client certificate chain".to_string(),
            ))?
            .iter()
            .map(|c| crypto::x509::create_der_certificate(c.to_vec()))
            .collect();

        let device = Device::new(peer_certificates)?;

        // Validate user
        let user_id = device.get_cert_access_context().user_id;

        if user_id == 0 {
            return Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                "Invalid certificate user identity".to_string(),
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
                        "Error retrieving user from user repo: uid={}, err={:?}",
                        user_id, err
                    ),
                )
            })?
            .ok_or(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0421_UNKNOWN_USER,
                format!("User is not found in user repo: uid={}", user_id),
            ))?;

        if user.status != Status::Active {
            return Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0422_INACTIVE_USER,
                format!(
                    "User is not active: uid={}, status={:?}",
                    user_id, user.status
                ),
            ));
        }

        // Determine (ALPN) connection protocol
        let alpn_protocol = Self::parse_alpn_protocol(&tls_conn.alpn_protocol())?;

        // Validate control plane connection
        if service_id.is_none() {
            // Ensure no active control plane for user
            if self
                .service_mgr
                .lock()
                .unwrap()
                .has_control_plane_for_user(user_id, false)
            {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0426_CONTROL_PLANE_ALREADY_CONNECTED,
                    format!(
                        "Not allowed to have multiple control planes: uid={}",
                        &user_id
                    ),
                ));
            }
        }
        // Validate service connection
        else {
            // Ensure active control plane for user
            if !self
                .service_mgr
                .lock()
                .unwrap()
                .has_control_plane_for_user(user_id, true)
            {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0427_CONTROL_PLANE_NOT_AUTHENTICATED,
                    format!(
                        "Service proxy connections require an authenticated control plane: uid={}",
                        &user_id
                    ),
                ));
            }

            // Validate requested service
            let service_id = service_id.unwrap();

            let invalid_service = match alpn_protocol {
                alpn::Protocol::ControlPlane => true,
                alpn::Protocol::Service(alpn_svc_id) => service_id != alpn_svc_id,
            };

            if invalid_service {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                    format!(
                        "ALPN has wrong service ID: alpn={:?}, svc_id={}",
                        alpn_protocol, service_id
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
                        "User is not authorized for service: uid={}, svc_id={}",
                        user_id, service_id
                    ),
                ));
            }
        }

        self.device = Some(device);
        self.user = Some(user);
        self.protocol = Some(alpn_protocol.clone());

        Ok(alpn_protocol)
    }

    /// User accessor
    pub fn get_user(&self) -> &Option<User> {
        &self.user
    }

    /// Parse TLS ALPN protocol
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
    fn set_event_channel_sender(
        &mut self,
        event_channel_sender: Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError> {
        let user = self.user.as_ref().unwrap();
        if self
            .protocol
            .as_ref()
            .unwrap()
            .eq(&alpn::Protocol::ControlPlane)
        {
            let request_processor: Arc<Mutex<dyn RequestProcessor>> =
                Arc::new(Mutex::new(ControlPlane::new(
                    self.app_config.clone(),
                    self.access_repo.clone(),
                    self.service_repo.clone(),
                    self.user_repo.clone(),
                    event_channel_sender.clone(),
                    self.device.as_ref().unwrap().clone(),
                    user.clone(),
                )?));
            self.service_mgr
                .lock()
                .unwrap()
                .add_control_plane(user.user_id, request_processor.clone())?;
            self.request_processor = Some(request_processor);
        }
        self.event_channel_sender = Some(event_channel_sender);

        Ok(())
    }

    fn on_connection_read(&mut self, data: &[u8]) -> Result<(), AppError> {
        let data_text = String::from_utf8(data.to_vec()).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting client input as UTF8".to_string(),
                Box::new(err),
            )
        })?;

        let _ = self
            .request_processor
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .process_request(&self.service_mgr, &data_text)?;

        Ok(())
    }

    fn on_shutdown(&mut self) -> Result<(), AppError> {
        self.service_mgr
            .lock()
            .unwrap()
            .shutdown_connections(Some(self.user.as_ref().unwrap().user_id), None)
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

        if let Err(err) = event_sender.send(conn_std::ConnectionEvent::Write(
            format!("{}{}", msg, config::LINE_ENDING).into_bytes(),
        )) {
            let _ = event_sender.send(conn_std::ConnectionEvent::Closing);

            error(
                &target!(),
                &format!(
                    "Error sending error message response: err={:?}, respmsg={}",
                    err, msg
                ),
            );
        }
    }
}

unsafe impl Send for ClientConnVisitor {}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::controller::tests::MockReqProcessor;
    use crate::client::device::CertAccessContext;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::role_repo::RoleRepository;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::GatewayServiceMgr;
    use crate::testutils::MockTlsSvrConn;
    use mockall::predicate;
    use std::collections::HashMap;
    use std::fmt;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use trust0_common::control::request;
    use trust0_common::crypto::file::load_certificates;
    use trust0_common::model::access::{EntityType, ServiceAccess};
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
        user_control_plane: Option<(u64, Arc<Mutex<dyn RequestProcessor>>)>,
    ) -> Result<ClientConnVisitor, AppError> {
        let app_config = Arc::new(config::tests::create_app_config_with_repos(
            user_repo,
            service_repo,
            role_repo,
            access_repo,
        )?);
        let proxy_tasks_sender: Sender<ProxyExecutorEvent> = mpsc::channel().0;
        let proxy_events_sender: Sender<ProxyEvent> = mpsc::channel().0;
        let service_mgr = Arc::new(Mutex::new(GatewayServiceMgr::new(
            app_config.clone(),
            proxy_tasks_sender,
            proxy_events_sender,
        )));
        if user_control_plane.is_some() {
            let user_control_plane = user_control_plane.unwrap();
            service_mgr
                .lock()
                .unwrap()
                .add_control_plane(user_control_plane.0, user_control_plane.1.clone())?;
        }
        Ok(ClientConnVisitor::new(app_config, service_mgr))
    }

    fn create_req_processor(is_authenticated: bool) -> Arc<Mutex<dyn RequestProcessor>> {
        let mut req_processor = MockReqProcessor::new();
        req_processor
            .expect_is_authenticated()
            .times(1)
            .return_once(move || is_authenticated);
        Arc::new(Mutex::new(req_processor))
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_gooduser_and_goodproto_and_1stcontrol(
    ) -> Result<(), AppError> {
        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();

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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();

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
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
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
            Some((100, create_req_processor(true))),
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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
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
            Some((100, create_req_processor(false))),
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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
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
            Some((100, create_req_processor(true))),
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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();

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
            Some((100, create_req_processor(true))),
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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;

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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;

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
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;

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
    fn cliconnvis_set_event_channel_sender_when_control_plane() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let mut service_repo = MockServiceRepo::new();
        service_repo
            .expect_get_all()
            .times(1)
            .return_once(|| Ok(vec![]));
        let role_repo = MockRoleRepo::new();
        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Inactive,
            roles: vec![],
        };
        let device = Device {
            cert_access_context: CertAccessContext {
                user_id: 100,
                platform: "Linux".to_string(),
            },
            cert_alt_subj: HashMap::new(),
            cert_subj: HashMap::new(),
        };

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;
        cli_conn_visitor.user = Some(user.clone());
        cli_conn_visitor.device = Some(device);
        cli_conn_visitor.protocol = Some(alpn::Protocol::ControlPlane);

        assert!(cli_conn_visitor.event_channel_sender.is_none());
        assert!(cli_conn_visitor.request_processor.is_none());
        assert!(!cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_user(100, false));

        if let Err(err) = cli_conn_visitor.set_event_channel_sender(mpsc::channel().0) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(cli_conn_visitor.event_channel_sender.is_some());
        assert!(cli_conn_visitor.request_processor.is_some());
        assert!(cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_user(100, false));

        Ok(())
    }

    #[test]
    fn cliconnvis_set_event_channel_sender_when_service() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get_all().never();
        let role_repo = MockRoleRepo::new();
        let user = User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Inactive,
            roles: vec![],
        };
        let device = Device {
            cert_access_context: CertAccessContext {
                user_id: 100,
                platform: "Linux".to_string(),
            },
            cert_alt_subj: HashMap::new(),
            cert_subj: HashMap::new(),
        };

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;
        cli_conn_visitor.user = Some(user.clone());
        cli_conn_visitor.device = Some(device);
        cli_conn_visitor.protocol = Some(alpn::Protocol::Service(200));

        assert!(cli_conn_visitor.event_channel_sender.is_none());
        assert!(cli_conn_visitor.request_processor.is_none());
        assert!(!cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_user(100, false));

        if let Err(err) = cli_conn_visitor.set_event_channel_sender(mpsc::channel().0) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(cli_conn_visitor.event_channel_sender.is_some());
        assert!(cli_conn_visitor.request_processor.is_none());
        assert!(!cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_user(100, false));

        Ok(())
    }

    #[test]
    fn cliconnvis_on_connection_read_when_valid_data() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;
        let data = "data1";
        let mut request_procesor = MockReqProcessor::new();
        request_procesor
            .expect_process_request()
            .with(predicate::always(), predicate::eq(data.to_string()))
            .return_once(|_, _| Ok(request::Request::Ignore));
        cli_conn_visitor.request_processor = Some(Arc::new(Mutex::new(request_procesor)));

        if let Err(err) = cli_conn_visitor.on_connection_read(data.as_bytes()) {
            panic!("Unexpected result: err={:?}", &err);
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_on_connection_read_when_invalid_data() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            None,
        )?;
        let data = [0xff];
        let mut request_procesor = MockReqProcessor::new();
        request_procesor.expect_process_request().never();

        if let Ok(()) = cli_conn_visitor.on_connection_read(&data) {
            panic!("Unexpected successful result");
        }

        Ok(())
    }

    #[test]
    fn cliconnvis_on_shutdown() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
        )?;
        cli_conn_visitor.user = Some(User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            name: "".to_string(),
            status: Status::Inactive,
            roles: vec![],
        });

        assert!(cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_user(100, false));

        if let Err(err) = cli_conn_visitor.on_shutdown() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(!cli_conn_visitor
            .service_mgr
            .lock()
            .unwrap()
            .has_control_plane_for_user(100, false));

        Ok(())
    }

    #[test]
    fn cliconnvis_send_error_response_when_genwithcode_error() -> Result<(), AppError> {
        let user_repo = MockUserRepo::new();
        let access_repo = MockAccessRepo::new();
        let service_repo = MockServiceRepo::new();
        let role_repo = MockRoleRepo::new();

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
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

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
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

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
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

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
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

        let mut cli_conn_visitor = create_cliconnvis(
            Arc::new(Mutex::new(user_repo)),
            Arc::new(Mutex::new(service_repo)),
            Arc::new(Mutex::new(role_repo)),
            Arc::new(Mutex::new(access_repo)),
            Some((100, Arc::new(Mutex::new(MockReqProcessor::new())))),
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
}
