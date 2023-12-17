use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;

use anyhow::Result;
use pki_types::CertificateDer;

use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::model::user::{Status, User};
use trust0_common::net::tls_server::conn_std::{self, TlsConnection};
use trust0_common::{crypto, target};
use crate::client::controller::{ControlPlane, RequestProcessor};
use crate::client::device::Device;
use crate::config::{self, AppConfig};
use crate::repository::access_repo::AccessRepository;
use crate::repository::service_repo::ServiceRepository;
use crate::repository::user_repo::UserRepository;
use crate::service::manager::ServiceMgr;

/// tls_server::std_conn::Connection strategy visitor pattern implementation
pub struct ClientConnVisitor {
    app_config: Arc<AppConfig>,
    server_mode: config::ServerMode,
    access_repo: Arc<Mutex<dyn AccessRepository>>,
    service_repo: Arc<Mutex<dyn ServiceRepository>>,
    user_repo: Arc<Mutex<dyn UserRepository>>,
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    request_processor: Option<Box<dyn RequestProcessor>>,
    device: Option<Device>,
    user: Option<User>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>
}

impl ClientConnVisitor {

    /// ClientConnVisitor constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>) -> Self {

        let server_mode = app_config.server_mode.clone();
        let access_repo = Arc::clone(&app_config.access_repo);
        let service_repo = Arc::clone(&app_config.service_repo);
        let user_repo = Arc::clone(&app_config.user_repo);

        Self {
            app_config: app_config.clone(),
            server_mode,
            access_repo,
            service_repo,
            user_repo,
            event_channel_sender: None,
            request_processor: None,
            device: None,
            user: None,
            service_mgr
        }
    }

    /// Create device and user from peer certificate
    pub fn process_authorization(&mut self, tls_conn: &dyn TlsConnection, service_id: Option<u64>)
                                 -> Result<alpn::Protocol, AppError> {

        // parse certificate context details
        let peer_certificates: Vec<CertificateDer<'static>> = tls_conn.peer_certificates()
            .ok_or(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                "Empty client certificate chain".to_string()))?
            .iter()
            .map(|c| crypto::x509::create_der_certificate(c.to_vec()))
            .collect();

        let device = Device::new(peer_certificates)?;

        // validate user
        let user_id = device.get_cert_access_context().user_id;

        if user_id == 0 {
            return Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE,
                "Invalid certificate user identity".to_string()));
        }

        let user = self.user_repo.lock().unwrap().get(user_id)
            .map_err(|err| AppError::GenWithCodeAndMsg(
                config::RESPCODE_0500_SYSTEM_ERROR,
                format!("Error retrieving user from user repo: uid={}, err={:?}", user_id, err)))?
            .ok_or(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0421_UNKNOWN_USER,
                format!("User is not found in user repo: uid={}", user_id)))?;

        if user.status != Status::Active {
            return Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0422_INACTIVE_USER,
                format!("User is not active: uid={}, status={:?}", user_id, user.status)));
        }

        // determine (ALPN) connection protocol
        let alpn_protocol = Self::parse_alpn_protocol(&tls_conn.alpn_protocol())?;

        // validate service (if necessary)
        if service_id.is_some() {
            let service_id = service_id.unwrap();

            let invalid_service = match alpn_protocol {
                alpn::Protocol::ControlPlane => true,
                alpn::Protocol::Service(alpn_svc_id) => service_id != alpn_svc_id
            };

            if invalid_service {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                    format!("ALPN has wrong service ID: alpn={:?}, svc_id={}", alpn_protocol, service_id)));
            }

            if self.access_repo.lock().unwrap().get(user_id, service_id)?.is_none() {
                return Err(AppError::GenWithCodeAndMsg(
                    config::RESPCODE_0403_FORBIDDEN,
                    format!("User is not authorized for service: uid={}, svc_id={}", user_id, service_id)));
            }
        }

        self.device = Some(device);
        self.user = Some(user);

        Ok(alpn_protocol)
    }

    /// User accessor
    pub fn get_user(&self) -> &Option<User> {
        &self.user
    }

    /// Parse TLS ALPN protocol
    pub fn parse_alpn_protocol(protocol_name: &Option<Vec<u8>>) -> Result<alpn::Protocol, AppError> {

        match protocol_name {

            None => Err(AppError::GenWithCodeAndMsg(
                config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                "Missing ALPN protocol".to_string())),

            Some(protocol_name_bytes) => {
                let protocol_name = String::from_utf8_lossy(protocol_name_bytes);
                match alpn::Protocol::parse(protocol_name.as_ref()) {
                    None => return Err(AppError::GenWithCodeAndMsg(
                        config::RESPCODE_0424_INVALID_ALPN_PROTOCOL,
                        format!("Invalid ALPN protocol: proto={}", protocol_name.as_ref()))),
                    Some(alpn_protocol) => Ok(alpn_protocol)
                }
            }
        }
    }
}

impl conn_std::ConnectionVisitor for ClientConnVisitor {

    fn set_event_channel_sender(&mut self, event_channel_sender: Sender<conn_std::ConnectionEvent>)
        -> Result<(), AppError> {

        self.request_processor = Some(Box::new(ControlPlane::new(
            self.app_config.clone(),
            self.access_repo.clone(),
            self.service_repo.clone(),
            self.user_repo.clone(),
            event_channel_sender.clone(),
            self.device.as_ref().unwrap_or(&Device::default()).clone(),
            self.user.as_ref().unwrap_or(&User::default()).clone())?));

        self.event_channel_sender = Some(event_channel_sender);

        Ok(())
    }

    fn on_connection_read(&mut self, data: &[u8]) -> Result<(), AppError> {

        match self.server_mode {

            config::ServerMode::ControlPlane => {

                let data_text = String::from_utf8(data.to_vec()).map_err(|err|
                    AppError::GenWithMsgAndErr("Error converting client input as UTF8".to_string(), Box::new(err)))?;

                let _ = self.request_processor.as_mut().unwrap().process_request(&self.service_mgr, &data_text)?;
            }

            config::ServerMode::Proxy => {}
        }

        Ok(())
    }

    fn on_shutdown(&mut self) -> Result<(), AppError> {

        self.service_mgr.lock().unwrap().shutdown_connections(Some(self.user.as_ref().unwrap().user_id), None)
    }

    fn send_error_response(&mut self, err: &AppError) {

        let resp_msgs = &config::RESPONSE_MSGS;

        let unknown_msg = move |code|
            format!("{}: ref={}", resp_msgs.get(&config::RESPCODE_0520_UNKNOWN_CODE).unwrap(), code);

        let msg = match err {
            AppError::GenWithCode(code) => resp_msgs.get(code).map_or(unknown_msg(code), |m| m.to_string()),
            AppError::GenWithCodeAndMsgAndErr(code, _, _) => resp_msgs.get(code).map_or(unknown_msg(code), |m| m.to_string()),
            AppError::GenWithCodeAndErr(code, _) => resp_msgs.get(code).map_or(unknown_msg(code), |m| m.to_string()),
            AppError::GenWithCodeAndMsg(code, _) => resp_msgs.get(code).map_or(unknown_msg(code), |m| m.to_string()),
            _ => resp_msgs.get(&config::RESPCODE_0500_SYSTEM_ERROR).unwrap().to_string()
        };

        let event_sender = self.event_channel_sender.as_ref().unwrap();

        if let Err(err) = event_sender.send(conn_std::ConnectionEvent::Write(format!("{}\n", msg).into_bytes())) {

            let _ = event_sender.send(conn_std::ConnectionEvent::Closing);

            error(&target!(), &format!("Error sending error message response: err={:?}, respmsg={}", err, msg));
        }
    }
}

unsafe impl Send for ClientConnVisitor {}

/// Unit tests
#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;
    use mockall::predicate;
    use trust0_common::crypto::file::load_certificates;
    use trust0_common::model::access::ServiceAccess;
    use trust0_common::proxy::event::ProxyEvent;
    use trust0_common::proxy::executor::ProxyExecutorEvent;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::GatewayServiceMgr;
    use crate::testutils::MockTlsSvrConn;
    use super::*;

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "client-uid100.crt.pem"];
    const CERTFILE_NON_CLIENT_PATHPARTS: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "non-client.crt.pem"];

    // ClientConnVisitor tests
    // =======================

    fn create_cliconnvis(user_repo: Arc<Mutex<dyn UserRepository>>,
                         service_repo: Arc<Mutex<dyn ServiceRepository>>,
                         access_repo: Arc<Mutex<dyn AccessRepository>>)
        -> Result<ClientConnVisitor, AppError> {

        let app_config = Arc::new(config::tests::create_app_config_with_repos(user_repo, service_repo, access_repo)?);
        let proxy_tasks_sender: Sender<ProxyExecutorEvent> = mpsc::channel().0;
        let proxy_events_sender: Sender<ProxyEvent> = mpsc::channel().0;
        let service_mgr = Arc::new(Mutex::new(GatewayServiceMgr::new(app_config.clone(), proxy_tasks_sender, proxy_events_sender)));
        Ok(ClientConnVisitor::new(app_config, service_mgr))
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_gooduser_and_goodproto() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().times(1).return_once(move || Some(alpn_proto));

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().with(predicate::eq(100)).times(1)
            .return_once(move |_| Ok(Some(User {user_id: 100, name: "".to_string(), status: Status::Active})));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Ok(protocol) = &result {
            if let alpn::Protocol::ControlPlane = protocol {
                return Ok(());
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_goodsvc_and_gooduser_and_goodproto() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::Protocol::create_service_protocol(200).as_bytes().to_vec();

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().times(1).return_once(move || Some(alpn_proto));

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().with(predicate::eq(100)).times(1)
            .return_once(move |_| Ok(Some(User {user_id: 100, name: "".to_string(), status: Status::Active})));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().with(predicate::eq(100), predicate::eq(200)).times(1)
            .return_once(move |_, _| Ok(Some(ServiceAccess {user_id: 100, service_id: 200})));
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(200));
        if let Ok(protocol) = &result {
            if let alpn::Protocol::Service(service_id) = protocol {
                if *service_id == 200 {
                    return Ok(());
                }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_wrongsvc_and_gooduser_and_goodproto() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::Protocol::create_service_protocol(200).as_bytes().to_vec();

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().times(1).return_once(move || Some(alpn_proto));

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().with(predicate::eq(100)).times(1)
            .return_once(move |_| Ok(Some(User {user_id: 100, name: "".to_string(), status: Status::Active})));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().with(predicate::eq(100), predicate::eq(200)).never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(201));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0424_INVALID_ALPN_PROTOCOL { return Ok(()); }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_goodsvc_and_gooduser_and_wrongproto() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;
        let alpn_proto = alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec();

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().times(1).return_once(move || Some(alpn_proto));

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().with(predicate::eq(100)).times(1)
            .return_once(move |_| Ok(Some(User {user_id: 100, name: "".to_string(), status: Status::Active})));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(200));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0424_INVALID_ALPN_PROTOCOL { return Ok(()); }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_badcert() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_NON_CLIENT_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().never();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().never();
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, Some(200));
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0420_INVALID_CLIENT_CERTIFICATE { return Ok(()); }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_baduid() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().never();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().with(predicate::eq(100)).times(1).return_once(move |_| Ok(None));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0421_UNKNOWN_USER { return Ok(()); }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    #[test]
    fn cliconnvis_process_authorization_fn_when_nosvc_and_inactiveuser() -> Result<(), AppError> {

        let peer_certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let peer_certs = load_certificates(peer_certs_file.to_str().unwrap().to_string())?;

        let mut tls_conn = MockTlsSvrConn::new();
        tls_conn.expect_peer_certificates().times(1).return_once(move || Some(peer_certs));
        tls_conn.expect_alpn_protocol().never();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_get().with(predicate::eq(100)).times(1)
            .return_once(move |_| Ok(Some(User {user_id: 100, name: "".to_string(), status: Status::Inactive})));
        let mut access_repo = MockAccessRepo::new();
        access_repo.expect_get().never();
        let mut service_repo = MockServiceRepo::new();
        service_repo.expect_get().never();

        let mut cli_conn_visitor = create_cliconnvis(Arc::new(Mutex::new(user_repo)), Arc::new(Mutex::new(service_repo)), Arc::new(Mutex::new(access_repo)))?;

        let result = cli_conn_visitor.process_authorization(&tls_conn, None);
        if let Err(err) = &result {
            if let AppError::GenWithCodeAndMsg(code, _) = err {
                if *code == config::RESPCODE_0422_INACTIVE_USER { return Ok(()); }
            }
        }

        panic!("Unexpected result: val={:?}", &result);
    }

    // ClientConnVisitor::parse_alpn_protocol tests

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_invalid_value() {
        assert!(ClientConnVisitor::parse_alpn_protocol(&Some("INVALID".as_bytes().to_vec())).is_err());
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_no_value() {
        assert!(ClientConnVisitor::parse_alpn_protocol(&None).is_err());
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_control_plane() -> Result<(), AppError> {
        assert_eq!(ClientConnVisitor::parse_alpn_protocol(
            &Some(alpn::PROTOCOL_CONTROL_PLANE.as_bytes().to_vec()))?,
            alpn::Protocol::ControlPlane);
        Ok(())
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_valid_service() -> Result<(), AppError> {
        let protocol = ClientConnVisitor::parse_alpn_protocol(&Some(alpn::Protocol::create_service_protocol(123).as_bytes().to_vec()))?;
        match protocol {
            alpn::Protocol::Service(service_id) => assert_eq!(service_id, 123),
            _ => panic!("Protocol is not Service(123)")
        }
        Ok(())
    }

    #[test]
    fn cliconnvis_parse_alpn_protocol_fn_when_invalid_service() {
        assert!(ClientConnVisitor::parse_alpn_protocol(&Some(format!("{}{}", alpn::PROTOCOL_SERVICE, "INVALID").as_bytes().to_vec())).is_err());
    }
}