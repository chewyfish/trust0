use anyhow::Result;
use std::borrow::Borrow;
use std::io::Write;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::Duration;
use trust0_common::authn::authenticator::{AuthenticatorClient, AuthnMessage, AuthnType};
use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorClient;

use crate::config::AppConfig;
use crate::console;
use crate::console::ShellOutputWriter;
use crate::service::manager::{self, ServiceMgr};
use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use trust0_common::net::tls_client::conn_std;

const AUTHN_LABEL_USERNAME: &str = "Username: ";
const AUTHN_LABEL_PASSWORD: &str = "Password: ";

const AUTHN_RESPONSE_AUTHENTICATED: &str = "Authenticated";
const AUTHN_RESPONSE_UNAUTHENTICATED: &str = "Unauthenticated";
const AUTHN_RESPONSE_ERROR: &str = "Error";

/// (MFA) Authentication context
struct AuthnContext {
    authenticator: Option<Box<dyn AuthenticatorClient>>,
    authn_type: AuthnType,
    username: Option<String>,
}

/// Process control plane commands (validate requests, parse gateway control plane responses).
pub struct ControlPlane {
    processor: request::RequestProcessor,
    event_channel_sender: Option<mpsc::Sender<conn_std::ConnectionEvent>>,
    console_shell_output: Arc<Mutex<ShellOutputWriter>>,
    tty_echo_disabler: Arc<Mutex<bool>>,
    authn_context: Rc<Mutex<Option<AuthnContext>>>,
    authenticated: Rc<Mutex<bool>>,
}

impl ControlPlane {
    /// ControlPlane constructor
    pub fn new(app_config: Arc<AppConfig>, tty_echo_disabler: Arc<Mutex<bool>>) -> Self {
        Self {
            processor: request::RequestProcessor::new(),
            event_channel_sender: None,
            console_shell_output: app_config.console_shell_output.clone(),
            tty_echo_disabler,
            authn_context: Rc::new(Mutex::new(None)),
            authenticated: Rc::new(Mutex::new(false)),
        }
    }

    /// Send control plane connection event message
    fn send_connection_event_message(
        &self,
        message: conn_std::ConnectionEvent,
    ) -> Result<(), AppError> {
        let event_sender = self.event_channel_sender.as_ref().unwrap();

        if let Err(err) = event_sender.send(message).map_err(|err| {
            AppError::GenWithMsgAndErr("Error sending connection event".to_string(), Box::new(err))
        }) {
            let _ = event_sender.send(conn_std::ConnectionEvent::Closing);

            return Err(err);
        }

        Ok(())
    }

    /// Process authentication message
    fn process_authn_message(&self, authn_msg: Option<AuthnMessage>) -> Result<(), AppError> {
        // Process authentication message
        let mut authn_context = self.authn_context.lock().unwrap();
        let authn_type = authn_context.as_ref().unwrap().authn_type.clone();

        let (console_output_text, response_authn_msg, authn_complete) = match authn_type {
            AuthnType::ScramSha256 => {
                self.process_authn_message_for_scramsha256(&mut authn_context, authn_msg)?
            }
            AuthnType::Insecure => {
                self.process_authn_message_for_insecure(&mut authn_context, authn_msg)?
            }
        };

        // Send gateway authentication message
        if response_authn_msg.is_some() {
            self.send_connection_event_message(conn_std::ConnectionEvent::Write(
                format!(
                    r#"{} --{} "{}""#,
                    request::PROTOCOL_REQUEST_LOGIN_DATA,
                    request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
                    response_authn_msg
                        .unwrap()
                        .to_json_str()?
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                )
                .into_bytes(),
            ))?;
        }

        // Display text (if required)
        if !console_output_text.is_empty() {
            self.console_shell_output
                .lock()
                .unwrap()
                .write_all(console_output_text.as_bytes())
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error writing login label to STDOUT".to_string(),
                        Box::new(err),
                    )
                })?;
            self.console_shell_output
                .lock()
                .unwrap()
                .flush()
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error flushing login label to STDOUT".to_string(),
                        Box::new(err),
                    )
                })?;
        }

        if authn_complete {
            self.console_shell_output
                .lock()
                .unwrap()
                .write_shell_prompt(false)?;
            *authn_context = None;
        }

        Ok(())
    }

    /// Process authentication message (SCRAM SHA256)
    fn process_authn_message_for_scramsha256(
        &self,
        authn_context: &mut MutexGuard<Option<AuthnContext>>,
        authn_msg: Option<AuthnMessage>,
    ) -> Result<(String, Option<AuthnMessage>, bool), AppError> {
        let mut console_output_text = String::new();
        let mut response_authn_msg = None;
        let mut authn_complete = false;

        // Step 1: Prepare to receive username. Disable TTY echo for password input
        if authn_msg.is_none() {
            console_output_text = AUTHN_LABEL_USERNAME.to_string();
            *self.tty_echo_disabler.lock().unwrap() = true;
        }
        // Step 2: Save username. Prepare to receive password
        else if authn_context.as_ref().unwrap().username.is_none() {
            console_output_text = AUTHN_LABEL_PASSWORD.to_string();
            if let Some(AuthnMessage::Payload(username)) = authn_msg {
                authn_context
                    .as_mut()
                    .unwrap()
                    .username
                    .replace(username.trim_end().to_string());
            }
        }
        // Step 3: Start up authenticator with given username, password
        else if authn_context.as_ref().unwrap().authenticator.is_none() {
            if let Some(AuthnMessage::Payload(password)) = authn_msg {
                let username = authn_context.as_ref().unwrap().username.as_ref().unwrap();
                let mut authenticator = ScramSha256AuthenticatorClient::new(
                    username,
                    password.trim_end(),
                    Duration::from_millis(10_000),
                );
                let _ = authenticator.spawn_authentication();
                response_authn_msg = authenticator.exchange_messages(None)?;
                authn_context
                    .as_mut()
                    .unwrap()
                    .authenticator
                    .replace(Box::new(authenticator));
            }
        }
        // Steps 4,...: Exchange authentication flow messages
        else {
            match &authn_msg {
                Some(AuthnMessage::Payload(_)) => {}
                Some(AuthnMessage::Error(msg)) => {
                    console_output_text = format!(
                        "{}: msg={:?}{}",
                        AUTHN_RESPONSE_ERROR,
                        msg,
                        console::LINE_ENDING
                    )
                }
                Some(_) => {}
                None => {}
            }
            response_authn_msg = authn_context
                .as_mut()
                .unwrap()
                .authenticator
                .as_mut()
                .unwrap()
                .exchange_messages(authn_msg)?;
            if response_authn_msg.is_none() {
                if authn_context
                    .as_ref()
                    .unwrap()
                    .authenticator
                    .as_ref()
                    .unwrap()
                    .is_authenticated()
                {
                    *self.authenticated.lock().unwrap() = true;
                    console_output_text =
                        format!("{}{}", AUTHN_RESPONSE_AUTHENTICATED, console::LINE_ENDING);
                } else if console_output_text.is_empty() {
                    console_output_text =
                        format!("{}{}", AUTHN_RESPONSE_UNAUTHENTICATED, console::LINE_ENDING);
                }
                authn_complete = true;
            }
        }

        Ok((console_output_text, response_authn_msg, authn_complete))
    }

    /// Process authentication message (Insecure)
    fn process_authn_message_for_insecure(
        &self,
        _: &mut MutexGuard<Option<AuthnContext>>,
        _: Option<AuthnMessage>,
    ) -> Result<(String, Option<AuthnMessage>, bool), AppError> {
        *self.authenticated.lock().unwrap() = true;
        Ok((
            format!("{}{}", AUTHN_RESPONSE_AUTHENTICATED, console::LINE_ENDING),
            None,
            true,
        ))
    }

    /// Process 'proxies' response
    fn process_response_proxies(
        &self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        gateway_response: &mut response::Response,
    ) -> Result<(), AppError> {
        let mut proxies =
            response::Proxy::from_serde_value(gateway_response.data.as_ref().unwrap())?;

        for proxy in &mut proxies {
            if let Some(proxy_addrs) = service_mgr
                .lock()
                .unwrap()
                .get_proxy_addrs_for_service(proxy.service.id)
            {
                proxy.client_port = Some(proxy_addrs.get_client_port());
            }
        }

        gateway_response.data = Some(serde_json::to_value(proxies).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Failed converting Proxies vector to serde Value::Array".to_string(),
                Box::new(err),
            )
        })?);

        Ok(())
    }

    /// Process 'login', 'login-data' responses
    fn process_response_login_data(
        &self,
        gateway_response: &mut response::Response,
    ) -> Result<(), AppError> {
        let login_data_list =
            response::LoginData::from_serde_value(gateway_response.data.as_ref().unwrap())?;

        if login_data_list.len() != 1 {
            return Err(AppError::General(format!(
                "Expecting a single login data response object: data={:?}",
                &login_data_list
            )));
        }
        let login_data = login_data_list.first().unwrap();

        if self.authn_context.lock().unwrap().is_none() {
            *self.authn_context.lock().unwrap() = Some(AuthnContext {
                authenticator: None,
                authn_type: login_data.authn_type.clone(),
                username: None,
            });
            self.process_authn_message(None)?;

            gateway_response.request = request::Request::Ignore;
        } else {
            self.process_authn_message(login_data.message.clone())?;
            gateway_response.request = request::Request::Ignore;
        }

        Ok(())
    }

    /// Process 'start' response
    fn process_response_start(
        &self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        gateway_response: &mut response::Response,
    ) -> Result<(), AppError> {
        let proxy_container =
            response::Proxy::from_serde_value(gateway_response.data.as_ref().unwrap())?;
        let proxy = proxy_container.first().unwrap();

        let _ = service_mgr.lock().unwrap().startup(
            &proxy.service.clone().into(),
            &manager::ProxyAddrs(
                proxy.client_port.unwrap(),
                proxy.gateway_host.as_ref().unwrap().to_string(),
                proxy.gateway_port,
            ),
        )?;

        Ok(())
    }

    /// Process 'quit' response
    fn process_response_quit(
        &self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
    ) -> Result<(), AppError> {
        service_mgr.lock().unwrap().shutdown()
    }
}

impl RequestProcessor for ControlPlane {
    fn set_event_channel_sender(
        &mut self,
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
    ) {
        self.event_channel_sender = Some(event_channel_sender);
    }

    fn validate_request(&mut self, command_line: &str) -> Result<request::Request, AppError> {
        let result: Result<request::Request, AppError>;

        if self.authn_context.lock().unwrap().is_some() {
            self.process_authn_message(Some(AuthnMessage::Payload(command_line.to_string())))?;
            result = Ok(request::Request::Ignore);
        } else {
            let processed_request = self.processor.parse(command_line);
            match processed_request {
                Ok(request::Request::None) => {
                    result = Ok(request::Request::None);
                }
                Err(err) => result = Err(err),
                _ => result = Ok(processed_request.unwrap().clone()),
            }
        }

        result
    }

    fn process_response(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        response_line: &str,
    ) -> Result<response::Response, AppError> {
        // Process response based on request context
        let mut gateway_response = response::Response::parse(response_line)?;

        if gateway_response.code == response::CODE_OK {
            match gateway_response.request.borrow() {
                request::Request::Login => {
                    self.process_response_login_data(&mut gateway_response)?;
                }
                request::Request::LoginData { message: _ } => {
                    self.process_response_login_data(&mut gateway_response)?;
                }
                request::Request::Proxies => {
                    self.process_response_proxies(service_mgr, &mut gateway_response)?;
                }
                request::Request::Start {
                    service_name: _,
                    local_port: _,
                } => {
                    self.process_response_start(service_mgr, &mut gateway_response)?;
                }
                request::Request::Quit => {
                    self.process_response_quit(service_mgr)?;
                }
                _ => {}
            }
        }

        if request::Request::Ignore == gateway_response.request {
            return Ok(gateway_response);
        }

        // Write response to REPL shell
        let repl_shell_response = format!(
            "{}\n",
            serde_json::to_string_pretty(&gateway_response).map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error serializing response".to_ascii_lowercase(),
                    Box::new(err),
                )
            })?
        );

        self.console_shell_output
            .lock()
            .unwrap()
            .write_all(repl_shell_response.as_bytes())
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error writing response to STDOUT".to_string(),
                    Box::new(err),
                )
            })?;

        Ok(gateway_response)
    }
}

pub trait RequestProcessor {
    /// Accept a connection event channel sender object
    fn set_event_channel_sender(
        &mut self,
        event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>,
    );

    /// Validate given command request, prior to being sent to the gateway control plane
    fn validate_request(&mut self, command_line: &str) -> Result<request::Request, AppError>;

    /// Process gateway response data
    fn process_response(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        response_line: &str,
    ) -> Result<response::Response, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use crate::service::manager::ProxyAddrs;
    use mockall::{mock, predicate};
    use regex::Regex;
    use ring::digest::SHA256_OUTPUT_LEN;
    use serde_json::json;
    use std::num::NonZeroU32;
    use std::sync::mpsc;
    use std::sync::mpsc::TryRecvError;
    use trust0_common::authn::authenticator::AuthenticatorServer;
    use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorServer;
    use trust0_common::model::service::Transport;
    use trust0_common::testutils::ChannelWriter;
    use trust0_common::{model, testutils};

    // mocks/dummies
    // =============

    mock! {
        pub GwReqProcessor {}
        impl RequestProcessor for GwReqProcessor {
            fn set_event_channel_sender(&mut self, event_channel_sender: mpsc::Sender<conn_std::ConnectionEvent>);
            fn validate_request(&mut self, command_line: &str)
                -> Result<request::Request, AppError>;
            fn process_response(&mut self, service_mgr: &Arc<Mutex<dyn ServiceMgr>>, response_line: &str)
                -> Result<response::Response, AppError>;
        }
    }

    pub struct ExampleProvider {
        user1_password: [u8; SHA256_OUTPUT_LEN],
    }

    impl ExampleProvider {
        pub fn new() -> Self {
            let pwd_iterations = NonZeroU32::new(4096).unwrap();
            let user1_password = scram::hash_password("pass1", pwd_iterations, b"user1");
            ExampleProvider { user1_password }
        }
    }

    impl scram::AuthenticationProvider for ExampleProvider {
        fn get_password_for(&self, username: &str) -> Option<scram::server::PasswordInfo> {
            match username {
                "user1" => Some(scram::server::PasswordInfo::new(
                    self.user1_password.to_vec(),
                    4096,
                    "user1".bytes().collect(),
                )),
                _ => None,
            }
        }
    }

    // tests
    // =====

    #[test]
    fn ctlplane_send_connection_event_when_no_errors() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let event_channel = mpsc::channel();
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        control_plane.set_event_channel_sender(event_channel.0);

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
        let app_config = config::tests::create_app_config(None).unwrap();
        let event_channel_sender;
        {
            event_channel_sender = mpsc::channel().0;
        }
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        control_plane.set_event_channel_sender(event_channel_sender);

        if let Ok(msg) = control_plane
            .send_connection_event_message(conn_std::ConnectionEvent::Write(vec![0x20]))
        {
            panic!("Unexpected successful send result: msg={:?}", &msg);
        }
    }

    #[test]
    fn ctlplane_validate_request_when_invalid_request() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let result = control_plane.validate_request("INVALID");
        match result {
            Ok(request) => {
                panic!("Unexpected validate request: req={:?}", request);
            }
            Err(err) => {
                assert!(err.get_code().is_some());
                assert_eq!(err.get_code().unwrap(), 400);
            }
        }
    }

    #[test]
    fn ctlplane_validate_request_when_valid_ping_request() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let result = control_plane.validate_request("ping");
        match result {
            Ok(request) => {
                if request != request::Request::Ping {
                    panic!("Unexpected validate request: req={:?}", request);
                }
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }
    }

    #[test]
    fn ctlplane_process_response_when_invalid_json_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let result = control_plane.process_response(&service_mgr, "INVALID");
        if let Ok(response) = &result {
            panic!("Unexpected process response: resp={:?}", response);
        }

        let expected_data = "".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_login_flow_for_scramsha256_step1() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        let event_channel = mpsc::channel();
        control_plane.set_event_channel_sender(event_channel.0);
        let response_data_str = r#"[{"authnType":"scramSha256","message":null}]"#;
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = control_plane.process_response(
            &service_mgr,
            &format!(
                r#"{{"code":200,"message":null,"request":"Login","data":{}}}"#,
                response_data_str
            ),
        );

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Ignore,
                    "Unexpected process response request: resp={:?}",
                    response
                );
                assert_eq!(
                    response.data,
                    Some(response_data_json),
                    "Unexpected process response data: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        assert!(control_plane.authn_context.lock().unwrap().is_some());
        assert_eq!(
            control_plane
                .authn_context
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .authn_type,
            AuthnType::ScramSha256
        );
        assert!(!*control_plane.authenticated.lock().unwrap());

        match event_channel.1.try_recv() {
            Ok(msg) => panic!("Unexpected event channel msg: msg={:?}", &msg),
            Err(err) if TryRecvError::Empty == err => {}
            Err(err) => panic!("Unexpected event channel result: err={:?}", &err),
        }

        let expected_data = AUTHN_LABEL_USERNAME.to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_login_flow_for_scramsha256_step2() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        let event_channel = mpsc::channel();
        control_plane.set_event_channel_sender(event_channel.0);
        *control_plane.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: None,
        });

        match control_plane.validate_request("user1") {
            Ok(request) if request::Request::Ignore == request => {}
            Ok(request) => panic!("Unexpected validate result: req={:?}", &request),
            Err(err) => panic!("Unexpected validate result: err={:?}", &err),
        }

        assert!(control_plane.authn_context.lock().unwrap().is_some());
        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .username
            .is_some());
        assert!(!*control_plane.authenticated.lock().unwrap());
        assert_eq!(
            control_plane
                .authn_context
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .username
                .as_ref()
                .unwrap(),
            "user1"
        );

        match event_channel.1.try_recv() {
            Ok(msg) => panic!("Unexpected event channel msg: msg={:?}", &msg),
            Err(err) if TryRecvError::Empty == err => {}
            Err(err) => panic!("Unexpected event channel result: err={:?}", &err),
        }

        let expected_data = AUTHN_LABEL_PASSWORD.to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_login_flow_for_scramsha256_step3() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        let event_channel = mpsc::channel();
        control_plane.set_event_channel_sender(event_channel.0);
        *control_plane.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: Some("user1".to_string()),
        });

        match control_plane.process_authn_message(Some(AuthnMessage::Payload("pass1".to_string())))
        {
            Err(err) => panic!("Unexpected process message result: err={:?}", &err),
            Ok(()) => {}
        }

        assert!(control_plane.authn_context.lock().unwrap().is_some());
        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .username
            .is_some());
        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .authenticator
            .is_some());
        assert!(!*control_plane.authenticated.lock().unwrap());
        assert_eq!(
            control_plane
                .authn_context
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .username
                .as_ref()
                .unwrap(),
            "user1"
        );

        match event_channel.1.try_recv() {
            Ok(msg) => match msg {
                conn_std::ConnectionEvent::Write(_) => {}
                _ => panic!("Unexpected event channel msg: msg={:?}", &msg),
            },
            Err(err) => panic!("Unexpected event channel result: err={:?}", &err),
        }

        let expected_data: Vec<u8> = vec![];
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(output_data, expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_login_flow_for_scramsha256_final_steps() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let login_data_payload_regex =
            Regex::new(r#"login-data --message "[{]\\"payload\\":\\"(?<data>[\S]+)\\"}""#).unwrap();

        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        let event_channel = mpsc::channel();
        control_plane.set_event_channel_sender(event_channel.0);
        *control_plane.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: Some("user1".to_string()),
        });

        // Perform step 3: In - None, Out - client first msg
        match control_plane.process_authn_message(Some(AuthnMessage::Payload("pass1".to_string())))
        {
            Err(err) => panic!("Unexpected process message result: step=3, err={:?}", &err),
            Ok(()) => {}
        }

        let client_to_server_data = match event_channel.1.try_recv() {
            Ok(msg) => match msg {
                conn_std::ConnectionEvent::Write(data) => String::from_utf8(data).unwrap(),
                _ => panic!("Unexpected event channel msg: step=3, msg={:?}", &msg),
            },
            Err(err) => panic!("Unexpected event channel result: step=3, err={:?}", &err),
        };

        let Some(captures) = login_data_payload_regex.captures(&client_to_server_data) else {
            panic!(
                "Unexpected client first message: msg={:?}",
                &client_to_server_data
            );
        };
        let client_to_server_data = captures["data"]
            .to_string()
            .replace("\\\\", "\\")
            .replace("\\\\", "\\")
            .replace("\\\"", "\"");
        let client_to_server_msg = Some(AuthnMessage::Payload(client_to_server_data));

        let mut auth_server =
            ScramSha256AuthenticatorServer::new(ExampleProvider::new(), Duration::from_millis(100));
        auth_server.spawn_authentication().unwrap();

        // Perform step 4: In - server first msg, Out - client final msg
        let server_to_client_data = match auth_server.exchange_messages(client_to_server_msg) {
            Ok(Some(server_to_client_msg)) => {
                if let AuthnMessage::Payload(data) = server_to_client_msg {
                    data
                } else {
                    panic!(
                        "Unexpected server response to client first msg: step=4, msg={:?}",
                        &server_to_client_msg
                    );
                }
            }
            Ok(None) => panic!("Unexpected missing server response to client first msg: step=4"),
            Err(err) => panic!(
                "Unexpected server response to client first msg: step=4, err={:?}",
                &err
            ),
        };

        let response_data_str = format!(
            r#"[{{"authnType":"scramSha256","message":{{"payload": "{}"}}}}]"#,
            &server_to_client_data
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = control_plane.process_response(
            &service_mgr,
            &format!(
                r#"{{"code":200,"message":null,"request":{},"data":{}}}"#,
                r#"{"LoginData":{"authnType":"scramSha256","message":{"payload":"msg1"}}}"#,
                response_data_str
            ),
        );

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: step=4, resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: step=4, resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Ignore,
                    "Unexpected process response request: step=4, resp={:?}",
                    response
                );
                assert_eq!(
                    response.data,
                    Some(response_data_json),
                    "Unexpected process response data: step=4, resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: step=4, err={:?}", err);
            }
        }

        assert!(control_plane.authn_context.lock().unwrap().is_some());
        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .username
            .is_some());
        assert!(control_plane
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .authenticator
            .is_some());
        assert!(!*control_plane.authenticated.lock().unwrap());
        assert_eq!(
            control_plane
                .authn_context
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .username
                .as_ref()
                .unwrap(),
            "user1"
        );

        let client_to_server_data = match event_channel.1.try_recv() {
            Ok(msg) => match msg {
                conn_std::ConnectionEvent::Write(data) => String::from_utf8(data).unwrap(),
                _ => panic!("Unexpected event channel msg: step=4, msg={:?}", &msg),
            },
            Err(err) => panic!("Unexpected event channel result: step=4, err={:?}", &err),
        };

        let Some(captures) = login_data_payload_regex.captures(&client_to_server_data) else {
            panic!(
                "Unexpected client first message: step=4, msg={:?}",
                &client_to_server_data
            );
        };
        let client_to_server_data = captures["data"]
            .to_string()
            .replace("\\\\", "\\")
            .replace("\\\\", "\\")
            .replace("\\\"", "\"");
        let client_to_server_msg = Some(AuthnMessage::Payload(client_to_server_data));

        // Perform step 5: In - server final msg, Out - None
        let server_to_client_data = match auth_server.exchange_messages(client_to_server_msg) {
            Ok(Some(server_to_client_msg)) => {
                if let AuthnMessage::Payload(data) = server_to_client_msg {
                    data
                } else {
                    panic!(
                        "Unexpected server response to client final msg: step=5, msg={:?}",
                        &server_to_client_msg
                    );
                }
            }
            Ok(None) => panic!("Unexpected missing server response to client final msg: step=5"),
            Err(err) => panic!(
                "Unexpected server response to client final msg: step=5, err={:?}",
                &err
            ),
        };

        let response_data_str = format!(
            r#"[{{"authnType":"scramSha256","message":{{"payload": "{}"}}}}]"#,
            &server_to_client_data
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = control_plane.process_response(
            &service_mgr,
            &format!(
                r#"{{"code":200,"message":null,"request":{},"data":{}}}"#,
                r#"{"LoginData":{"authnType":"scramSha256","message":{"payload":"msg1"}}}"#,
                response_data_str
            ),
        );

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: step=5, resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: step=5, resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Ignore,
                    "Unexpected process response request: step=5, resp={:?}",
                    response
                );
                assert_eq!(
                    response.data,
                    Some(response_data_json),
                    "Unexpected process response data: step=5, resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: step=5, err={:?}", err);
            }
        }

        assert!(control_plane.authn_context.lock().unwrap().is_none());
        assert!(*control_plane.authenticated.lock().unwrap());

        match event_channel.1.try_recv() {
            Ok(msg) => panic!("Unexpected successful event channel msg: msg={:?}", &msg),
            Err(err) if TryRecvError::Empty == err => {}
            Err(err) => panic!("Unexpected event channel result: err={:?}", &err),
        }

        let expected_data = format!(
            "{}{}{}",
            AUTHN_RESPONSE_AUTHENTICATED,
            console::LINE_ENDING,
            console::SHELL_PROMPT
        );
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_login_response_for_insecure_step1() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));
        let response_data_str = r#"[{"authnType":"insecure","message":null}]"#;
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = control_plane.process_response(
            &service_mgr,
            &format!(
                r#"{{"code":200,"message":null,"request":"Login","data":{}}}"#,
                response_data_str
            ),
        );

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Ignore,
                    "Unexpected process response request: resp={:?}",
                    response
                );
                assert_eq!(
                    response.data,
                    Some(response_data_json),
                    "Unexpected process response data: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        assert!(control_plane.authn_context.lock().unwrap().is_none());
        assert!(*control_plane.authenticated.lock().unwrap());

        let expected_data = format!(
            "{}{}{}",
            AUTHN_RESPONSE_AUTHENTICATED,
            console::LINE_ENDING,
            console::SHELL_PROMPT
        );
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_proxies_response_for_no_proxies() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let result = control_plane.process_response(
            &service_mgr,
            "{\"code\":200,\"message\":null,\"request\":\"Proxies\",\"data\":[]}",
        );
        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Proxies,
                    "Unexpected process response request: resp={:?}",
                    response
                );
                assert_eq!(
                    response.data,
                    Some(json!([])),
                    "Unexpected process response data: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": []\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_proxies_response_for_2_proxies() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_get_proxy_addrs_for_service()
            .with(predicate::eq(203))
            .times(1)
            .return_once(|_| Some(ProxyAddrs(8501, "gwhost1".to_string(), 8400)));
        service_mgr
            .expect_get_proxy_addrs_for_service()
            .with(predicate::eq(204))
            .times(1)
            .return_once(|_| Some(ProxyAddrs(8601, "gwhost1".to_string(), 8400)));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let response_data_str = "[
                {
                  \"client_port\": 8601,
                  \"gateway_host\": \"gwhost1\",
                  \"gateway_port\": 8400,
                  \"service\": {
                    \"address\": \"echohost1:8600\",
                    \"id\": 204,
                    \"name\": \"echo-udp\",
                    \"transport\": \"UDP\"
                  }
                },
                {
                  \"client_port\": 8501,
                  \"gateway_host\": \"gwhost1\",
                  \"gateway_port\": 8400,
                  \"service\": {
                    \"address\": \"chathost1:8500\",
                    \"id\": 203,
                    \"name\": \"chat-tcp\",
                    \"transport\": \"TCP\"
                  }
                }]";
        let response_str = format!(
            "{{\"code\":200,\"message\":null,\"request\":\"Proxies\",\"data\":{}}}",
            response_data_str
        );
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Proxies,
                    "Unexpected process response request: resp={:?}",
                    response
                );
                assert_eq!(
                    response.data,
                    Some(response_data_json),
                    "Unexpected process response data: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": [\n    {\n      \"client_port\": 8601,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 8400,\n      \"service\": {\n        \"address\": \"echohost1:8600\",\n        \"id\": 204,\n        \"name\": \"echo-udp\",\n        \"transport\": \"UDP\"\n      }\n    },\n    {\n      \"client_port\": 8501,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 8400,\n      \"service\": {\n        \"address\": \"chathost1:8500\",\n        \"id\": 203,\n        \"name\": \"chat-tcp\",\n        \"transport\": \"TCP\"\n      }\n    }\n  ]\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_start_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_startup()
            .with(
                predicate::eq(model::service::Service::new(
                    203,
                    "chat-tcp",
                    &Transport::TCP,
                    "chathost1",
                    8500,
                )),
                predicate::eq(ProxyAddrs(8501, "gwhost1".to_string(), 8400)),
            )
            .times(1)
            .return_once(|_, addrs| Ok(addrs.clone()));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let response_str = "{
              \"code\": 200,
              \"message\": null,
              \"request\": {
                \"Start\": {
                  \"service_name\": \"chat-tcp\",
                  \"local_port\": 8501
                }
              },
              \"data\": {
                \"client_port\": 8501,
                \"gateway_host\": \"gwhost1\",
                \"gateway_port\": 8400,
                \"service\": {
                  \"address\": \"chathost1:8500\",
                  \"id\": 203,
                  \"name\": \"chat-tcp\",
                  \"transport\": \"TCP\"
                }
              }
            }";

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Start {
                        service_name: "chat-tcp".to_string(),
                        local_port: 8501
                    },
                    "Unexpected process response request: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        let expected_data ="{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": {\n    \"Start\": {\n      \"service_name\": \"chat-tcp\",\n      \"local_port\": 8501\n    }\n  },\n  \"data\": {\n    \"client_port\": 8501,\n    \"gateway_host\": \"gwhost1\",\n    \"gateway_port\": 8400,\n    \"service\": {\n      \"address\": \"chathost1:8500\",\n      \"id\": 203,\n      \"name\": \"chat-tcp\",\n      \"transport\": \"TCP\"\n    }\n  }\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_quit_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_shutdown()
            .times(1)
            .return_once(|| Ok(()));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let response_str = "{\"code\":200,\"message\":null,\"request\":\"Quit\",\"data\":null}";

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 200,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message, None,
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Quit,
                    "Unexpected process response request: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Quit\",\n  \"data\": null\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_non200_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane =
            ControlPlane::new(Arc::new(app_config), Arc::new(Mutex::new(false)));

        let response_str = "{\"code\":500,\"message\":\"System error encountered\",\"request\":\"Ping\",\"data\":null}";

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(
                    response.code, 500,
                    "Unexpected process response code: resp={:?}",
                    response
                );
                assert_eq!(
                    response.message,
                    Some("System error encountered".to_string()),
                    "Unexpected process response msg: resp={:?}",
                    response
                );
                assert_eq!(
                    response.request,
                    request::Request::Ping,
                    "Unexpected process response request: resp={:?}",
                    response
                );
            }
            Err(err) => {
                panic!("Unexpected process response result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 500,\n  \"message\": \"System error encountered\",\n  \"request\": \"Ping\",\n  \"data\": null\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }
}
