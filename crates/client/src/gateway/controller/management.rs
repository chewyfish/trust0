use anyhow::Result;
use serde_json::Value;
use std::borrow::Borrow;
use std::collections::VecDeque;
use std::io::Write;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::Duration;
use trust0_common::authn::authenticator::{AuthenticatorClient, AuthnMessage, AuthnType};
use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorClient;

use crate::config::AppConfig;
#[cfg(not(test))]
use crate::console::ShellInputReader;
use crate::console::{self, InputTextStreamConnector, ShellOutputWriter};
use crate::gateway::controller::ChannelProcessor;
use crate::service::manager::{self, ServiceMgr};
use trust0_common::control::pdu::{ControlChannel, MessageFrame};
use trust0_common::control::{self, management};
use trust0_common::error::AppError;
use trust0_common::net::tls_client::conn_std;

const AUTHN_LABEL_USERNAME: &str = "Username: ";
const AUTHN_LABEL_PASSWORD: &str = "Password: ";

const AUTHN_RESPONSE_AUTHENTICATED: &str = "Authenticated";
const AUTHN_RESPONSE_UNAUTHENTICATED: &str = "Unauthenticated";
const AUTHN_RESPONSE_ERROR: &str = "Error";

/// (MFA) Authentication context
struct AuthnContext {
    /// Client authentication processor
    authenticator: Option<Box<dyn AuthenticatorClient>>,
    /// Authentication scheme
    authn_type: AuthnType,
    /// User-entered username (if appropriate for authn scheme)
    username: Option<String>,
}

/// Process control plane management commands (validate requests, parse gateway control plane responses).
pub struct ManagementController {
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Channel sender for connection events
    event_channel_sender: Option<mpsc::Sender<conn_std::ConnectionEvent>>,
    /// Queued PDU requests to be sent to gateway
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Management control plane request processor
    management_processor: management::request::RequestProcessor,
    /// Console input data reader
    stdin_connector: Box<dyn InputTextStreamConnector>,
    /// Console output writer
    console_shell_output: Arc<Mutex<ShellOutputWriter>>,
    /// Toggle terminal input echo display (for next input line read action)
    tty_echo_disabler: Arc<Mutex<bool>>,
    /// Context for an ongoing/past secondary authentication
    authn_context: Rc<Mutex<Option<AuthnContext>>>,
    /// Records whether user has passed secondary authentication
    authenticated: Rc<Mutex<bool>>,
}

impl ManagementController {
    /// Controller constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration
    /// * `service_mgr` - Service manager object
    /// * `message_outbox` - Processed requests (PDUs) to send to gateway
    ///
    /// # Returns
    ///
    /// A newly constructed [`ManagementController`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        message_outbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Self {
        let (stdin_connector, tty_echo_disabler) = Self::create_console_input_reader();
        Self {
            service_mgr: service_mgr.clone(),
            event_channel_sender: None,
            message_outbox: message_outbox.clone(),
            management_processor: management::request::RequestProcessor::new(),
            stdin_connector,
            console_shell_output: app_config.console_shell_output.clone(),
            tty_echo_disabler,
            authn_context: Rc::new(Mutex::new(None)),
            authenticated: Rc::new(Mutex::new(false)),
        }
    }

    /// Creates the input reader. Will spawn thread to handle queueing input.
    ///
    /// # Returns
    ///
    /// A tuple containing the [`InputTextStreamConnector`] and the TTY echo disabler
    ///
    #[cfg(not(test))]
    fn create_console_input_reader() -> (Box<dyn InputTextStreamConnector>, Arc<Mutex<bool>>) {
        let stdin_connector = ShellInputReader::new();
        stdin_connector.spawn_line_reader();
        let disable_tty_echo = stdin_connector.clone_disable_tty_echo();
        (Box::new(stdin_connector), disable_tty_echo)
    }
    #[cfg(test)]
    fn create_console_input_reader() -> (Box<dyn InputTextStreamConnector>, Arc<Mutex<bool>>) {
        (
            Box::new(console::tests::MockInpTxtStreamConnector::new()),
            Arc::new(Mutex::new(false)),
        )
    }

    /// Validate given command request, prior to being sent to the gateway control plane
    ///
    /// # Arguments
    ///
    /// * `command_line` - The corresponding serialized [`request::Request`] string to validate
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the deserialized [`request::Request`] object.
    ///
    fn validate_request(
        &mut self,
        command_line: &str,
    ) -> Result<management::request::Request, AppError> {
        let result: Result<management::request::Request, AppError>;

        if self.authn_context.lock().unwrap().is_some() {
            self.process_authn_message(&Some(AuthnMessage::Payload(command_line.to_string())))?;
            result = Ok(management::request::Request::Ignore);
        } else {
            let processed_request = self.management_processor.parse(command_line);
            match processed_request {
                Ok(management::request::Request::None) => {
                    result = Ok(management::request::Request::None);
                }
                Err(err) => result = Err(err),
                _ => result = Ok(processed_request.unwrap().clone()),
            }
        }

        result
    }

    /// Process 'proxies' response. Add local client port to proxies response for console display.
    ///
    /// # Arguments
    ///
    /// * `gateway_response` - Response object received from the gateway
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_message_proxies(
        &self,
        gateway_response: &mut management::response::Response,
    ) -> Result<(), AppError> {
        let mut proxies =
            management::response::Proxy::from_serde_value(gateway_response.data.as_ref().unwrap())?;

        for proxy in &mut proxies {
            if let Some(proxy_addrs) = self
                .service_mgr
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

    /// Process 'login', 'login-data' responses. Passes message to authentication processor
    ///
    /// # Arguments
    ///
    /// * `gateway_response` - Response object received from the gateway
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_message_login_data(
        &self,
        gateway_response: &mut management::response::Response,
    ) -> Result<(), AppError> {
        let login_data_list = management::response::LoginData::from_serde_value(
            gateway_response.data.as_ref().unwrap(),
        )?;

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
            self.process_authn_message(&login_data.message)?;

            gateway_response.request = management::request::Request::Ignore;
        } else {
            self.process_authn_message(&login_data.message)?;
            gateway_response.request = management::request::Request::Ignore;
        }

        Ok(())
    }

    /// Process 'start' response. Starts up service proxy on client.
    ///
    /// # Arguments
    ///
    /// * `gateway_response` - Response object received from the gateway
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_message_start(
        &self,
        gateway_response: &mut management::response::Response,
    ) -> Result<(), AppError> {
        let proxy_container =
            management::response::Proxy::from_serde_value(gateway_response.data.as_ref().unwrap())?;
        let proxy = proxy_container.first().unwrap();

        let _ = self.service_mgr.lock().unwrap().startup(
            &proxy.service.clone().into(),
            &manager::ProxyAddrs(
                proxy.client_port.unwrap(),
                proxy.gateway_host.as_ref().unwrap().to_string(),
                proxy.gateway_port,
            ),
        )?;

        Ok(())
    }

    /// Process 'quit' response. Shuts down service proxies.
    ///
    /// # Arguments
    ///
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_message_quit(&self) -> Result<(), AppError> {
        self.service_mgr.lock().unwrap().shutdown()
    }

    /// Process inbound gateway authentication message (as is appropriate for the current authentication state)
    ///
    /// # Arguments
    ///
    /// * `authn_msg` - Gateway authentication message to process
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation
    ///
    fn process_authn_message(&self, authn_msg: &Option<AuthnMessage>) -> Result<(), AppError> {
        // Process authentication message
        let mut authn_context = self.authn_context.lock().unwrap();
        let authn_type = authn_context.as_ref().unwrap().authn_type.clone();

        let (console_output_text, response_authn_msg, authn_complete) =
            if let Some(AuthnMessage::Authenticated) = authn_msg {
                *self.authenticated.lock().unwrap() = true;
                (
                    format!("{}{}", AUTHN_RESPONSE_AUTHENTICATED, console::LINE_ENDING),
                    None,
                    true,
                )
            } else if let Some(AuthnMessage::Unauthenticated(_)) = authn_msg {
                (
                    format!("{}{}", AUTHN_RESPONSE_UNAUTHENTICATED, console::LINE_ENDING),
                    None,
                    true,
                )
            } else {
                match authn_type {
                    AuthnType::ScramSha256 => {
                        self.process_authn_message_for_scramsha256(&mut authn_context, authn_msg)?
                    }
                    AuthnType::Insecure => {
                        self.process_authn_message_for_insecure(&mut authn_context, authn_msg)?
                    }
                }
            };

        // Send gateway PDU authentication message
        if response_authn_msg.is_some() {
            let msg_frame = MessageFrame::new(
                ControlChannel::Management,
                control::pdu::CODE_OK,
                &None,
                &None,
                &Some(Value::String(format!(
                    r#"{} --{} "{}""#,
                    management::request::PROTOCOL_REQUEST_LOGIN_DATA,
                    management::request::PROTOCOL_REQUEST_LOGIN_DATA_ARG_MESSAGE,
                    response_authn_msg
                        .unwrap()
                        .to_json_str()?
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                ))),
            );

            self.message_outbox
                .lock()
                .unwrap()
                .push_back(msg_frame.build_pdu()?);
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

    /// SCRAM SHA256 authentication state processor
    ///
    /// # Arguments
    ///
    /// * `authn_context` - Context for an ongoing authentication
    /// * `authn_msg` - Gateway authentication message to process
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a tuple of:
    ///
    /// * Console output test
    /// * Potential client response authentication message
    /// * Indication of whether authentication process is complete
    ///
    fn process_authn_message_for_scramsha256(
        &self,
        authn_context: &mut MutexGuard<Option<AuthnContext>>,
        authn_msg: &Option<AuthnMessage>,
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
            match authn_msg {
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
                .exchange_messages(authn_msg.clone())?;
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

    /// Insecure authentication state processor
    ///
    /// # Arguments
    ///
    /// * `authn_context` - Context for an ongoing authentication
    /// * `authn_msg` - Gateway authentication message to process
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a tuple of:
    ///
    /// * Console output test
    /// * Potential client response authentication message
    /// * Indication of whether authentication process is complete
    ///
    /// This will always return that the user has been authenticated.
    ///
    fn process_authn_message_for_insecure(
        &self,
        _: &mut MutexGuard<Option<AuthnContext>>,
        _: &Option<AuthnMessage>,
    ) -> Result<(String, Option<AuthnMessage>, bool), AppError> {
        *self.authenticated.lock().unwrap() = true;
        Ok((
            format!("{}{}", AUTHN_RESPONSE_AUTHENTICATED, console::LINE_ENDING),
            None,
            true,
        ))
    }
}

unsafe impl Send for ManagementController {}

impl ChannelProcessor for ManagementController {
    fn on_connected(
        &mut self,
        event_channel_sender: &mpsc::Sender<conn_std::ConnectionEvent>,
    ) -> Result<(), AppError> {
        self.event_channel_sender = Some(event_channel_sender.clone());

        self.console_shell_output
            .lock()
            .unwrap()
            .write_shell_prompt(true)
    }

    fn process_outbound_messages(&mut self) -> Result<(), AppError> {
        // Retrieve next command line (if available)
        let line = self.stdin_connector.next_line()?;
        if line.is_none() {
            return Ok(());
        }
        let line = line.unwrap();

        // Validate command
        let validated_request = self.validate_request(&line);

        match validated_request {
            Ok(management::request::Request::None) => {
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_shell_prompt(false)?;
                return Ok(());
            }
            Ok(management::request::Request::Ignore) => {
                return Ok(());
            }
            Err(err) => {
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_all(format!("{}\n", err).as_bytes())
                    .map_err(|err| {
                        AppError::GenWithMsgAndErr(
                            "Error writing invalid command response to STDOUT".to_string(),
                            Box::new(err),
                        )
                    })?;
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_shell_prompt(false)?;
                return Ok(());
            }
            _ => {}
        }

        // Valid command, send PDU to gateway control plane
        let msg_frame = MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &None,
            &None,
            &Some(Value::String(line)),
        );

        self.message_outbox
            .lock()
            .unwrap()
            .push_back(msg_frame.build_pdu()?);

        Ok(())
    }

    fn process_inbound_message(&mut self, message: MessageFrame) -> Result<(), AppError> {
        let mut gateway_response: management::response::Response = message.try_into()?;

        // Process (good) response by type
        if gateway_response.code == control::pdu::CODE_OK {
            match gateway_response.request.borrow() {
                management::request::Request::Login => {
                    self.process_inbound_message_login_data(&mut gateway_response)?;
                }
                management::request::Request::LoginData { message: _ } => {
                    self.process_inbound_message_login_data(&mut gateway_response)?;
                }
                management::request::Request::Proxies => {
                    self.process_inbound_message_proxies(&mut gateway_response)?;
                }
                management::request::Request::Start {
                    service_name: _,
                    local_port: _,
                } => {
                    self.process_inbound_message_start(&mut gateway_response)?;
                }
                management::request::Request::Quit => {
                    self.process_inbound_message_quit()?;
                }
                _ => {}
            }
        }

        if management::request::Request::Ignore == gateway_response.request {
            return Ok(());
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

        self.console_shell_output
            .lock()
            .unwrap()
            .write_shell_prompt(false)?;

        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use mockall::predicate;
    use regex::Regex;
    use ring::digest::SHA256_OUTPUT_LEN;
    use std::num::NonZeroU32;
    use std::sync::mpsc;
    use trust0_common::authn::authenticator::AuthenticatorServer;
    use trust0_common::authn::scram_sha256_authenticator::ScramSha256AuthenticatorServer;
    use trust0_common::testutils::ChannelWriter;
    use trust0_common::{model, testutils};

    // mocks/dummies
    // =============

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
    fn mgtcontrol_new() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let controller = ManagementController::new(
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service_mgr,
            &Arc::new(Mutex::new(VecDeque::new())),
        );

        assert!(controller.event_channel_sender.is_none());
        assert!(!*controller.tty_echo_disabler.lock().unwrap());
        assert!(controller.authn_context.lock().unwrap().is_none());
        assert!(!*controller.authenticated.lock().unwrap());
    }

    #[test]
    fn mgtcontrol_on_connected() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut controller = ManagementController::new(
            &Arc::new(app_config),
            &service_mgr,
            &Arc::new(Mutex::new(VecDeque::new())),
        );

        if let Err(err) = controller.on_connected(&mpsc::channel().0) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(controller.event_channel_sender.is_some());

        let expected_data = format!(
            "{} v{} {}\n{}",
            console::SHELL_MSG_APP_TITLE,
            console::SHELL_MSG_APP_VERSION,
            console::SHELL_MSG_APP_HELP,
            console::SHELL_PROMPT,
        );
        let output_data = String::from_utf8(testutils::gather_rcvd_bytearr_channel_data(
            &output_channel.1,
        ))
        .unwrap();
        assert_eq!(output_data, expected_data);
    }

    #[test]
    fn mgtcontrol_validate_request_when_invalid_request() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut controller = ManagementController::new(
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service_mgr,
            &Arc::new(Mutex::new(VecDeque::new())),
        );

        let result = controller.validate_request("INVALID");
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
    fn mgtcontrol_validate_request_when_valid_ping_request() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut controller = ManagementController::new(
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service_mgr,
            &Arc::new(Mutex::new(VecDeque::new())),
        );

        let result = controller.validate_request("ping");
        match result {
            Ok(request) => {
                if request != management::request::Request::Ping {
                    panic!("Unexpected validate request: req={:?}", request);
                }
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }
    }

    #[test]
    fn mgtcontrol_process_outbound_messages_when_no_input_lines() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut stdin_connector = console::tests::MockInpTxtStreamConnector::new();
        stdin_connector.expect_next_line().return_once(|| Ok(None));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);
        controller.stdin_connector = Box::new(stdin_connector);

        if let Err(err) = controller.process_outbound_messages() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert!(output_data.is_empty());
    }

    #[test]
    fn mgtcontrol_process_outbound_messages_when_blank_request() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut stdin_connector = console::tests::MockInpTxtStreamConnector::new();
        stdin_connector
            .expect_next_line()
            .return_once(|| Ok(Some(String::new())));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);
        controller.stdin_connector = Box::new(stdin_connector);

        if let Err(err) = controller.process_outbound_messages() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("Response: code=400, msg=COMMANDS:\n  about        Display context information for connected mTLS device user\n  connections  List current service proxy connections\n  login        Perform challenge-response authentication (if gateway configured for MFA)\n  ping         Simple gateway heartbeat request\n  proxies      List active service proxies, ready for new connections\n  services     List authorized services for connected mTLS device user\n  start        Startup proxy to authorized service via secure client-gateway proxy\n  stop         Shutdown active service proxy (previously started)\n  quit         Quit the control plane (and corresponding service connections)\n  help         Print this message or the help of the given subcommand(s)\n\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_outbound_messages_when_invalid_request() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut stdin_connector = console::tests::MockInpTxtStreamConnector::new();
        stdin_connector
            .expect_next_line()
            .return_once(|| Ok(Some("invalid1".to_string())));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);
        controller.stdin_connector = Box::new(stdin_connector);

        if let Err(err) = controller.process_outbound_messages() {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("Response: code=400, msg=error: unrecognized subcommand 'invalid1'\n\nUsage: <COMMAND>\n\nFor more information, try 'help'.\n\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_outbound_messages_when_valid_ping_request() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut stdin_connector = console::tests::MockInpTxtStreamConnector::new();
        stdin_connector
            .expect_next_line()
            .return_once(|| Ok(Some("ping".to_string())));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);
        controller.stdin_connector = Box::new(stdin_connector);

        if let Err(err) = controller.process_outbound_messages() {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_request_pdu = MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &None,
            &None,
            &Some(Value::String("ping".to_string())),
        )
        .build_pdu()
        .unwrap();
        assert!(!message_outbox.lock().unwrap().is_empty());
        assert_eq!(
            message_outbox.lock().unwrap().get(0).unwrap(),
            &expected_request_pdu
        );

        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert!(output_data.is_empty());
    }

    #[test]
    fn mgtcontrol_process_outbound_messages_when_valid_login_flow_for_scramsha256_step2() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut stdin_connector = console::tests::MockInpTxtStreamConnector::new();
        stdin_connector
            .expect_next_line()
            .return_once(|| Ok(Some("user1".to_string())));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);
        controller.stdin_connector = Box::new(stdin_connector);
        *controller.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: None,
        });

        match controller.validate_request("user1") {
            Ok(request) if management::request::Request::Ignore == request => {}
            Ok(request) => panic!("Unexpected validate result: req={:?}", &request),
            Err(err) => panic!("Unexpected validate result: err={:?}", &err),
        }

        assert!(controller.authn_context.lock().unwrap().is_some());
        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .username
            .is_some());
        assert!(!*controller.authenticated.lock().unwrap());
        assert_eq!(
            controller
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

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = AUTHN_LABEL_PASSWORD.to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_login_flow_for_scramsha256_step1() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let response_data_str = r#"[{"authnType":"scramSha256","message":null}]"#;
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = controller.process_inbound_message(MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &None,
            &Some(serde_json::to_value(management::request::Request::Login).unwrap()),
            &Some(response_data_json),
        ));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(controller.authn_context.lock().unwrap().is_some());
        assert_eq!(
            controller
                .authn_context
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .authn_type,
            AuthnType::ScramSha256
        );
        assert!(!*controller.authenticated.lock().unwrap());

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = AUTHN_LABEL_USERNAME.to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_proxies_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_get_proxy_addrs_for_service()
            .with(predicate::eq(200))
            .times(1)
            .return_once(|_| Some(manager::ProxyAddrs(8501, "gwhost1".to_string(), 1234)));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let response_data = management::response::Proxy::new(
            &management::response::Service::new(
                200,
                "svc200",
                &model::service::Transport::TCP,
                &None,
            ),
            &None,
            1234,
            &None,
        );
        let response_data_json = serde_json::to_value(vec![response_data]).unwrap();

        let result = controller.process_inbound_message(MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &None,
            &Some(serde_json::to_value(management::request::Request::Proxies).unwrap()),
            &Some(response_data_json),
        ));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("{{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": [\n    {{\n      \"client_port\": 8501,\n      \"gateway_host\": null,\n      \"gateway_port\": 1234,\n      \"service\": {{\n        \"address\": null,\n        \"id\": 200,\n        \"name\": \"svc200\",\n        \"transport\": \"TCP\"\n      }}\n    }}\n  ]\n}}\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_start_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let service = model::service::Service::new(
            200,
            "svc200",
            &model::service::Transport::TCP,
            "svchost1",
            9999,
        );
        let response_service = management::response::Service::new(
            200,
            "svc200",
            &model::service::Transport::TCP,
            &Some("svchost1:9999".to_string()),
        );
        let proxy_addrs = manager::ProxyAddrs(8501, "gwhost1".to_string(), 1234);
        let proxy_addrs_copy = proxy_addrs.clone();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_startup()
            .with(
                predicate::eq(service.clone()),
                predicate::eq(proxy_addrs.clone()),
            )
            .times(1)
            .return_once(|_, _| Ok(proxy_addrs_copy));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let response_data = management::response::Proxy::new(
            &response_service,
            &Some("gwhost1".to_string()),
            1234,
            &Some(8501),
        );
        let response_data_json = serde_json::to_value(vec![response_data]).unwrap();

        let result = controller.process_inbound_message(MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &None,
            &Some(
                serde_json::to_value(management::request::Request::Start {
                    service_name: "svc200".to_string(),
                    local_port: 8501,
                })
                .unwrap(),
            ),
            &Some(response_data_json),
        ));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("{{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": {{\n    \"Start\": {{\n      \"service_name\": \"svc200\",\n      \"local_port\": 8501\n    }}\n  }},\n  \"data\": [\n    {{\n      \"client_port\": 8501,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 1234,\n      \"service\": {{\n        \"address\": \"svchost1:9999\",\n        \"id\": 200,\n        \"name\": \"svc200\",\n        \"transport\": \"TCP\"\n      }}\n    }}\n  ]\n}}\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_quit_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr
            .expect_shutdown()
            .times(1)
            .return_once(|| Ok(()));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let result = controller.process_inbound_message(MessageFrame::new(
            ControlChannel::Management,
            control::pdu::CODE_OK,
            &None,
            &Some(serde_json::to_value(management::request::Request::Quit).unwrap()),
            &None,
        ));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("{{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Quit\",\n  \"data\": null\n}}\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_authn_message_when_given_authenticated_msg() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);
        *controller.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: Some("user1".to_string()),
        });

        match controller.process_authn_message(&Some(AuthnMessage::Authenticated)) {
            Err(err) => panic!("Unexpected process message result: err={:?}", &err),
            Ok(()) => {}
        }

        assert!(controller.authn_context.lock().unwrap().is_none());
        assert!(*controller.authenticated.lock().unwrap());
        assert!(message_outbox.lock().unwrap().is_empty());

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
    fn mgtcontrol_process_authn_message_when_given_unauthenticated_msg() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        *controller.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: Some("user1".to_string()),
        });

        match controller
            .process_authn_message(&Some(AuthnMessage::Unauthenticated("msg1".to_string())))
        {
            Err(err) => panic!("Unexpected process message result: err={:?}", &err),
            Ok(()) => {}
        }

        assert!(controller.authn_context.lock().unwrap().is_none());
        assert!(!*controller.authenticated.lock().unwrap());
        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!(
            "{}{}{}",
            AUTHN_RESPONSE_UNAUTHENTICATED,
            console::LINE_ENDING,
            console::SHELL_PROMPT
        );
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_authn_message_when_valid_login_flow_for_scramsha256_step3() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        *controller.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: Some("user1".to_string()),
        });

        match controller.process_authn_message(&Some(AuthnMessage::Payload("pass1".to_string()))) {
            Err(err) => panic!("Unexpected process message result: err={:?}", &err),
            Ok(()) => {}
        }

        assert!(controller.authn_context.lock().unwrap().is_some());
        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .username
            .is_some());
        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .authenticator
            .is_some());
        assert!(!*controller.authenticated.lock().unwrap());
        assert_eq!(
            controller
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

        assert_eq!(message_outbox.lock().unwrap().len(), 1);

        let expected_data: Vec<u8> = vec![];
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert_eq!(output_data, expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_login_flow_for_scramsha256_final_steps() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let login_data_payload_regex =
            Regex::new(r#"login-data --message "[{]\\"payload\\":\\"(?<data>[\S]+)\\"}""#).unwrap();
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        *controller.authn_context.lock().unwrap() = Some(AuthnContext {
            authenticator: None,
            authn_type: AuthnType::ScramSha256,
            username: Some("user1".to_string()),
        });

        // Perform step 3: In - None, Out - client first msg
        match controller.process_authn_message(&Some(AuthnMessage::Payload("pass1".to_string()))) {
            Err(err) => panic!("Unexpected process message result: step=3, err={:?}", &err),
            Ok(()) => {}
        }

        assert_eq!(message_outbox.lock().unwrap().len(), 1);

        let mut request_msg_buffer =
            VecDeque::from(message_outbox.lock().unwrap().pop_front().unwrap());
        let request_msg_result = MessageFrame::consume_next_pdu(&mut request_msg_buffer);
        let request_msg = match request_msg_result {
            Ok(Some(request_msg)) => request_msg,
            Ok(None) => panic!(
                "Unable to parse message frame PDU: step=3. buf={:?}",
                &request_msg_buffer
            ),
            Err(err) => panic!(
                "Unexpected message frame parse result: step=3, err={:?}",
                &err
            ),
        };
        if request_msg.data.is_none() {
            panic!("Missing message frame data: step=3, msg={:?}", &request_msg);
        }
        let client_to_server_data: String =
            serde_json::from_value(request_msg.data.unwrap()).unwrap();

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

        let response: MessageFrame = serde_json::from_str(&format!(
            r#"{{"channel":"Management","code":200,"message":null,"context":{},"data":{}}}"#,
            r#"{"LoginData":{"authnType":"scramSha256","message":{"payload":"msg1"}}}"#,
            response_data_str
        ))
        .unwrap();

        let response_result = controller.process_inbound_message(response);
        if let Err(err) = response_result {
            panic!("Unexpected process response result: step=4, err={:?}", &err);
        }

        assert!(controller.authn_context.lock().unwrap().is_some());
        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .username
            .is_some());
        assert!(controller
            .authn_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .authenticator
            .is_some());
        assert!(!*controller.authenticated.lock().unwrap());
        assert_eq!(
            controller
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

        assert_eq!(message_outbox.lock().unwrap().len(), 1);

        let mut request_msg_buffer =
            VecDeque::from(message_outbox.lock().unwrap().pop_front().unwrap());
        let request_msg_result = MessageFrame::consume_next_pdu(&mut request_msg_buffer);
        let request_msg = match request_msg_result {
            Ok(Some(request_msg)) => request_msg,
            Ok(None) => panic!(
                "Unable to parse message frame PDU: step=4. buf={:?}",
                &request_msg_buffer
            ),
            Err(err) => panic!(
                "Unexpected message frame parse result: step=4, err={:?}",
                &err
            ),
        };
        if request_msg.data.is_none() {
            panic!("Missing message frame data: step=4, msg={:?}", &request_msg);
        }
        let client_to_server_data: String =
            serde_json::from_value(request_msg.data.unwrap()).unwrap();

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

        let response: MessageFrame = serde_json::from_str(&format!(
            r#"{{"channel":"Management","code":200,"message":null,"context":{},"data":{}}}"#,
            r#"{"LoginData":{"authnType":"scramSha256","message":{"payload":"msg1"}}}"#,
            response_data_str
        ))
        .unwrap();

        let response_result = controller.process_inbound_message(response);
        if let Err(err) = response_result {
            panic!("Unexpected process response result: step=5, err={:?}", &err);
        }

        assert!(controller.authn_context.lock().unwrap().is_none());
        assert!(*controller.authenticated.lock().unwrap());
        assert!(message_outbox.lock().unwrap().is_empty());

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
    fn mgtcontrol_process_inbound_message_when_valid_login_response_for_insecure_step1() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let response: MessageFrame = serde_json::from_str(&format!(
            r#"{{"channel":"Management","code":200,"message":null,"context":"Login","data":{}}}"#,
            r#"[{"authnType":"insecure","message":null}]"#
        ))
        .unwrap();

        let result = controller.process_inbound_message(response);

        if let Err(err) = result {
            panic!("Unexpected process response result: err={:?}", &err);
        }

        assert!(controller.authn_context.lock().unwrap().is_none());
        assert!(*controller.authenticated.lock().unwrap());
        assert!(message_outbox.lock().unwrap().is_empty());

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
    fn mgtcontrol_process_inbound_message_when_valid_proxies_response_for_no_proxies() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let response: MessageFrame = serde_json::from_str(
            r#"{"channel":"Management","code":200,"message":null,"context":"Proxies","data":[]}"#,
        )
        .unwrap();

        let result = controller.process_inbound_message(response);
        if let Err(err) = result {
            panic!("Unexpected process response result: err={:?}", err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("{{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": []\n}}\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_proxies_response_for_2_proxies() {
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
            .return_once(|_| Some(manager::ProxyAddrs(8501, "gwhost1".to_string(), 8400)));
        service_mgr
            .expect_get_proxy_addrs_for_service()
            .with(predicate::eq(204))
            .times(1)
            .return_once(|_| Some(manager::ProxyAddrs(8601, "gwhost1".to_string(), 8400)));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

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
            "{{\"channel\":\"Management\",\"code\":200,\"message\":null,\"context\":\"Proxies\",\"data\":{}}}",
            response_data_str
        );
        let response: MessageFrame = serde_json::from_str(&response_str).unwrap();

        let result = controller.process_inbound_message(response);

        if let Err(err) = result {
            panic!("Unexpected process response result: err={:?}", &err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("{{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": [\n    {{\n      \"client_port\": 8601,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 8400,\n      \"service\": {{\n        \"address\": \"echohost1:8600\",\n        \"id\": 204,\n        \"name\": \"echo-udp\",\n        \"transport\": \"UDP\"\n      }}\n    }},\n    {{\n      \"client_port\": 8501,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 8400,\n      \"service\": {{\n        \"address\": \"chathost1:8500\",\n        \"id\": 203,\n        \"name\": \"chat-tcp\",\n        \"transport\": \"TCP\"\n      }}\n    }}\n  ]\n}}\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn mgtcontrol_process_inbound_message_when_valid_non200_response() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> =
            Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let message_outbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut controller =
            ManagementController::new(&Arc::new(app_config), &service_mgr, &message_outbox);

        let response_str = "{\"channel\":\"Management\",\"code\":500,\"message\":\"System error encountered\",\"context\":\"Ping\",\"data\":null}";
        let response: MessageFrame = serde_json::from_str(&response_str).unwrap();

        let result = controller.process_inbound_message(response);

        if let Err(err) = result {
            panic!("Unexpected process response result: err={:?}", err);
        }

        assert!(message_outbox.lock().unwrap().is_empty());

        let expected_data = format!("{{\n  \"code\": 500,\n  \"message\": \"System error encountered\",\n  \"request\": \"Ping\",\n  \"data\": null\n}}\n{}", console::SHELL_PROMPT);
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }
}
