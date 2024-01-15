use crate::authn::authenticator::{AuthenticatorClient, AuthenticatorServer, AuthnMessage};
use crate::error::AppError;
use crate::model;
use base64::prelude::*;
use log::error;
use scram::AuthenticationStatus;
use std::num::NonZeroU32;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Hash password (as is expected by this implementation)
pub fn hash_password(username: &str, password: &str, base64_encode: bool) -> Vec<u8> {
    let hashed_password = scram::hash_password(
        password,
        NonZeroU32::new(4096).unwrap(),
        username.as_bytes(),
    );

    if base64_encode {
        BASE64_URL_SAFE.encode(hashed_password).as_bytes().to_vec()
    } else {
        hashed_password.to_vec()
    }
}

/// Handle processing error
fn process_error(
    response_sender: &Option<mpsc::Sender<AuthnMessage>>,
    app_error: Option<AppError>,
    scram_error: Option<scram::Error>,
) -> Result<AuthnMessage, AppError> {
    let authn_msg = match app_error {
        Some(err) => AuthnMessage::Error(format!("{:?}", &err)),
        None => {
            let error = scram_error.unwrap();
            match &error {
                scram::Error::InvalidServer => {
                    AuthnMessage::Unauthenticated(format!("{:?}", &error))
                }
                scram::Error::Authentication(_) => {
                    AuthnMessage::Unauthenticated(format!("{:?}", &error))
                }
                scram::Error::InvalidUser(_) => {
                    AuthnMessage::Unauthenticated(format!("{:?}", &error))
                }
                _ => AuthnMessage::Error(format!(
                    "SCRAM SHA256 authentication processing error: err={:?}",
                    &error
                )),
            }
        }
    };

    if response_sender.is_some() {
        response_sender
            .as_ref()
            .unwrap()
            .send(authn_msg.clone())
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error sending SCRAM SHA256 error message".to_string(),
                    Box::new(err),
                )
            })?;
    }

    Ok(authn_msg)
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
/// Client authentication "challenge-response" state flow
enum ClientStateFlow {
    New,
    ClientInitialSent,
    ServerChallengeRecvd,
    ClientResponseSent,
    ServerFinalRecvd,
}

/// Client authenticator utilizing SCRAM SHA256 SASL authentication
pub struct ScramSha256AuthenticatorClient {
    client_response_sender: Option<mpsc::Sender<AuthnMessage>>,
    client_response_receiver: Option<mpsc::Receiver<AuthnMessage>>,
    server_response_sender: Option<mpsc::Sender<AuthnMessage>>,
    server_response_receiver: Option<mpsc::Receiver<AuthnMessage>>,
    username: String,
    password: String,
    channel_timeout: Duration,
    authenticated: Arc<Mutex<bool>>,
    #[cfg(test)]
    state: Arc<Mutex<ClientStateFlow>>,
}

impl ScramSha256AuthenticatorClient {
    /// ScramSha256AuthenticatorClient constructor
    pub fn new(username: &str, password: &str, channel_timeout: Duration) -> Self {
        let client_response_channel = mpsc::channel();
        let server_response_channel = mpsc::channel();
        Self {
            client_response_sender: Some(client_response_channel.0),
            client_response_receiver: Some(client_response_channel.1),
            server_response_sender: Some(server_response_channel.0),
            server_response_receiver: Some(server_response_channel.1),
            username: username.to_string(),
            password: password.to_string(),
            channel_timeout,
            authenticated: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            state: Arc::new(Mutex::new(ClientStateFlow::New)),
        }
    }
}

impl AuthenticatorClient for ScramSha256AuthenticatorClient {
    fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>> {
        let mut auth_client = ScramSha256AuthenticatorClient {
            client_response_sender: self.client_response_sender.take(),
            client_response_receiver: None,
            server_response_sender: None,
            server_response_receiver: self.server_response_receiver.take(),
            username: self.username.clone(),
            password: self.password.clone(),
            channel_timeout: self.channel_timeout,
            authenticated: self.authenticated.clone(),
            #[cfg(test)]
            state: self.state.clone(),
        };

        Some(thread::spawn(move || auth_client.authenticate()))
    }

    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        // Process (build/send) client first auth message
        let client_request_processor =
            scram::ScramClient::new(&self.username, &self.password, None);
        let (server_response_handler, client_first_msg) = client_request_processor.client_first();

        self.client_response_sender
            .as_ref()
            .unwrap()
            .send(AuthnMessage::Payload(client_first_msg.clone()))
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error sending SCRAM SHA256 client first message: user={}, msg={}",
                        self.username, &client_first_msg
                    ),
                    Box::new(err),
                )
            })?;

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ClientStateFlow::ClientInitialSent;
        }

        // Process (recv/parse) server first response
        let server_first_msg = match self
            .server_response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(self.channel_timeout)
        {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => {
                    if AuthnMessage::Authenticated == auth_msg {
                        *self.authenticated.lock().unwrap() = true;
                    }
                    return Ok(auth_msg);
                }
            },
            Err(err) => {
                return process_error(
                    &self.client_response_sender,
                    Some(AppError::GenWithMsgAndErr(
                        format!(
                            "Error receiving SCRAM SHA256 server first message: user={}",
                            self.username
                        ),
                        Box::new(err),
                    )),
                    None,
                )
            }
        };

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ClientStateFlow::ServerChallengeRecvd;
        }

        let client_response_processor =
            match server_response_handler.handle_server_first(&server_first_msg) {
                Ok(processor) => processor,
                Err(err) => return process_error(&self.client_response_sender, None, Some(err)),
            };

        // Process (build/send) client final auth message
        let (server_response_handler, client_final_msg) = client_response_processor.client_final();

        self.client_response_sender
            .as_ref()
            .unwrap()
            .send(AuthnMessage::Payload(client_final_msg.clone()))
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error sending SCRAM SHA256 client final message: user={}, msg={}",
                        self.username, &client_final_msg
                    ),
                    Box::new(err),
                )
            })?;

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ClientStateFlow::ClientResponseSent;
        }

        // Process (recv/parse) server final response
        let server_final_msg = match self
            .server_response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(self.channel_timeout)
        {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => {
                    if AuthnMessage::Authenticated == auth_msg {
                        *self.authenticated.lock().unwrap() = true;
                    }
                    return Ok(auth_msg);
                }
            },
            Err(err) => {
                return process_error(
                    &None,
                    Some(AppError::GenWithMsgAndErr(
                        format!(
                            "Error receiving SCRAM SHA256 server final message: user={}",
                            self.username
                        ),
                        Box::new(err),
                    )),
                    None,
                )
            }
        };

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ClientStateFlow::ServerFinalRecvd;
        }

        match server_response_handler.handle_server_final(&server_final_msg) {
            Ok(()) => {
                *self.authenticated.lock().unwrap() = true;
                Ok(AuthnMessage::Authenticated)
            }
            Err(err) => process_error(&None, None, Some(err)),
        }
    }

    fn exchange_messages(
        &mut self,
        inbound_msg: Option<AuthnMessage>,
    ) -> Result<Option<AuthnMessage>, AppError> {
        if inbound_msg.is_some() {
            self.server_response_sender
                .as_ref()
                .unwrap()
                .send(inbound_msg.unwrap())
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending SCRAM SHA256 client inbound message".to_string(),
                        Box::new(err),
                    )
                })?;
        }

        match self
            .client_response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_millis(150))
        {
            Ok(msg) => return Ok(Some(msg)),
            Err(RecvTimeoutError::Disconnected) => return Ok(None),
            _ => {}
        }

        Ok(None)
    }

    fn is_authenticated(&self) -> bool {
        *self.authenticated.lock().unwrap()
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
/// Server authentication "challenge-response" state flow
enum ServerStateFlow {
    New,
    ClientInitialRecvd,
    ServerChallengeSent,
    ClientResponseRecvd,
    ServerFinalSent,
}

/// Server authenticator utilizing SCRAM SHA256 SASL authentication
pub struct ScramSha256AuthenticatorServer<P>
where
    P: scram::AuthenticationProvider + Sized,
{
    server_response_sender: Option<mpsc::Sender<AuthnMessage>>,
    server_response_receiver: Option<mpsc::Receiver<AuthnMessage>>,
    client_response_sender: Option<mpsc::Sender<AuthnMessage>>,
    client_response_receiver: Option<mpsc::Receiver<AuthnMessage>>,
    auth_provider: Option<Box<P>>,
    channel_timeout: Duration,
    authenticated: Arc<Mutex<bool>>,
    #[cfg(test)]
    state: Arc<Mutex<ServerStateFlow>>,
}

impl<P> ScramSha256AuthenticatorServer<P>
where
    P: scram::AuthenticationProvider + Send + Sized + 'static,
{
    /// ScramSha256AuthenticatorServer constructor
    pub fn new(auth_provider: P, channel_timeout: Duration) -> Self {
        let server_response_channel = mpsc::channel();
        let client_response_channel = mpsc::channel();
        Self {
            server_response_sender: Some(server_response_channel.0),
            server_response_receiver: Some(server_response_channel.1),
            client_response_sender: Some(client_response_channel.0),
            client_response_receiver: Some(client_response_channel.1),
            auth_provider: Some(Box::new(auth_provider)),
            channel_timeout,
            authenticated: Arc::new(Mutex::new(false)),
            #[cfg(test)]
            state: Arc::new(Mutex::new(ServerStateFlow::New)),
        }
    }
}

impl<P> AuthenticatorServer for ScramSha256AuthenticatorServer<P>
where
    P: scram::AuthenticationProvider + Send + Sized + 'static,
{
    fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>> {
        let mut auth_server = ScramSha256AuthenticatorServer {
            server_response_sender: self.server_response_sender.take(),
            server_response_receiver: None,
            client_response_sender: None,
            client_response_receiver: self.client_response_receiver.take(),
            auth_provider: self.auth_provider.take(),
            channel_timeout: self.channel_timeout,
            authenticated: self.authenticated.clone(),
            #[cfg(test)]
            state: self.state.clone(),
        };

        Some(thread::spawn(move || auth_server.authenticate()))
    }

    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        // Process (recv/parse) client first auth message
        let client_first_msg = match self
            .client_response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(self.channel_timeout)
        {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => {
                    return process_error(
                        &self.server_response_sender,
                        Some(AppError::General(format!(
                            "Unexpected SCRAM SHA256 client first message: msg={:?}",
                            &auth_msg
                        ))),
                        None,
                    )
                }
            },
            Err(err) => {
                return process_error(
                    &self.server_response_sender,
                    Some(AppError::GenWithMsgAndErr(
                        "Error receiving SCRAM SHA256 client first message".to_string(),
                        Box::new(err),
                    )),
                    None,
                )
            }
        };

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ServerStateFlow::ClientInitialRecvd;
        }

        let client_response_handler = scram::ScramServer::new(*self.auth_provider.take().unwrap());
        let server_response_processor =
            match client_response_handler.handle_client_first(&client_first_msg) {
                Ok(processor) => processor,
                Err(err) => return process_error(&self.server_response_sender, None, Some(err)),
            };

        // Process (build/send) server first (challenge) message
        let (client_response_handler, server_first_msg) = server_response_processor.server_first();

        self.server_response_sender
            .as_ref()
            .unwrap()
            .send(AuthnMessage::Payload(server_first_msg.clone()))
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error sending SCRAM SHA256 server first message: msg={}",
                        &server_first_msg
                    ),
                    Box::new(err),
                )
            })?;

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ServerStateFlow::ServerChallengeSent;
        }

        // Process (recv/parse) client final response to auth challenge
        let client_final_msg = match self
            .client_response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(self.channel_timeout)
        {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => {
                    return process_error(
                        &self.server_response_sender,
                        Some(AppError::General(format!(
                            "Unexpected SCRAM SHA256 client final message: msg={:?}",
                            &auth_msg
                        ))),
                        None,
                    )
                }
            },
            Err(err) => {
                return process_error(
                    &self.server_response_sender,
                    Some(AppError::GenWithMsgAndErr(
                        "Error receiving SCRAM SHA256 client final message".to_string(),
                        Box::new(err),
                    )),
                    None,
                )
            }
        };

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ServerStateFlow::ClientResponseRecvd;
        }

        let server_response_processor =
            match client_response_handler.handle_client_final(&client_final_msg) {
                Ok(processor) => processor,
                Err(err) => return process_error(&self.server_response_sender, None, Some(err)),
            };

        // Process (build/send) server final message
        let (auth_status, server_final_msg) = server_response_processor.server_final();

        self.server_response_sender
            .as_ref()
            .unwrap()
            .send(AuthnMessage::Payload(server_final_msg.clone()))
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error sending SCRAM SHA256 server final message: msg={}",
                        &server_final_msg
                    ),
                    Box::new(err),
                )
            })?;

        #[cfg(test)]
        {
            *self.state.lock().unwrap() = ServerStateFlow::ServerFinalSent;
        }

        match auth_status {
            AuthenticationStatus::Authenticated => {
                *self.authenticated.lock().unwrap() = true;
                Ok(AuthnMessage::Authenticated)
            }
            AuthenticationStatus::NotAuthenticated => Ok(AuthnMessage::Unauthenticated(
                "Not authenticated".to_string(),
            )),
            AuthenticationStatus::NotAuthorized => {
                Ok(AuthnMessage::Unauthenticated("Not authorized".to_string()))
            }
        }
    }

    fn exchange_messages(
        &mut self,
        inbound_msg: Option<AuthnMessage>,
    ) -> Result<Option<AuthnMessage>, AppError> {
        if inbound_msg.is_some() {
            self.client_response_sender
                .as_ref()
                .unwrap()
                .send(inbound_msg.unwrap())
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error sending SCRAM SHA256 server inbound message".to_string(),
                        Box::new(err),
                    )
                })?;
        }

        match self
            .server_response_receiver
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_millis(150))
        {
            Ok(msg) => return Ok(Some(msg)),
            Err(RecvTimeoutError::Disconnected) => return Ok(None),
            _ => {}
        }

        Ok(None)
    }

    fn is_authenticated(&self) -> bool {
        *self.authenticated.lock().unwrap()
    }
}

/// SCRAM SHA256 authentication credentials provider implementaiton for User model
impl scram::AuthenticationProvider for model::user::User {
    fn get_password_for(&self, user_name: &str) -> Option<scram::server::PasswordInfo> {
        if self.user_name.is_none() || self.password.is_none() {
            None
        } else if self.user_name.as_ref().unwrap() == user_name {
            match BASE64_URL_SAFE.decode(self.password.as_ref().unwrap().as_bytes()) {
                Err(err) => {
                    error!(
                        "Error Base64 decoding user password: user={}, err={:?}",
                        &user_name, &err
                    );
                    None
                }
                Ok(decoded_password) => Some(scram::server::PasswordInfo::new(
                    decoded_password,
                    4096,
                    user_name.bytes().collect(),
                )),
            }
        } else {
            None
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::authn::authenticator::AuthnMessage;
    use scram::AuthenticationProvider;
    use std::ops::Add;
    use std::sync::mpsc::TryRecvError;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    // mocks/dummies

    pub struct ExampleProvider {
        user1_password: Vec<u8>,
    }

    impl ExampleProvider {
        pub fn new() -> Self {
            let user1_password = hash_password("user1", "pass1", false);
            ExampleProvider { user1_password }
        }
    }

    impl AuthenticationProvider for ExampleProvider {
        fn get_password_for(&self, username: &str) -> Option<scram::server::PasswordInfo> {
            match username {
                "user1" => Some(scram::server::PasswordInfo::new(
                    self.user1_password.clone(),
                    4096,
                    "user1".bytes().collect(),
                )),
                _ => None,
            }
        }
    }

    // utils

    fn start_auth_flow(
        request_username: &str,
        request_password: &str,
    ) -> (
        Arc<Mutex<bool>>,
        Arc<Mutex<bool>>,
        Arc<Mutex<ClientStateFlow>>,
        Arc<Mutex<ServerStateFlow>>,
        mpsc::Sender<AuthnMessage>,
        mpsc::Receiver<AuthnMessage>,
        mpsc::Sender<AuthnMessage>,
        mpsc::Receiver<AuthnMessage>,
        mpsc::Sender<AuthnMessage>,
        mpsc::Sender<AuthnMessage>,
    ) {
        // Spawn client thread
        let mut auth_client = ScramSha256AuthenticatorClient::new(
            &request_username,
            &request_password,
            Duration::from_millis(1500),
        );
        let client_authenticated = auth_client.authenticated.clone();
        let tester_to_client_send = auth_client.server_response_sender.take().unwrap();
        let client_to_tester_recv = auth_client.client_response_receiver.take().unwrap();
        let client_to_tester_send = auth_client.client_response_sender.as_ref().unwrap().clone();
        let client_state_flow = auth_client.state.clone();
        thread::spawn(move || match auth_client.authenticate() {
            Ok(msg) => println!("Auth client thread result: msg={:?}", &msg),
            Err(err) => println!("Auth client thread result: err={:?}", &err),
        });

        // Spawn server thread
        let mut auth_server = ScramSha256AuthenticatorServer::new(
            ExampleProvider::new(),
            Duration::from_millis(1500),
        );
        let server_authenticated = auth_server.authenticated.clone();
        let tester_to_server_send = auth_server.client_response_sender.take().unwrap();
        let server_to_tester_recv = auth_server.server_response_receiver.take().unwrap();
        let server_to_tester_send = auth_server.server_response_sender.as_ref().unwrap().clone();
        let server_state_flow = auth_server.state.clone();
        thread::spawn(move || match auth_server.authenticate() {
            Ok(msg) => println!("Auth server thread result: msg={:?}", &msg),
            Err(err) => println!("Auth server thread result: err={:?}", &err),
        });

        (
            client_authenticated,
            server_authenticated,
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            client_to_tester_send,
            server_to_tester_send,
        )
    }

    fn is_authn_msg_error(msg: &AuthnMessage) -> bool {
        match msg {
            AuthnMessage::Payload(text) => text.starts_with("e=") || text.contains(",e="),
            AuthnMessage::Error(_) => true,
            _ => false,
        }
    }
    // tests

    #[test]
    fn scramsha256cli_new() {
        let auth_client =
            ScramSha256AuthenticatorClient::new("user1", "pass1", Duration::from_millis(150));
        assert_eq!(auth_client.username, "user1");
        assert_eq!(auth_client.password, "pass1");
        assert_eq!(
            *auth_client.state.clone().lock().unwrap(),
            ClientStateFlow::New
        )
    }

    #[test]
    fn scramsha256svr_new() {
        let auth_server =
            ScramSha256AuthenticatorServer::new(ExampleProvider::new(), Duration::from_millis(150));
        assert_eq!(
            *auth_server.state.clone().lock().unwrap(),
            ServerStateFlow::New
        );
    }

    #[test]
    fn scramsha256_authenticate_flow_when_client_first_and_invalid_username() {
        let (
            client_authenticated,
            server_authenticated,
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("userX", "pass1");

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let c2s_msg = match client_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_server_send.send(c2s_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ClientInitialRecvd
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let s2c_msg = match server_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Unauthenticated(_) = msg {
                    msg
                } else {
                    panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_client_send.send(s2c_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ClientInitialRecvd
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        match client_to_tester_recv.try_recv() {
            Ok(msg) => panic!("Unexpected client to server msg (#2): msg={:?}", &msg),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected client to server msg (#2) result: err={:?}",
                &err
            ),
            _ => {}
        }

        let _ = tester_to_client_send.send(AuthnMessage::Error("shutdown".to_string()));
        let _ = tester_to_server_send.send(AuthnMessage::Error("shutdown".to_string()));
    }

    #[test]
    fn scramsha256_authenticate_flow_when_client_first_and_invalid_password() {
        let (
            client_authenticated,
            server_authenticated,
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("user1", "passX");

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let c2s_msg = match client_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_server_send.send(c2s_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let s2c_msg = match server_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_client_send.send(s2c_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let c2s_msg = match client_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#2): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#2): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected client to server msg (#2) result: err={:?}",
                &err
            ),
        };
        tester_to_server_send.send(c2s_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let s2c_msg = match server_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(text) = &msg {
                    if text != "e=Invalid Password" {
                        panic!("Unexpected server to client msg (#2): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#2): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected server to client msg (#2) result: err={:?}",
                &err
            ),
        };
        tester_to_client_send.send(s2c_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        match client_to_tester_recv.try_recv() {
            Ok(msg) => panic!("Unexpected client to server msg (#3): msg={:?}", &msg),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected client to server msg (#3) result: err={:?}",
                &err
            ),
            _ => {}
        }

        let _ = tester_to_client_send.send(AuthnMessage::Error("shutdown".to_string()));
        let _ = tester_to_server_send.send(AuthnMessage::Error("shutdown".to_string()));
    }

    #[test]
    fn scramsha256_authenticate_flow_when_valid_credentials() {
        let (
            client_authenticated,
            server_authenticated,
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("user1", "pass1");

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let c2s_msg = match client_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_server_send.send(c2s_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let s2c_msg = match server_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_client_send.send(s2c_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let c2s_msg = match client_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#2): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#2): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected client to server msg (#2) result: err={:?}",
                &err
            ),
        };
        tester_to_server_send.send(c2s_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );
        assert!(!*client_authenticated.lock().unwrap());
        assert!(*server_authenticated.lock().unwrap());

        let s2c_msg = match server_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected server to client msg (#2): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#2): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected server to client msg (#2) result: err={:?}",
                &err
            ),
        };
        tester_to_client_send.send(s2c_msg).unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ServerFinalRecvd
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );
        assert!(*client_authenticated.lock().unwrap());
        assert!(*server_authenticated.lock().unwrap());

        match client_to_tester_recv.try_recv() {
            Ok(msg) => panic!("Unexpected client to server msg (#3): msg={:?}", &msg),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected client to server msg (#3) result: err={:?}",
                &err
            ),
            _ => {}
        }

        let _ = tester_to_client_send.send(AuthnMessage::Error("shutdown".to_string()));
        let _ = tester_to_server_send.send(AuthnMessage::Error("shutdown".to_string()));
    }

    #[test]
    fn scramsha256_authenticate_flow_when_client_first_and_wrong_msg() {
        let (
            client_authenticated,
            server_authenticated,
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("user1", "pass1");

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let _ = match client_to_tester_recv.try_recv() {
            Ok(msg) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };
        tester_to_server_send
            .send(AuthnMessage::Error("wrong".to_string()))
            .unwrap();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);
        assert!(!*client_authenticated.lock().unwrap());
        assert!(!*server_authenticated.lock().unwrap());

        let _ = match server_to_tester_recv.try_recv() {
            Ok(msg) => match msg {
                AuthnMessage::Error(_) => {}
                _ => panic!("Unexpected server to client msg (#1): msg={:?}", &msg),
            },
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
            _ => {}
        };

        let _ = tester_to_client_send.send(AuthnMessage::Error("shutdown".to_string()));
        let _ = tester_to_server_send.send(AuthnMessage::Error("shutdown".to_string()));
    }

    #[test]
    fn scramsha256_spawn_authentication_flow_when_valid_credentials() {
        let mut auth_client =
            ScramSha256AuthenticatorClient::new("user1", "pass1", Duration::from_millis(150));
        let mut auth_server =
            ScramSha256AuthenticatorServer::new(ExampleProvider::new(), Duration::from_millis(150));

        let auth_client_handle = auth_client.spawn_authentication();
        let auth_server_handle = auth_server.spawn_authentication();

        assert!(auth_client_handle.is_some());
        assert!(auth_server_handle.is_some());

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*auth_server.state.lock().unwrap(), ServerStateFlow::New);
        assert!(!auth_client.is_authenticated());
        assert!(!auth_server.is_authenticated());

        let c2s_msg = match auth_client.exchange_messages(None) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing client to server msg (#1)"),
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };

        let s2c_msg = match auth_server.exchange_messages(Some(c2s_msg)) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing server to client msg (#1)"),
            Err(err) => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
        };

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *auth_server.state.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!auth_client.is_authenticated());
        assert!(!auth_server.is_authenticated());

        let c2s_msg = match auth_client.exchange_messages(Some(s2c_msg)) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#2): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#2): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing client to server msg (#2)"),
            Err(err) => panic!(
                "Unexpected client to server msg (#2) result: err={:?}",
                &err
            ),
        };

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *auth_server.state.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!auth_client.is_authenticated());
        assert!(!auth_server.is_authenticated());

        let s2c_msg = match auth_server.exchange_messages(Some(c2s_msg)) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected server to client msg (#2): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#2): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing server to client msg (#2)"),
            Err(err) => panic!(
                "Unexpected server to client msg (#2) result: err={:?}",
                &err
            ),
        };

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *auth_server.state.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );
        assert!(!auth_client.is_authenticated());
        assert!(auth_server.is_authenticated());

        match auth_client.exchange_messages(Some(s2c_msg)) {
            Ok(Some(msg)) => panic!("Unexpected client to server msg (#3): msg={:?}", &msg),
            Ok(None) => {}
            Err(err) => panic!(
                "Unexpected client to server msg (#3) result: err={:?}",
                &err
            ),
        }

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ServerFinalRecvd
        );
        assert_eq!(
            *auth_server.state.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );
        assert!(auth_client.is_authenticated());
        assert!(auth_server.is_authenticated());

        let _ = auth_client.exchange_messages(Some(AuthnMessage::Error("shutdown".to_string())));
        let _ = auth_server.exchange_messages(Some(AuthnMessage::Error("shutdown".to_string())));
    }

    #[test]
    fn scramsha256_spawn_authentication_flow_when_valid_credentials_but_exceed_server_channel_timeout(
    ) {
        let mut auth_client =
            ScramSha256AuthenticatorClient::new("user1", "pass1", Duration::from_millis(150));
        let mut auth_server =
            ScramSha256AuthenticatorServer::new(ExampleProvider::new(), Duration::from_millis(150));

        let auth_client_handle = auth_client.spawn_authentication();
        let auth_server_handle = auth_server.spawn_authentication();

        assert!(auth_client_handle.is_some());
        assert!(auth_server_handle.is_some());

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*auth_server.state.lock().unwrap(), ServerStateFlow::New);
        assert!(!auth_client.is_authenticated());
        assert!(!auth_server.is_authenticated());

        let c2s_msg = match auth_client.exchange_messages(None) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing client to server msg (#1)"),
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };

        thread::sleep(auth_server.channel_timeout.add(Duration::from_millis(50)));

        match auth_server.exchange_messages(Some(c2s_msg)) {
            Ok(Some(msg)) => panic!(
                "Unexpected server to client msg (#1) response, should've timed out: msg={:?}",
                &msg
            ),
            Ok(None) => panic!(
                "Unexpected server to client msg (#1) response, should've timed out: msg=None"
            ),
            _ => {}
        }
    }

    #[test]
    fn scramsha256_spawn_authentication_flow_when_valid_credentials_but_exceed_client_channel_timeout(
    ) {
        let mut auth_client =
            ScramSha256AuthenticatorClient::new("user1", "pass1", Duration::from_millis(150));
        let mut auth_server =
            ScramSha256AuthenticatorServer::new(ExampleProvider::new(), Duration::from_millis(150));

        let auth_client_handle = auth_client.spawn_authentication();
        let auth_server_handle = auth_server.spawn_authentication();

        assert!(auth_client_handle.is_some());
        assert!(auth_server_handle.is_some());

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*auth_server.state.lock().unwrap(), ServerStateFlow::New);
        assert!(!auth_client.is_authenticated());
        assert!(!auth_server.is_authenticated());

        let c2s_msg = match auth_client.exchange_messages(None) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected client to server msg (#1): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing client to server msg (#1)"),
            Err(err) => panic!(
                "Unexpected client to server msg (#1) result: err={:?}",
                &err
            ),
        };

        let s2c_msg = match auth_server.exchange_messages(Some(c2s_msg)) {
            Ok(Some(msg)) => {
                if let AuthnMessage::Payload(_) = msg {
                    if is_authn_msg_error(&msg) {
                        panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                    }
                    msg
                } else {
                    panic!("Unexpected server to client msg (#1): msg={:?}", &msg);
                }
            }
            Ok(None) => panic!("Missing server to client msg (#1)"),
            Err(err) => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
        };

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            *auth_client.state.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *auth_server.state.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );
        assert!(!auth_client.is_authenticated());
        assert!(!auth_server.is_authenticated());

        thread::sleep(auth_client.channel_timeout.add(Duration::from_millis(50)));

        match auth_client.exchange_messages(Some(s2c_msg)) {
            Ok(Some(msg)) => panic!(
                "Unexpected client to server msg (#2) response, should've timed out: msg={:?}",
                &msg
            ),
            Ok(None) => panic!(
                "Unexpected client to server msg (#2) response, should've timed out: msg=None"
            ),
            _ => {}
        };
    }

    #[test]
    fn user_authentication_provider_when_invalid_username() {
        let user = model::user::User {
            user_id: 100,
            user_name: Some("userX".to_string()),
            password: Some("30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=".to_string()),
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
        };

        match user.get_password_for("user1") {
            Some(_pwd_info) => panic!("Unexpected successful result"),
            None => {}
        }
    }

    #[test]
    fn user_authentication_provider_when_invalid_password() {
        let user = model::user::User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("WRONG".to_string()),
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
        };

        match user.get_password_for("user1") {
            Some(_pwd_info) => panic!("Unexpected successful result"),
            None => {}
        }
    }

    #[test]
    fn user_authentication_provider_when_valid() {
        let user = model::user::User {
            user_id: 100,
            user_name: Some("user1".to_string()),
            password: Some("30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=".to_string()),
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
        };

        match user.get_password_for("user1") {
            Some(_pwd_info) => {}
            None => panic!("Unexpected unsuccessful result"),
        }
    }
}
