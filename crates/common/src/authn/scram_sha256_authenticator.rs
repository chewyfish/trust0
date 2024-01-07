use crate::authn::authenticator::{AuthenticatorClient, AuthenticatorServer, AuthnMessage};
use crate::error::AppError;
use scram::AuthenticationStatus;
use std::sync::mpsc;
#[cfg(test)]
use std::sync::{Arc, Mutex};

/// Handle processing error
fn process_error(
    response_sender: Option<&mpsc::Sender<AuthnMessage>>,
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
    client_response_sender: mpsc::Sender<AuthnMessage>,
    server_response_receiver: mpsc::Receiver<AuthnMessage>,
    username: String,
    password: String,
    #[cfg(test)]
    state: Arc<Mutex<ClientStateFlow>>,
}

impl ScramSha256AuthenticatorClient {
    /// ScramSha256AuthenticatorClient constructor
    pub fn new(
        client_response_sender: mpsc::Sender<AuthnMessage>,
        server_response_receiver: mpsc::Receiver<AuthnMessage>,
        username: &str,
        password: &str,
    ) -> Self {
        Self {
            client_response_sender,
            server_response_receiver,
            username: username.to_string(),
            password: password.to_string(),
            #[cfg(test)]
            state: Arc::new(Mutex::new(ClientStateFlow::New)),
        }
    }
}

impl AuthenticatorClient for ScramSha256AuthenticatorClient {
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        // Process (build/send) client first auth message
        let client_request_processor =
            scram::ScramClient::new(&self.username, &self.password, None);
        let (server_response_handler, client_first_msg) = client_request_processor.client_first();

        self.client_response_sender
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
        let server_first_msg = match self.server_response_receiver.recv() {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => return Ok(auth_msg),
            },
            Err(err) => {
                return process_error(
                    Some(&self.client_response_sender),
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

        let client_response_processor = match server_response_handler
            .handle_server_first(&server_first_msg)
        {
            Ok(processor) => processor,
            Err(err) => return process_error(Some(&self.client_response_sender), None, Some(err)),
        };

        // Process (build/send) client final auth message
        let (server_response_handler, client_final_msg) = client_response_processor.client_final();

        self.client_response_sender
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
        let server_final_msg = match self.server_response_receiver.recv() {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => return Ok(auth_msg),
            },
            Err(err) => {
                return process_error(
                    None,
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
            Ok(()) => Ok(AuthnMessage::Authenticated),
            Err(err) => process_error(None, None, Some(err)),
        }
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
    server_response_sender: mpsc::Sender<AuthnMessage>,
    client_response_receiver: mpsc::Receiver<AuthnMessage>,
    auth_provider: Option<Box<P>>,
    #[cfg(test)]
    state: Arc<Mutex<ServerStateFlow>>,
}

impl<P> ScramSha256AuthenticatorServer<P>
where
    P: scram::AuthenticationProvider + Sized,
{
    /// ScramSha256AuthenticatorServer constructor
    pub fn new(
        server_response_sender: mpsc::Sender<AuthnMessage>,
        client_response_receiver: mpsc::Receiver<AuthnMessage>,
        auth_provider: P,
    ) -> Self {
        Self {
            server_response_sender,
            client_response_receiver,
            auth_provider: Some(Box::new(auth_provider)),
            #[cfg(test)]
            state: Arc::new(Mutex::new(ServerStateFlow::New)),
        }
    }
}

impl<P> AuthenticatorServer for ScramSha256AuthenticatorServer<P>
where
    P: scram::AuthenticationProvider + Sized,
{
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        // Process (recv/parse) client first auth message
        let client_first_msg = match self.client_response_receiver.recv() {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => return Ok(auth_msg),
            },
            Err(err) => {
                return process_error(
                    Some(&self.server_response_sender),
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
        let server_response_processor = match client_response_handler
            .handle_client_first(&client_first_msg)
        {
            Ok(processor) => processor,
            Err(err) => return process_error(Some(&self.server_response_sender), None, Some(err)),
        };

        // Process (build/send) server first (challenge) message
        let (client_response_handler, server_first_msg) = server_response_processor.server_first();

        self.server_response_sender
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
        let client_final_msg = match self.client_response_receiver.recv() {
            Ok(auth_msg) => match auth_msg {
                AuthnMessage::Payload(msg) => msg,
                _ => return Ok(auth_msg),
            },
            Err(err) => {
                return process_error(
                    Some(&self.server_response_sender),
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

        let server_response_processor = match client_response_handler
            .handle_client_final(&client_final_msg)
        {
            Ok(processor) => processor,
            Err(err) => return process_error(Some(&self.server_response_sender), None, Some(err)),
        };

        // Process (build/send) server final message
        let (auth_status, server_final_msg) = server_response_processor.server_final();

        self.server_response_sender
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
            AuthenticationStatus::Authenticated => Ok(AuthnMessage::Authenticated),
            AuthenticationStatus::NotAuthenticated => Ok(AuthnMessage::Unauthenticated(
                "Not authenticated".to_string(),
            )),
            AuthenticationStatus::NotAuthorized => {
                Ok(AuthnMessage::Unauthenticated("Not authorized".to_string()))
            }
        }
    }
}

/// Unit tests
#[cfg(test)]
mod test {
    use super::*;
    use crate::authn::authenticator::AuthnMessage;
    use ring::digest::SHA256_OUTPUT_LEN;
    use std::num::NonZeroU32;
    use std::sync::mpsc::TryRecvError;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    // mocks/dummies

    struct ExampleProvider {
        uname1_password: [u8; SHA256_OUTPUT_LEN],
    }

    impl ExampleProvider {
        pub fn new() -> Self {
            let pwd_iterations = NonZeroU32::new(4096).unwrap();
            let uname1_password = scram::hash_password("pass1", pwd_iterations, b"salt");
            ExampleProvider { uname1_password }
        }
    }

    impl scram::AuthenticationProvider for ExampleProvider {
        fn get_password_for(&self, username: &str) -> Option<scram::server::PasswordInfo> {
            match username {
                "uname1" => Some(scram::server::PasswordInfo::new(
                    self.uname1_password.to_vec(),
                    4096,
                    "salt".bytes().collect(),
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
        let (tester_to_client_send, tester_to_client_recv) = mpsc::channel();
        let (client_to_tester_send, client_to_tester_recv) = mpsc::channel();
        let client_to_tester_send_copy = client_to_tester_send.clone();
        let mut auth_client = ScramSha256AuthenticatorClient::new(
            client_to_tester_send_copy,
            tester_to_client_recv,
            &request_username,
            &request_password,
        );
        let client_state_flow = auth_client.state.clone();
        thread::spawn(move || match auth_client.authenticate() {
            Ok(msg) => println!("Auth client thread result: msg={:?}", &msg),
            Err(err) => println!("Auth client thread result: err={:?}", &err),
        });

        // Spawn server thread
        let (tester_to_server_send, tester_to_server_recv) = mpsc::channel();
        let (server_to_tester_send, server_to_tester_recv) = mpsc::channel();
        let server_to_tester_send_copy = server_to_tester_send.clone();
        let mut auth_server = ScramSha256AuthenticatorServer::new(
            server_to_tester_send_copy,
            tester_to_server_recv,
            ExampleProvider::new(),
        );
        let server_state_flow = auth_server.state.clone();
        thread::spawn(move || match auth_server.authenticate() {
            Ok(msg) => println!("Auth server thread result: msg={:?}", &msg),
            Err(err) => println!("Auth server thread result: err={:?}", &err),
        });

        (
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
        let auth_client = ScramSha256AuthenticatorClient::new(
            mpsc::channel().0,
            mpsc::channel().1,
            "uname1",
            "pass1",
        );
        assert_eq!(auth_client.username, "uname1");
        assert_eq!(auth_client.password, "pass1");
        assert_eq!(
            *auth_client.state.clone().lock().unwrap(),
            ClientStateFlow::New
        )
    }

    #[test]
    fn scramsha256svr_new() {
        let auth_server = ScramSha256AuthenticatorServer::new(
            mpsc::channel().0,
            mpsc::channel().1,
            ExampleProvider::new(),
        );
        assert_eq!(
            *auth_server.state.clone().lock().unwrap(),
            ServerStateFlow::New
        );
    }

    #[test]
    fn scramsha256_authenticate_flow_when_client_first_and_invalid_username() {
        let (
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("unameX", "pass1");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ClientInitialRecvd
        );

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ClientInitialRecvd
        );

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
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("uname1", "passX");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );

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

        thread::sleep(Duration::from_millis(20));
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
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("uname1", "pass1");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerChallengeSent
        );

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientResponseSent
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ServerFinalRecvd
        );
        assert_eq!(
            *server_state_flow.lock().unwrap(),
            ServerStateFlow::ServerFinalSent
        );

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
            client_state_flow,
            server_state_flow,
            tester_to_client_send,
            client_to_tester_recv,
            tester_to_server_send,
            server_to_tester_recv,
            _client_to_tester_send,
            _server_to_tester_send,
        ) = start_auth_flow("uname1", "pass1");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);

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

        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            *client_state_flow.lock().unwrap(),
            ClientStateFlow::ClientInitialSent
        );
        assert_eq!(*server_state_flow.lock().unwrap(), ServerStateFlow::New);

        let _ = match server_to_tester_recv.try_recv() {
            Ok(msg) => panic!("Unexpected server to client msg (#1): msg={:?}", &msg),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected server to client msg (#1) result: err={:?}",
                &err
            ),
            _ => {}
        };

        let _ = tester_to_client_send.send(AuthnMessage::Error("shutdown".to_string()));
        let _ = tester_to_server_send.send(AuthnMessage::Error("shutdown".to_string()));
    }
}
