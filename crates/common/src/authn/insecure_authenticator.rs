use crate::authn::authenticator::{AuthenticatorClient, AuthenticatorServer, AuthnMessage};
use crate::error::AppError;
use std::thread::JoinHandle;

/// A client authenticator that always indicates successful authentication
pub struct InsecureAuthenticatorClient;

impl InsecureAuthenticatorClient {
    /// InsecureAuthenticatorClient constructor
    ///
    /// # Returns
    ///
    /// A newly constructed [`InsecureAuthenticatorClient`] object.
    ///
    pub fn new() -> Self {
        Self
    }
}

impl AuthenticatorClient for InsecureAuthenticatorClient {
    fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>> {
        None
    }

    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        Ok(AuthnMessage::Authenticated)
    }

    fn exchange_messages(
        &mut self,
        _inbound_msg: Option<AuthnMessage>,
    ) -> Result<Option<AuthnMessage>, AppError> {
        Ok(Some(AuthnMessage::Authenticated))
    }

    fn is_authenticated(&self) -> bool {
        true
    }
}

impl Default for InsecureAuthenticatorClient {
    fn default() -> Self {
        Self::new()
    }
}

/// A server authenticator that always indicates successful authentication
pub struct InsecureAuthenticatorServer;

impl InsecureAuthenticatorServer {
    /// InsecureAuthenticatorServer constructor
    ///
    /// # Returns
    ///
    /// A newly constructed [`InsecureAuthenticatorServer`] object.
    ///
    pub fn new() -> Self {
        Self
    }
}

impl AuthenticatorServer for InsecureAuthenticatorServer {
    fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>> {
        None
    }

    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        Ok(AuthnMessage::Authenticated)
    }

    fn exchange_messages(
        &mut self,
        _inbound_msg: Option<AuthnMessage>,
    ) -> Result<Option<AuthnMessage>, AppError> {
        Ok(Some(AuthnMessage::Authenticated))
    }

    fn is_authenticated(&self) -> bool {
        true
    }
}

impl Default for InsecureAuthenticatorServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Unit tests
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn insecurecli_new() {
        let _ = InsecureAuthenticatorClient::new();
    }

    #[test]
    fn insecurecli_spawn_authentication() {
        let mut auth_client = InsecureAuthenticatorClient;
        let message = auth_client.spawn_authentication();
        assert!(message.is_none());
    }

    #[test]
    fn insecurecli_authenticate() {
        let mut auth_client = InsecureAuthenticatorClient;
        let message = auth_client.authenticate();
        assert!(message.is_ok());
        let message = message.unwrap();
        assert_eq!(message, AuthnMessage::Authenticated);
    }

    #[test]
    fn insecurecli_exchange_messages() {
        let mut auth_client = InsecureAuthenticatorClient;
        let message =
            auth_client.exchange_messages(Some(AuthnMessage::Payload("data".to_string())));
        assert!(message.is_ok());
        let message = message.unwrap();
        assert!(message.is_some());
        assert_eq!(message.unwrap(), AuthnMessage::Authenticated);
    }

    #[test]
    fn insecurecli_is_authenticated() {
        let auth_client = InsecureAuthenticatorClient;
        assert!(auth_client.is_authenticated());
    }

    #[test]
    fn insecuresvr_new() {
        let _ = InsecureAuthenticatorServer::new();
    }

    #[test]
    fn insecuresvr_spawn_authentication() {
        let mut auth_server = InsecureAuthenticatorServer;
        let message = auth_server.spawn_authentication();
        assert!(message.is_none());
    }

    #[test]
    fn insecuresvr_authenticate() {
        let mut auth_server = InsecureAuthenticatorServer;
        let message = auth_server.authenticate();
        assert!(message.is_ok());
        let message = message.unwrap();
        assert_eq!(message, AuthnMessage::Authenticated);
    }

    #[test]
    fn insecuresvr_exchange_messages() {
        let mut auth_server = InsecureAuthenticatorServer;
        let message =
            auth_server.exchange_messages(Some(AuthnMessage::Payload("data".to_string())));
        assert!(message.is_ok());
        let message = message.unwrap();
        assert!(message.is_some());
        assert_eq!(message.unwrap(), AuthnMessage::Authenticated);
    }

    #[test]
    fn insecuresvr_is_authenticated() {
        let auth_client = InsecureAuthenticatorClient;
        assert!(auth_client.is_authenticated());
    }
}
