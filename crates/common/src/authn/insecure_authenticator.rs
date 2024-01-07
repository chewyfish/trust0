use crate::authn::authenticator::{AuthenticatorClient, AuthenticatorServer, AuthnMessage};
use crate::error::AppError;

/// A client authenticator that always indicates successful authentication
pub struct InsecureAuthenticatorClient;

impl InsecureAuthenticatorClient {
    /// InsecureAuthenticatorClient constructor
    pub fn new() -> Self {
        Self
    }
}

impl AuthenticatorClient for InsecureAuthenticatorClient {
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        Ok(AuthnMessage::Authenticated)
    }
}

/// A server authenticator that always indicates successful authentication
pub struct InsecureAuthenticatorServer;

impl InsecureAuthenticatorServer {
    /// InsecureAuthenticatorServer constructor
    pub fn new() -> Self {
        Self
    }
}

impl AuthenticatorServer for InsecureAuthenticatorServer {
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError> {
        Ok(AuthnMessage::Authenticated)
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
    fn insecurecli_authenticate() {
        let mut auth_client = InsecureAuthenticatorClient;
        let message = auth_client.authenticate();
        assert!(message.is_ok());
        let message = message.unwrap();
        assert_eq!(message, AuthnMessage::Authenticated);
    }

    #[test]
    fn insecuresvr_new() {
        let _ = InsecureAuthenticatorServer::new();
    }

    #[test]
    fn insecuresvr_authenticate() {
        let mut auth_server = InsecureAuthenticatorServer;
        let message = auth_server.authenticate();
        assert!(message.is_ok());
        let message = message.unwrap();
        assert_eq!(message, AuthnMessage::Authenticated);
    }
}
