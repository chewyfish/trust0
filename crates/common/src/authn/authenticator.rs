use crate::error::AppError;

/// Represents authentication message in a "challenge-response" flow
#[derive(Debug, Clone, PartialEq)]
pub enum AuthnMessage {
    Payload(String),
    Error(String),
    Authenticated,
    Unauthenticated(String),
}

/// Authentication flow processing for the client party
pub trait AuthenticatorClient {
    /// Perform complete authentication flow as is appropriate for the client
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError>;
}

/// Authentication flow processing for the server party
pub trait AuthenticatorServer {
    /// Perform complete authentication flow as is appropriate for the server
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError>;
}

/// Unit tests
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn authnstatus_construction() {
        let status = AuthnMessage::Payload("text".to_string());
        let AuthnMessage::Payload(_) = status else {
            panic!("Unexpected non-payload message: msg={:?}", &status);
        };

        let status = AuthnMessage::Error("error".to_string());
        let AuthnMessage::Error(_) = status else {
            panic!("Unexpected non-error message: msg={:?}", &status);
        };

        let status = AuthnMessage::Authenticated;
        let AuthnMessage::Authenticated = status else {
            panic!("Unexpected non-auth message: msg={:?}", &status);
        };

        let status = AuthnMessage::Unauthenticated("not allowed".to_string());
        let AuthnMessage::Unauthenticated(_) = status else {
            panic!("Unexpected non-unauth status: msg={:?}", &status);
        };
    }
}
