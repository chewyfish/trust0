use crate::error::AppError;
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::thread::JoinHandle;

/// Authentication implementation types
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AuthnType {
    Insecure,
    ScramSha256,
}

impl fmt::Display for AuthnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AuthnType::Insecure => "insecure",
                AuthnType::ScramSha256 => "scram-sha256",
            }
        )
    }
}

impl From<String> for AuthnType {
    fn from(type_name: String) -> Self {
        Self::from(type_name.as_str())
    }
}

impl From<&str> for AuthnType {
    fn from(type_name: &str) -> Self {
        match type_name {
            "none" => AuthnType::Insecure,
            "insecure" => AuthnType::Insecure,
            "scram-sha256" => AuthnType::ScramSha256,
            _ => panic!("Invalid AuthnType: val={}", type_name),
        }
    }
}

/// Authentication message in a "challenge-response" flow
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum AuthnMessage {
    Payload(String),
    Error(String),
    Authenticated,
    Unauthenticated(String),
}

impl AuthnMessage {
    /// Parse JSON string message value
    pub fn parse_json_str(message_str: &str) -> Result<AuthnMessage, AppError> {
        serde_json::from_str(message_str).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to parse AuthnMessage JSON: val={}", message_str),
                Box::new(err),
            )
        })
    }

    /// Convert message to JSON string value
    pub fn to_json_str(&self) -> Result<String, AppError> {
        serde_json::to_string(self).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Failed to create AuthnMessage JSON".to_string(),
                Box::new(err),
            )
        })
    }
}

/// Authentication flow processing for the client party
pub trait AuthenticatorClient {
    /// Spawn authentication flow thread (non-blocking)
    fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>>;

    /// Perform authentication flow (blocking)
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError>;

    /// Exchange authentication flow messages
    /// Optionally send inbound message and optionally receive outbound message
    fn exchange_messages(
        &mut self,
        inbound_msg: Option<AuthnMessage>,
    ) -> Result<Option<AuthnMessage>, AppError>;

    /// Returns authentication status
    fn is_authenticated(&self) -> bool;
}

/// Authentication flow processing for the server party
pub trait AuthenticatorServer {
    /// Spawn authentication flow thread (non-blocking)
    fn spawn_authentication(&mut self) -> Option<JoinHandle<Result<AuthnMessage, AppError>>>;

    /// Perform authentication flow (blocking)
    fn authenticate(&mut self) -> Result<AuthnMessage, AppError>;

    /// Exchange authentication flow messages
    /// Optionally send inbound message and optionally receive outbound message
    fn exchange_messages(
        &mut self,
        inbound_msg: Option<AuthnMessage>,
    ) -> Result<Option<AuthnMessage>, AppError>;

    /// Returns authentication status
    fn is_authenticated(&self) -> bool;
}

/// Unit tests
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn authtype_display() {
        assert_eq!(format!("{}", AuthnType::Insecure), "insecure");
        assert_eq!(format!("{}", AuthnType::ScramSha256), "scram-sha256");
    }

    #[test]
    fn authtype_from_str_when_none_val() {
        assert_eq!(
            <String as Into<AuthnType>>::into("none".to_string()),
            AuthnType::Insecure
        );
        assert_eq!(<&str as Into<AuthnType>>::into("none"), AuthnType::Insecure);
    }

    #[test]
    fn authtype_from_str_when_insecure_val() {
        assert_eq!(
            <String as Into<AuthnType>>::into("insecure".to_string()),
            AuthnType::Insecure
        );
        assert_eq!(
            <&str as Into<AuthnType>>::into("insecure"),
            AuthnType::Insecure
        );
    }

    #[test]
    fn authtype_from_str_when_scramsha256_val() {
        assert_eq!(
            <String as Into<AuthnType>>::into("scram-sha256".to_string()),
            AuthnType::ScramSha256
        );
        assert_eq!(
            <&str as Into<AuthnType>>::into("scram-sha256"),
            AuthnType::ScramSha256
        );
    }

    #[test]
    #[should_panic]
    fn authtype_from_str_when_invalid_val() {
        let _authn_type: AuthnType = "invalid".into();
    }

    #[test]
    fn authnmsg_parse_json_str_when_valid_payload_msg() {
        let json_str = r#"{"payload":"data1"}"#;
        match AuthnMessage::parse_json_str(json_str) {
            Ok(msg) => assert_eq!(msg, AuthnMessage::Payload("data1".to_string())),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_invalid_payload_msg() {
        let json_str = r#"{"payload":"data1""#;
        if let Ok(msg) = AuthnMessage::parse_json_str(json_str) {
            panic!("Unexpected successful result: msg={:?}", &msg);
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_valid_error_msg() {
        let json_str = r#"{"error":"msg1"}"#;
        match AuthnMessage::parse_json_str(json_str) {
            Ok(msg) => assert_eq!(msg, AuthnMessage::Error("msg1".to_string())),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_invalid_error_msg() {
        let json_str = r#"{"error":"msg1""#;
        if let Ok(msg) = AuthnMessage::parse_json_str(json_str) {
            panic!("Unexpected successful result: msg={:?}", &msg);
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_valid_authenticated_msg() {
        let json_str = r#""authenticated""#;
        if let Err(err) = AuthnMessage::parse_json_str(json_str) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_invalid_authenticated_msg() {
        let json_str = r#""authenticated": true""#;
        if let Ok(msg) = AuthnMessage::parse_json_str(json_str) {
            panic!("Unexpected successful result: msg={:?}", &msg);
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_valid_unauthenticated_msg() {
        let json_str = r#"{"unauthenticated":"msg1"}"#;
        match AuthnMessage::parse_json_str(json_str) {
            Ok(msg) => assert_eq!(msg, AuthnMessage::Unauthenticated("msg1".to_string())),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn authnmsg_parse_json_str_when_invalid_unauthenticated_msg() {
        let json_str = r#"{"unauthenticated":"msg1""#;
        if let Ok(msg) = AuthnMessage::parse_json_str(json_str) {
            panic!("Unexpected successful result: msg={:?}", &msg);
        }
    }

    #[test]
    fn authnmsg_to_json_str_when_payload_msg() {
        let expected_json_str = r#"{"payload":"data1"}"#;
        let authn_msg = AuthnMessage::Payload("data1".to_string());
        match authn_msg.to_json_str() {
            Ok(json_str) => assert_eq!(json_str, expected_json_str),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn authnmsg_to_json_str_when_error_msg() {
        let expected_json_str = r#"{"error":"msg1"}"#;
        let authn_msg = AuthnMessage::Error("msg1".to_string());
        match authn_msg.to_json_str() {
            Ok(json_str) => assert_eq!(json_str, expected_json_str),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn authnmsg_to_json_str_when_authenticated_msg() {
        let expected_json_str = r#""authenticated""#;
        let authn_msg = AuthnMessage::Authenticated;
        match authn_msg.to_json_str() {
            Ok(json_str) => assert_eq!(json_str, expected_json_str),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn authnmsg_to_json_str_when_unauthenticated_msg() {
        let expected_json_str = r#"{"unauthenticated":"msg1"}"#;
        let authn_msg = AuthnMessage::Unauthenticated("msg1".to_string());
        match authn_msg.to_json_str() {
            Ok(json_str) => assert_eq!(json_str, expected_json_str),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

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
