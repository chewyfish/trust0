use std::borrow::Borrow;

use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::pdu::{ControlChannel, MessageFrame};
use crate::error::AppError;

/// Signaling message event type
#[derive(Serialize, Deserialize, Clone, Default, Debug, Eq, Hash, PartialEq)]
pub enum EventType {
    #[default]
    General,
    CertificateReissue,
    ProxyConnections,
}

/// Signaling control plane channel message event
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct SignalEvent {
    /// Indicates well-known code status for event
    pub code: u16,
    /// If necessary, contains a top-level message
    pub message: Option<String>,
    /// Type of message event
    pub event_type: EventType,
    /// Event data (different depending on message event type)
    pub data: Option<Value>,
}

impl SignalEvent {
    /// SignalEvent constructor
    ///
    /// # Arguments
    ///
    /// * `code` - Well-known code status for event
    /// * `message` - (optional) Top-level pdu message
    /// * `event_type` - Corresponding message event type
    /// * `data` - (optional) Event data object (generic as is different per event type)
    ///
    /// # Returns
    ///
    /// A newly constructed [`SignalEvent`] object.
    ///
    pub fn new(
        code: u16,
        message: &Option<String>,
        event_type: &EventType,
        data: &Option<Value>,
    ) -> Self {
        Self {
            code,
            message: message.clone(),
            event_type: event_type.clone(),
            data: data.clone(),
        }
    }
}

impl TryInto<MessageFrame> for SignalEvent {
    type Error = AppError;

    fn try_into(self) -> Result<MessageFrame, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<MessageFrame> for &SignalEvent {
    type Error = AppError;

    fn try_into(self) -> Result<MessageFrame, Self::Error> {
        let event_type = serde_json::to_value(self.event_type.clone()).unwrap();
        Ok(MessageFrame::new(
            ControlChannel::Signaling,
            self.code,
            &self.message,
            &Some(event_type),
            &self.data,
        ))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::pdu;

    #[test]
    fn signalevt_new() {
        let signal_event = SignalEvent::new(
            pdu::CODE_OK,
            &Some("msg1".to_string()),
            &EventType::ProxyConnections,
            &Some(Value::String("data1".to_string())),
        );

        assert_eq!(signal_event.code, pdu::CODE_OK);
        assert!(signal_event.message.is_some());
        assert_eq!(signal_event.message.as_ref().unwrap(), "msg1");
        assert_eq!(signal_event.event_type, EventType::ProxyConnections);
        assert!(signal_event.data.is_some());
        assert_eq!(
            signal_event.data.as_ref().unwrap().to_string(),
            "\"data1\"".to_string()
        );
    }

    #[test]
    fn signalevt_try_into_message_frame() {
        let signal_event = SignalEvent::new(
            pdu::CODE_OK,
            &Some("msg1".to_string()),
            &EventType::ProxyConnections,
            &Some(Value::String("data1".to_string())),
        );

        let result: Result<MessageFrame, AppError> = signal_event.try_into();
        match result {
            Ok(msg_frame) => {
                assert_eq!(
                    msg_frame,
                    MessageFrame {
                        channel: pdu::ControlChannel::Signaling,
                        code: pdu::CODE_OK,
                        message: Some("msg1".to_string()),
                        context: Some(serde_json::to_value(EventType::ProxyConnections).unwrap()),
                        data: Some(Value::String("data1".to_string())),
                    }
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }
}
