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
    /// Message constructor
    ///
    /// # Arguments
    ///
    /// * `code` - Well-known code status for event
    /// * `message` - (optional) Top-level response message
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
        let event_type = serde_json::to_value(self.event_type.clone()).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting EventType to Value".to_string(),
                Box::new(err),
            )
        })?;
        Ok(MessageFrame::new(
            ControlChannel::Signaling,
            self.code,
            &self.message,
            &Some(event_type),
            &self.data,
        ))
    }
}

/// Active service proxy connections for connected mTLS device user
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct ProxyConnection {
    /// Service key name value
    pub service_name: String,
    /// List of current connection bind address pairs
    pub binds: Vec<Vec<String>>,
}

impl ProxyConnection {
    /// ProxyConnection constructor
    ///
    /// # Arguments
    ///
    /// * `service_name` - Service key name value
    /// * `binds` - List of current connection bind address pairs
    ///
    /// # Returns
    ///
    /// A newly constructed [`ProxyConnection`] object.
    ///
    pub fn new(service_name: &str, binds: Vec<Vec<String>>) -> Self {
        Self {
            service_name: service_name.to_string(),
            binds,
        }
    }

    /// Construct proxy connection(s) from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a JSON array of [`ProxyConnection`] or a single [`ProxyConnection`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of corresponding [`ProxyConnection`] objects.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Vec<ProxyConnection>, AppError> {
        if let Value::Array(values) = &value {
            Ok(values
                .iter()
                .map(|v| {
                    serde_json::from_value(v.clone()).map_err(|err| {
                        AppError::GenWithMsgAndErr(
                            "Error converting serde Value to Connection".to_string(),
                            Box::new(err),
                        )
                    })
                })
                .collect::<Result<Vec<ProxyConnection>, AppError>>()?)
        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(
                |err| {
                    AppError::GenWithMsgAndErr(
                        "Error converting serde Value to Connection".to_string(),
                        Box::new(err),
                    )
                },
            )?])
        }
    }
}

unsafe impl Send for ProxyConnection {}

impl TryInto<Value> for ProxyConnection {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &ProxyConnection {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        serde_json::to_value(self).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting Connection to serde Value".to_string(),
                Box::new(err),
            )
        })
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::pdu;
    use serde_json::json;

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

    #[test]
    fn proxyconn_from_serde_value_when_invalid() {
        let conn_json = json!({"service_name_INVALID": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match ProxyConnection::from_serde_value(&conn_json) {
            Ok(proxies) => panic!("Unexpected successful result: conns={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn proxyconn_from_serde_value_when_valid_connections_list() {
        let proxy_conns_json =
            json!([{"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]}]);

        match ProxyConnection::from_serde_value(&proxy_conns_json) {
            Ok(proxy_conns) => {
                assert_eq!(proxy_conns.len(), 1);
                let proxy_conn = ProxyConnection::new(
                    "svc1",
                    vec![
                        vec!["b0".to_string(), "b1".to_string()],
                        vec!["b2".to_string(), "b3".to_string()],
                    ],
                );
                assert_eq!(proxy_conns, vec![proxy_conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxyconn_from_serde_value_when_valid_connections_object() {
        let proxy_conns_json = json!({"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match ProxyConnection::from_serde_value(&proxy_conns_json) {
            Ok(proxy_conns) => {
                assert_eq!(proxy_conns.len(), 1);
                let proxy_conn = ProxyConnection::new(
                    "svc1",
                    vec![
                        vec!["b0".to_string(), "b1".to_string()],
                        vec!["b2".to_string(), "b3".to_string()],
                    ],
                );
                assert_eq!(proxy_conns, vec![proxy_conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxyconn_try_into_value() {
        let proxy_conn = ProxyConnection::new(
            "svc1",
            vec![
                vec!["b0".to_string(), "b1".to_string()],
                vec!["b2".to_string(), "b3".to_string()],
            ],
        );

        let result: Result<Value, AppError> = proxy_conn.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }
}
