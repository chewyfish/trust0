use std::borrow::Borrow;
use std::net::TcpStream;

use crate::control::pdu;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::pdu::{ControlChannel, MessageFrame};
use crate::error::AppError;

pub type ConnectionAddrs = (String, String);

/// TLS session message type
#[derive(Serialize, Deserialize, Clone, Default, Debug, Eq, Hash, PartialEq)]
pub enum DataType {
    #[default]
    Trust0Connection,
}

/// TLS session message
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct SessionMessage {
    /// Type of data message
    pub data_type: DataType,
    /// Message data (different depending on data type)
    pub data: Option<Value>,
}

impl SessionMessage {
    /// SessionMessage constructor
    ///
    /// # Arguments
    ///
    /// * `data_type` - Corresponding message data type
    /// * `data` - (optional) Data object (generic as is different per type)
    ///
    /// # Returns
    ///
    /// A newly constructed [`SessionMessage`] object.
    ///
    pub fn new(data_type: &DataType, data: &Option<Value>) -> Self {
        Self {
            data_type: data_type.clone(),
            data: data.clone(),
        }
    }
}

impl TryInto<MessageFrame> for SessionMessage {
    type Error = AppError;

    fn try_into(self) -> Result<MessageFrame, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<MessageFrame> for &SessionMessage {
    type Error = AppError;

    fn try_into(self) -> Result<MessageFrame, Self::Error> {
        let data_type = serde_json::to_value(self.data_type.clone()).unwrap();
        Ok(MessageFrame::new(
            ControlChannel::TLS,
            pdu::CODE_OK,
            &None,
            &Some(data_type),
            &self.data,
        ))
    }
}

/// Trust0 (control plane, service proxy) connection context
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Trust0Connection {
    /// TCP connection bind pair for connection
    pub binds: ConnectionAddrs,
}

impl Trust0Connection {
    /// Trust0Connection constructor
    ///
    /// # Arguments
    ///
    /// * `binds` - connection bind address pair
    ///
    /// # Returns
    ///
    /// A newly constructed [`Trust0Connection`] object.
    ///
    pub fn new(binds: &ConnectionAddrs) -> Self {
        Self {
            binds: binds.clone(),
        }
    }

    /// Construct Trust0 connection from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a single [`Trust0Connection`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the corresponding [`Trust0Connection`] object.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Trust0Connection, AppError> {
        serde_json::from_value(value.clone()).map_err(|err| {
            AppError::General(format!(
                "Error converting serde Value to Trust0Connection: err={:?}",
                &err
            ))
        })
    }

    /// Stringified tuple client and gateway connection addresses
    ///
    /// # Arguments
    ///
    /// * `tcp_stream` - TLS server connection TCP stream
    ///
    /// # Returns
    ///
    /// A [`ConnectionAddrs`] object corresponding to the TLS server connection socket address pair (client, gateway).
    ///
    pub fn create_connection_addrs(tcp_stream: &TcpStream) -> ConnectionAddrs {
        let client_addr = match &tcp_stream.peer_addr() {
            Ok(addr) => format!("{:?}", addr),
            Err(_) => "(NA)".to_string(),
        };
        let gateway_addr = match &tcp_stream.local_addr() {
            Ok(addr) => format!("{:?}", addr),
            Err(_) => "(NA)".to_string(),
        };

        (client_addr, gateway_addr)
    }
}

unsafe impl Send for Trust0Connection {}

impl TryInto<Value> for Trust0Connection {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &Trust0Connection {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        Ok(serde_json::to_value(self).unwrap())
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::pdu;
    use crate::net::stream_utils;
    use serde_json::json;

    #[test]
    fn sessmsg_new() {
        let session_msg = SessionMessage::new(
            &DataType::Trust0Connection,
            &Some(Value::String("data1".to_string())),
        );

        assert_eq!(session_msg.data_type, DataType::Trust0Connection);
        assert!(session_msg.data.is_some());
        assert_eq!(
            session_msg.data.as_ref().unwrap().to_string(),
            "\"data1\"".to_string()
        );
    }

    #[test]
    fn sessmsg_try_into_message_frame() {
        let session_msg = SessionMessage::new(
            &DataType::Trust0Connection,
            &Some(Value::String("data1".to_string())),
        );

        let result: Result<MessageFrame, AppError> = session_msg.try_into();
        match result {
            Ok(msg_frame) => {
                assert_eq!(
                    msg_frame,
                    MessageFrame {
                        channel: ControlChannel::TLS,
                        code: pdu::CODE_OK,
                        message: None,
                        context: Some(serde_json::to_value(DataType::Trust0Connection).unwrap()),
                        data: Some(Value::String("data1".to_string())),
                    }
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn trust0conn_new() {
        let conn = Trust0Connection::new(&("addr1".to_string(), "addr2".to_string()));

        assert_eq!(conn.binds, ("addr1".to_string(), "addr2".to_string()));
    }

    #[test]
    fn trust0conn_from_serde_value_when_invalid() {
        let conn_json = json!({"binds": ["addr1","addr2", "addr3"]});

        match Trust0Connection::from_serde_value(&conn_json) {
            Ok(conn) => panic!("Unexpected successful result: conn={:?}", conn),
            _ => {}
        }
    }

    #[test]
    fn trust0conn_from_serde_value_when_valid() {
        let conn_json = json!({"binds": ["addr1","addr2"]});

        match Trust0Connection::from_serde_value(&conn_json) {
            Ok(conn) => {
                let expected_conn =
                    Trust0Connection::new(&("addr1".to_string(), "addr2".to_string()));
                assert_eq!(conn, expected_conn);
            }
            _ => {}
        }
    }

    #[test]
    fn trust0conn_try_into_value() {
        let conn = Trust0Connection::new(&("addr1".to_string(), "addr2".to_string()));

        let result: Result<Value, AppError> = conn.try_into();
        match result {
            Ok(value) => {
                assert_eq!(value, json!({"binds": ["addr1","addr2"]}));
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn trust0conn_create_connection_addrs() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let connected_tcp_peer_addr = connected_tcp_stream.server_stream.0.peer_addr().unwrap();
        let connected_tcp_local_addr = connected_tcp_stream.server_stream.0.local_addr().unwrap();

        let expected_conn_addrs = (
            format!("{:?}", connected_tcp_peer_addr),
            format!("{:?}", connected_tcp_local_addr),
        );

        let conn_addrs =
            Trust0Connection::create_connection_addrs(&connected_tcp_stream.server_stream.0);

        assert_eq!(conn_addrs, expected_conn_addrs);
    }
}
