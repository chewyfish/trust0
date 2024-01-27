use std::borrow::Borrow;
use std::collections::VecDeque;

use crate::control::management;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;

pub const CODE_OK: u16 = 200;
pub const CODE_CREATED: u16 = 201;
pub const CODE_BAD_REQUEST: u16 = 400;
pub const CODE_UNAUTHORIZED: u16 = 401;
pub const CODE_FORBIDDEN: u16 = 403;
pub const CODE_NOT_FOUND: u16 = 404;
pub const CODE_INTERNAL_SERVER_ERROR: u16 = 500;

/// Control plane channel type:
///
/// * management (REPL shell session administration)
/// * signaling (OOB control/monitoring)
///
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub enum ControlChannel {
    /// User REPL shell used for service proxy management
    #[default]
    Management,
    /// OOB channel for control, eventing, monitoring, ...
    Signaling,
}

/// The control plane uses a frame-based messaging protocol. [`MessageFrame`] represents the protocol data unit (PDU)
/// passed between the client and server entities for the purpose of signaling or management
///
/// On the wire, the PDU is composed of a JSON serialized [`MessageFrame`] object preceded by its length (as a `u16`).
///
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct MessageFrame {
    /// Control plane channel
    pub channel: ControlChannel,
    /// Indicates well-known (status, ...) code
    pub code: u16,
    /// If necessary, contains top-level textual message
    pub message: Option<String>,
    /// Gives context for this data frame
    pub context: Option<Value>,
    /// Data payload (different depending on channel and context)
    pub data: Option<Value>,
}

impl MessageFrame {
    /// MessageFrame constructor
    ///
    /// # Arguments
    /// * `channel` - Control plane channel
    /// * `code` - Well-known (status, ...) code
    /// * `message` - (optional) Top-level textual message
    /// * `context` - (optional) Context for this data frame
    /// * `data` - (optional) Data payload (generic as is different per channel and context)
    ///
    /// # Returns
    ///
    /// A newly constructed [`MessageFrame`] object.
    ///
    pub fn new(
        channel: ControlChannel,
        code: u16,
        message: &Option<String>,
        context: &Option<Value>,
        data: &Option<Value>,
    ) -> Self {
        Self {
            channel: channel.clone(),
            code,
            message: message.clone(),
            context: context.clone(),
            data: data.clone(),
        }
    }

    /// Build (serialized) PDU for this MessageFrame
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the wire encoded PDU. This value is a JSON serialized [`MessageFrame`]
    /// preceded by a `u16`, which denotes its length.
    ///
    pub fn build_pdu(&self) -> Result<Vec<u8>, AppError> {
        let data_frame = serde_json::to_string(self).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Error serializing MessageFrame to JSON string: frame={:?}",
                    self
                ),
                Box::new(err),
            )
        })?;
        let data_frame_len = data_frame.len() as u16;

        Ok([&data_frame_len.to_be_bytes(), data_frame.as_bytes()].concat())
    }

    /// If available, consume next PDU bytes from buffer, parse and return data frame.
    ///
    /// Each PDU is a JSON serialized [`MessageFrame`] preceded by a `u16`, which denotes its length.
    ///
    /// # Arguments
    ///
    /// * `buffer` - [`VecDeque`] of PDUs (as bytes). If a complete PDU is available, buffer will be `drain`ed accordingly.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing an optional deserialized [`MessageFrame`] object for the given PDU string.
    /// If there are not enough bytes available for the next PDU, `Ok(None)` will be returned.
    ///
    pub fn consume_next_pdu(buffer: &mut VecDeque<u8>) -> Result<Option<MessageFrame>, AppError> {
        if buffer.len() < 3 {
            return Ok(None);
        }

        // Determine PDU length
        let pdu_len = u16::from_be_bytes(
            buffer
                .range(..2)
                .copied()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        ) as usize;
        if buffer.len() < (pdu_len + 2) {
            return Ok(None);
        }
        let _ = buffer.drain(..2);

        // Parse PDU data frame
        let data_frame_json = String::from_utf8(buffer.drain(..pdu_len).collect::<Vec<u8>>())
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error parsing UTF8 data".to_string(), Box::new(err))
            })?;

        Ok(Some(Self::deserialize(&data_frame_json)?))
    }

    /// Parse serialized [`MessageFrame`]
    ///
    /// # Arguments
    ///
    /// * `value` - JSON string, which should be a serialized [`MessageFrame`] object
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the deserialized [`MessageFrame`] object for the given value string.
    ///
    pub fn deserialize(value: &str) -> Result<MessageFrame, AppError> {
        serde_json::from_str(value).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to parse data frame value JSON: val={}", value),
                Box::new(err),
            )
        })
    }
}

impl TryInto<management::request::Request> for MessageFrame {
    type Error = AppError;

    fn try_into(self) -> Result<management::request::Request, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<management::request::Request> for &MessageFrame {
    type Error = AppError;

    fn try_into(self) -> Result<management::request::Request, Self::Error> {
        if self.data.is_none() {
            return Err(AppError::General(
                "Management request message frame must have data".to_string(),
            ));
        }
        let request_command_line: String =
            serde_json::from_value(self.data.as_ref().unwrap().clone()).map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error converting PDU data Value to request command line".to_string(),
                    Box::new(err),
                )
            })?;
        management::request::RequestProcessor::new().parse(&request_command_line)
    }
}

impl TryInto<management::response::Response> for MessageFrame {
    type Error = AppError;

    fn try_into(self) -> Result<management::response::Response, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<management::response::Response> for &MessageFrame {
    type Error = AppError;

    fn try_into(self) -> Result<management::response::Response, Self::Error> {
        if self.context.is_none() {
            return Err(AppError::General(
                "Management response message frame must have a context".to_string(),
            ));
        }
        let request: management::request::Request =
            serde_json::from_value(self.context.as_ref().unwrap().clone()).map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error converting PDU context Value to management Request".to_string(),
                    Box::new(err),
                )
            })?;
        Ok(management::response::Response::new(
            self.code,
            &self.message,
            &request,
            &self.data,
        ))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use super::*;
    use serde_json::json;

    #[test]
    fn msgframe_new() {
        let msg_frame = MessageFrame::new(
            ControlChannel::Management,
            CODE_OK,
            &Some("msg1".to_string()),
            &Some(json!({"Start": {"service_name": "svc1", "local_port": 3000}})),
            &Some(json!([1, 2])),
        );

        assert_eq!(msg_frame.code, CODE_OK);
        assert_eq!(msg_frame.channel, ControlChannel::Management);
        assert!(msg_frame.message.is_some());
        assert_eq!(msg_frame.message.unwrap(), "msg1".to_string());
        assert_eq!(
            msg_frame.context,
            Some(json!({"Start": {"service_name": "svc1", "local_port": 3000}})),
        );
        assert!(msg_frame.data.is_some());
        assert_eq!(msg_frame.data.unwrap(), json!([1, 2]));
    }

    #[test]
    fn msgframe_build_pdu() {
        let msg_frame = MessageFrame {
            channel: ControlChannel::Management,
            code: CODE_OK,
            message: Some("msg1".to_string()),
            context: Some(json!("Start")),
            data: Some(json!([1])),
        };

        let result = msg_frame.build_pdu();
        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
        let pdu = result.unwrap();

        let msg_frame_json =
            r#"{"channel":"Management","code":200,"message":"msg1","context":"Start","data":[1]}"#;
        let mut expected_pdu: Vec<u8> = vec![];
        expected_pdu.append(&mut (msg_frame_json.len() as u16).to_be_bytes().to_vec());
        expected_pdu.append(&mut msg_frame_json.as_bytes().to_vec());

        assert_eq!(pdu, expected_pdu);
    }

    #[test]
    fn msgframe_consume_next_pdu_when_not_available() {
        let mut buffer = VecDeque::from(vec![0, 10, 65, 66, 67]);

        match MessageFrame::consume_next_pdu(&mut buffer) {
            Ok(msg_frame) if msg_frame.is_some() => {
                panic!("Unexpected found pdu: msg={:?}", &msg_frame)
            }
            Err(err) => panic!("Unexepcted result: err={:?}", &err),
            _ => {}
        }
    }

    #[test]
    fn msgframe_consume_next_pdu_when_available() {
        let msg_frame_json =
            r#"{"channel":"Management","code":200,"message":"msg1","context":"Start","data":[1]}"#;
        let mut expected_pdu: Vec<u8> = vec![];
        expected_pdu.append(&mut (msg_frame_json.len() as u16).to_be_bytes().to_vec());
        expected_pdu.append(&mut msg_frame_json.as_bytes().to_vec());
        let extra_bytes = vec![0, 100, 65, 66, 67];

        let mut buffer = VecDeque::from([expected_pdu, extra_bytes.clone()].concat());

        match MessageFrame::consume_next_pdu(&mut buffer) {
            Ok(Some(msg_frame)) => {
                assert_eq!(msg_frame.code, 200);
                assert_eq!(msg_frame.channel, ControlChannel::Management);
                assert!(msg_frame.message.is_some());
                assert_eq!(msg_frame.message.unwrap(), "msg1".to_string());
                assert_eq!(msg_frame.context, Some(json!("Start")));
                assert!(msg_frame.data.is_some());
                assert_eq!(msg_frame.data.unwrap(), json!([1]));
                assert_eq!(buffer, VecDeque::from(extra_bytes));
            }
            Ok(None) => panic!("Unexpected not found pdu"),
            Err(err) => panic!("Unexepcted result: err={:?}", &err),
        }
    }

    #[test]
    fn msgframe_deserialize_when_invalid_json() {
        let json_str = r#"{
            "channel": "INVALID",
            "code": 200,
            "message": "msg1",
            "context": "{\"key1\": \"value1\"}",
            "data": "{\"user_id\": 100, \"name\": \"name1\", \"status\": \"Active\"}"
        }"#;

        match MessageFrame::deserialize(json_str) {
            Ok(frame) => panic!("Unexpected successful result: frame={:?}", frame),
            _ => {}
        }
    }

    #[test]
    fn msgframe_deserialize_when_valid() {
        let json_str = r#"{
            "channel": "Management",
            "code": 200,
            "message": "msg1",
            "context": { "Start": {"service_name": "svc1", "local_port": 3000} },
            "data": [ 1, 2 ]
        }"#;

        match MessageFrame::deserialize(json_str) {
            Ok(msg_frame) => {
                assert_eq!(msg_frame.code, 200);
                assert_eq!(msg_frame.channel, ControlChannel::Management);
                assert!(msg_frame.message.is_some());
                assert_eq!(msg_frame.message.unwrap(), "msg1".to_string());
                assert_eq!(
                    msg_frame.context,
                    Some(json!({"Start": {"service_name": "svc1", "local_port": 3000}})),
                );
                assert!(msg_frame.data.is_some());
                assert_eq!(msg_frame.data.unwrap(), json!([1, 2]));
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }
}
