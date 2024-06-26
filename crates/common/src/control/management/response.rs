use std::borrow::Borrow;

use crate::authn::authenticator;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::management::request::Request;
use crate::control::pdu::{ControlChannel, MessageFrame};
use crate::error::AppError;
use crate::model;

/// Control plane REPL response
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Response {
    /// Indicates well-known code status for response
    pub code: u16,
    /// If necessary, contains a top-level response message
    pub message: Option<String>,
    /// Will match the exact request for this response
    pub request: Request,
    /// Response data (different depending on request type)
    pub data: Option<Value>,
}

impl Response {
    /// Response constructor
    ///
    /// # Arguments
    ///
    /// * `code` - Well-known code status for response
    /// * `message` - (optional) Top-level response message
    /// * `request` - Corresponding request for this response
    /// * `data` - (optional) Response data object (generic as is different per request-type)
    ///
    /// # Returns
    ///
    /// A newly constructed [`Response`] object.
    ///
    pub fn new(
        code: u16,
        message: &Option<String>,
        request: &Request,
        data: &Option<Value>,
    ) -> Self {
        Self {
            code,
            message: message.clone(),
            request: request.clone(),
            data: data.clone(),
        }
    }

    /// Process command response text
    ///
    /// # Arguments
    ///
    /// * `data` - JSON string, which should be a serialized [`Response`] object
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the deserialized [`Response`] object for the given data string.
    ///
    pub fn parse(data: &str) -> Result<Response, AppError> {
        serde_json::from_str(data).map_err(|err| {
            AppError::General(format!(
                "Failed to parse response JSON: val={}, err={:?}",
                data, &err
            ))
        })
    }
}

impl TryInto<MessageFrame> for Response {
    type Error = AppError;

    fn try_into(self) -> Result<MessageFrame, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<MessageFrame> for &Response {
    type Error = AppError;

    fn try_into(self) -> Result<MessageFrame, Self::Error> {
        let request = serde_json::to_value(self.request.clone()).unwrap();
        Ok(MessageFrame::new(
            ControlChannel::Management,
            self.code,
            &self.message,
            &Some(request),
            &self.data,
        ))
    }
}

/// User corresponding to the client connection
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct User {
    /// User ID (unique across users)
    user_id: i64,
    /// Friendly name for user
    name: String,
    /// Indicates the current status of the user
    status: String,
}

impl User {
    /// User constructor
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID value
    /// * `name` - Friendly name for user
    /// * `status` - Current status for user
    ///
    /// # Returns
    ///
    /// A newly constructed [`User`] object.
    ///
    pub fn new(user_id: i64, name: &str, status: &str) -> Self {
        Self {
            user_id,
            name: name.to_string(),
            status: status.to_string(),
        }
    }
}

unsafe impl Send for User {}

impl TryInto<Value> for User {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &User {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        Ok(serde_json::to_value(self).unwrap())
    }
}

/// Contextual mTLS client connection information
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct About {
    /// Certificate `subject` information
    cert_subject: Option<String>,
    /// Certificate `subject-alternative-name` information
    cert_alt_subj: Option<String>,
    /// Core (operational) client authentication information
    cert_context: Option<String>,
    /// Corresponding [`User`] object for connection
    user: Option<User>,
}

impl About {
    /// About constructor
    ///
    /// # Arguments
    ///
    /// * `cert_subject` - Certificate `subject` information
    /// * `cert_alt_subj` - Certificate `subject-alternative-name` information
    /// * `cert_context` - Core (operational) client authentication information
    /// * `user` - Corresponding [`User`] object for connection
    ///
    /// # Returns
    ///
    /// A newly constructed [`About`] object.
    ///
    pub fn new(
        cert_subject: &Option<String>,
        cert_alt_subj: &Option<String>,
        cert_context: &Option<String>,
        user: &Option<User>,
    ) -> Self {
        Self {
            cert_subject: cert_subject.clone(),
            cert_alt_subj: cert_alt_subj.clone(),
            cert_context: cert_context.clone(),
            user: user.clone(),
        }
    }
}

unsafe impl Send for About {}

impl TryInto<Value> for About {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &About {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        Ok(serde_json::to_value(self).unwrap())
    }
}

/// Active service proxy, available for use by client
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Proxy {
    /// [`Service`] object for proxy
    pub service: Service,
    /// Trust0 gateway address host
    pub gateway_host: Option<String>,
    /// Trust0 gateway address port
    pub gateway_port: u16,
    /// Trust0 client socket bind port (for service client connections)
    pub client_port: Option<u16>,
}

impl Proxy {
    /// Service constructor
    ///
    /// # Arguments
    ///
    /// * `service` - [`Service`] object for proxy
    /// * `gateway_host` - Trust0 gateway address host
    /// * `gateway_port` - Trust0 gateway address port
    /// * `client_port` - Trust0 client socket bind port (for service client connections)
    ///
    /// # Returns
    ///
    /// A newly constructed [`Service`] object.
    ///
    pub fn new(
        service: &Service,
        gateway_host: &Option<String>,
        gateway_port: u16,
        client_port: &Option<u16>,
    ) -> Self {
        Self {
            service: service.clone(),
            gateway_host: gateway_host.clone(),
            gateway_port,
            client_port: *client_port,
        }
    }

    /// Construct Proxy(ies) from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a JSON array of [`Proxy`] or a single [`Proxy`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of corresponding [`Proxy`] objects.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Vec<Proxy>, AppError> {
        if let Value::Array(values) = &value {
            Ok(values
                .iter()
                .map(|v| {
                    serde_json::from_value(v.clone()).map_err(|err| {
                        AppError::General(format!(
                            "Error converting serde Value::Array to Proxy: err={:?}",
                            &err
                        ))
                    })
                })
                .collect::<Result<Vec<Proxy>, AppError>>()?)
        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(
                |err| {
                    AppError::General(format!(
                        "Error converting serde Value to Proxy: err={:?}",
                        &err
                    ))
                },
            )?])
        }
    }
}

unsafe impl Send for Proxy {}

impl TryInto<Value> for Proxy {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &Proxy {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        Ok(serde_json::to_value(self).unwrap())
    }
}

/// An authorized service for connected mTLS device user
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Service {
    /// Service ID (unique across services)
    pub id: i64,
    /// Well-known service key name (unique across services)
    pub name: String,
    /// Network transport type (`TCP`, `UDP`)
    pub transport: model::service::Transport,
    /// Remote service address (not returned if gateway masks addresses)
    pub address: Option<String>,
}

impl Service {
    /// Service constructor
    ///
    /// # Arguments
    ///
    /// * `id` - Service ID
    /// * `name` - Well-known service key name
    /// * `transport` - Network transport type (`TCP`, `UDP`)
    /// * `address` - Potentially masked (optional) remote service address
    ///
    /// # Returns
    ///
    /// A newly constructed [`Service`] object.
    ///
    pub fn new(
        id: i64,
        name: &str,
        transport: &model::service::Transport,
        address: &Option<String>,
    ) -> Self {
        Self {
            id,
            name: name.to_string(),
            transport: transport.clone(),
            address: address.clone(),
        }
    }

    /// Construct Service(s) from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a JSON array of [`Service`] or a single [`Service`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of corresponding [`Service`] objects.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Vec<Service>, AppError> {
        if let Value::Array(values) = &value {
            Ok(values
                .iter()
                .map(|v| {
                    serde_json::from_value(v.clone()).map_err(|err| {
                        AppError::General(format!(
                            "Error converting serde Value to Service: err={:?}",
                            &err
                        ))
                    })
                })
                .collect::<Result<Vec<Service>, AppError>>()?)
        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(
                |err| {
                    AppError::General(format!(
                        "Error converting serde Value to Service: err={:?}",
                        &err
                    ))
                },
            )?])
        }
    }
}

unsafe impl Send for Service {}

impl From<model::service::Service> for Service {
    fn from(service: model::service::Service) -> Self {
        Self::from(&service)
    }
}

impl From<&model::service::Service> for Service {
    fn from(service: &model::service::Service) -> Self {
        let address = if !&service.host.is_empty() {
            Some(format!("{}:{}", &service.host.clone(), service.port))
        } else {
            None
        };
        Service::new(
            service.service_id,
            &service.name,
            &service.transport,
            &address,
        )
    }
}

impl From<Service> for model::service::Service {
    fn from(value: Service) -> Self {
        let mut host = "";
        let mut port = 0;
        if let Some(address) = &value.address {
            let addr_parts: Vec<&str> = address.split(':').collect();
            if addr_parts.len() == 2 {
                host = *addr_parts.first().unwrap();
                port = (*addr_parts.get(1).unwrap()).parse::<u16>().unwrap_or(0);
            }
        }
        Self::new(value.id, &value.name, &value.transport, host, port)
    }
}

impl TryInto<Value> for Service {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &Service {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        Ok(serde_json::to_value(self).unwrap())
    }
}

/// Message data object used in an authentication exchange
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    /// Authentication scheme
    pub authn_type: authenticator::AuthnType,
    /// Authentication flow message
    pub message: Option<authenticator::AuthnMessage>,
}

impl LoginData {
    /// LoginData constructor
    ///
    /// # Arguments
    ///
    /// * `authn_type` - Authentication scheme
    /// * `message` - (optional) Authentication flow message
    ///
    /// # Returns
    ///
    /// A newly constructed [`LoginData`] object.
    ///
    pub fn new(
        authn_type: &authenticator::AuthnType,
        message: &Option<authenticator::AuthnMessage>,
    ) -> Self {
        Self {
            authn_type: authn_type.clone(),
            message: message.clone(),
        }
    }

    /// Construct LoginData(s) from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a JSON array of [`LoginData`] or a single [`LoginData`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of corresponding [`LoginData`] objects.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Vec<LoginData>, AppError> {
        if let Value::Array(values) = &value {
            Ok(values
                .iter()
                .map(|v| {
                    serde_json::from_value(v.clone()).map_err(|err| {
                        AppError::General(format!(
                            "Error converting serde Value::Array to LoginData: err={:?}",
                            &err
                        ))
                    })
                })
                .collect::<Result<Vec<LoginData>, AppError>>()?)
        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(
                |err| {
                    AppError::General(format!(
                        "Error converting serde Value to LoginData: err={:?}",
                        &err
                    ))
                },
            )?])
        }
    }
}

unsafe impl Send for LoginData {}

impl TryInto<Value> for LoginData {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &LoginData {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        Ok(serde_json::to_value(self).unwrap())
    }
}

/// An active service proxy connections for connected mTLS device user
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Connection {
    /// Service key name value
    pub service_name: String,
    /// List of current connection bind address pairs
    pub binds: Vec<Vec<String>>,
}

impl Connection {
    /// Connection constructor
    ///
    /// # Arguments
    ///
    /// * `service_name` - Service key name value
    /// * `binds` - List of current connection bind address pairs
    ///
    /// # Returns
    ///
    /// A newly constructed [`Connection`] object.
    ///
    pub fn new(service_name: &str, binds: &[Vec<String>]) -> Self {
        Self {
            service_name: service_name.to_string(),
            binds: binds.to_vec(),
        }
    }

    /// Construct Connection(s) from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a JSON array of [`Connection`] or a single [`Connection`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of corresponding [`Connection`] objects.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Vec<Connection>, AppError> {
        if let Value::Array(values) = &value {
            Ok(values
                .iter()
                .map(|v| {
                    serde_json::from_value(v.clone()).map_err(|err| {
                        AppError::General(format!(
                            "Error converting serde Value to Connection: err={:?}",
                            &err
                        ))
                    })
                })
                .collect::<Result<Vec<Connection>, AppError>>()?)
        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(
                |err| {
                    AppError::General(format!(
                        "Error converting serde Value to Connection: err={:?}",
                        &err
                    ))
                },
            )?])
        }
    }
}

unsafe impl Send for Connection {}

impl TryInto<Value> for Connection {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &Connection {
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
    use serde_json::json;

    #[test]
    fn response_new() {
        let response = Response::new(
            pdu::CODE_OK,
            &Some("msg1".to_string()),
            &Request::Ping,
            &Some(Value::String("pong".to_string())),
        );

        assert_eq!(response.code, pdu::CODE_OK);
        assert!(response.message.is_some());
        assert_eq!(response.message.as_ref().unwrap(), "msg1");
        assert_eq!(response.request, Request::Ping);
        assert!(response.data.is_some());
        assert_eq!(
            response.data.as_ref().unwrap().to_string(),
            "\"pong\"".to_string()
        );
    }

    #[test]
    fn response_parse_when_invalid() {
        let json_str = r#"{
            "code": 200,
            "message": "msg1",
            "request": "InvalidRequest",
            "data": "{\"user_id\": 100, \"name\": \"name1\", \"status\": \"Active\"}"
        }"#;

        match Response::parse(json_str) {
            Ok(response) => panic!("Unexpected successful result: resp={:?}", response),
            _ => {}
        }
    }

    #[test]
    fn response_parse_when_valid() {
        let json_str = r#"{
            "code": 200,
            "message": "msg1",
            "request": { "Start": {"service_name": "svc1", "local_port": 3000} },
            "data": [ 1, 2 ]
        }"#;

        match Response::parse(json_str) {
            Ok(response) => {
                assert_eq!(response.code, 200);
                assert!(response.message.is_some());
                assert_eq!(response.message.unwrap(), "msg1".to_string());
                assert_eq!(
                    response.request,
                    Request::Start {
                        service_name: "svc1".to_string(),
                        local_port: 3000
                    }
                );
                assert!(response.data.is_some());
                assert_eq!(response.data.unwrap(), json!([1, 2]));
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn signalevt_try_into_message_frame() {
        let response = Response::new(
            pdu::CODE_OK,
            &Some("msg1".to_string()),
            &Request::Ping,
            &Some(Value::String("pong".to_string())),
        );

        let result: Result<MessageFrame, AppError> = response.try_into();
        match result {
            Ok(msg_frame) => {
                assert_eq!(
                    msg_frame,
                    MessageFrame {
                        channel: pdu::ControlChannel::Management,
                        code: pdu::CODE_OK,
                        message: Some("msg1".to_string()),
                        context: Some(serde_json::to_value(Request::Ping).unwrap()),
                        data: Some(Value::String("pong".to_string())),
                    }
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn user_new() {
        let user = User::new(100, "user100", "Active");

        assert_eq!(user.user_id, 100);
        assert_eq!(user.name, "user100");
        assert_eq!(user.status, "Active");
    }

    #[test]
    fn user_try_into_value() {
        let user = User::new(100, "user100", "Active");

        let result: Result<Value, AppError> = user.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"user_id": 100, "name": "user100", "status": "Active"})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn about_new() {
        let user = User::new(100, "user100", "Active");
        let about = About::new(
            &Some("csubj1".to_string()),
            &Some("casubj1".to_string()),
            &Some("cctxt1".to_string()),
            &Some(user.clone()),
        );

        assert_eq!(about.cert_subject, Some("csubj1".to_string()));
        assert_eq!(about.cert_alt_subj, Some("casubj1".to_string()));
        assert_eq!(about.cert_context, Some("cctxt1".to_string()));
        assert_eq!(about.user, Some(user));
    }

    #[test]
    fn about_try_into_value() {
        let user = User::new(100, "user100", "Active");
        let about = About::new(
            &Some("csubj1".to_string()),
            &Some("casubj1".to_string()),
            &Some("cctxt1".to_string()),
            &Some(user),
        );

        let result: Result<Value, AppError> = about.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"cert_subject": "csubj1", "cert_alt_subj": "casubj1", "cert_context": "cctxt1", "user": {"user_id": 100, "name": "user100", "status": "Active"}})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn proxy_new() {
        let svc = Service::new(
            200,
            "svc1",
            &model::service::Transport::TCP,
            &Some("host:9000".to_string()),
        );
        let proxy = Proxy::new(&svc, &Some("gwhost1".to_string()), 8400, &Some(8501));

        assert_eq!(proxy.service, svc);
        assert_eq!(proxy.client_port, Some(8501));
        assert_eq!(proxy.gateway_host, Some("gwhost1".to_string()));
        assert_eq!(proxy.gateway_port, 8400);
    }

    #[test]
    fn proxy_from_serde_value_when_invalid_object() {
        let proxy_json = json!({"service_INVALID": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501});

        match Proxy::from_serde_value(&proxy_json) {
            Ok(proxies) => panic!("Unexpected successful result: proxies={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn proxy_from_serde_value_when_valid_object() {
        let proxy_json = json!({"service": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501});

        match Proxy::from_serde_value(&proxy_json) {
            Ok(proxies) => {
                assert_eq!(proxies.len(), 1);
                let svc = Service::new(
                    200,
                    "svc1",
                    &model::service::Transport::TCP,
                    &Some("host:9000".to_string()),
                );
                let proxy = Proxy::new(&svc, &Some("gwhost1".to_string()), 8400, &Some(8501));
                assert_eq!(proxies, vec![proxy]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxy_from_serde_value_when_invalid_list() {
        let proxy_json = json!([{"service_INVALID": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501}]);

        match Proxy::from_serde_value(&proxy_json) {
            Ok(proxies) => panic!("Unexpected successful result: proxies={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn proxy_from_serde_value_when_valid_list() {
        let proxy_json = json!([{"service": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501}]);

        match Proxy::from_serde_value(&proxy_json) {
            Ok(proxies) => {
                assert_eq!(proxies.len(), 1);
                let svc = Service::new(
                    200,
                    "svc1",
                    &model::service::Transport::TCP,
                    &Some("host:9000".to_string()),
                );
                let proxy = Proxy::new(&svc, &Some("gwhost1".to_string()), 8400, &Some(8501));
                assert_eq!(proxies, vec![proxy]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxy_try_into_value() {
        let svc = Service::new(
            200,
            "svc1",
            &model::service::Transport::TCP,
            &Some("host:9000".to_string()),
        );
        let proxy = Proxy::new(&svc, &Some("gwhost1".to_string()), 8400, &Some(8501));

        let result: Result<Value, AppError> = proxy.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"service": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn service_new() {
        let svc = Service::new(
            200,
            "svc1",
            &model::service::Transport::TCP,
            &Some("host:9000".to_string()),
        );

        assert_eq!(svc.id, 200);
        assert_eq!(svc.name, "svc1");
        assert_eq!(svc.transport, model::service::Transport::TCP);
        assert_eq!(svc.address, Some("host:9000".to_string()));
    }

    #[test]
    fn service_from_serde_value_when_invalid_object() {
        let service_json =
            json!({"id_INVALID": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"});

        match Service::from_serde_value(&service_json) {
            Ok(services) => panic!("Unexpected successful result: svcs={:?}", services),
            _ => {}
        }
    }

    #[test]
    fn service_from_serde_value_when_valid_object() {
        let service_json =
            json!({"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"});

        match Service::from_serde_value(&service_json) {
            Ok(services) => {
                assert_eq!(services.len(), 1);
                let service = Service::new(
                    200,
                    "svc1",
                    &model::service::Transport::TCP,
                    &Some("host:9000".to_string()),
                );
                assert_eq!(services, vec![service]);
            }
            _ => {}
        }
    }

    #[test]
    fn service_from_serde_value_when_invalid_list() {
        let service_json = json!([{"id_INVALID": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}]);

        match Service::from_serde_value(&service_json) {
            Ok(services) => panic!("Unexpected successful result: svcs={:?}", services),
            _ => {}
        }
    }

    #[test]
    fn service_from_serde_value_when_valid_list() {
        let service_json =
            json!([{"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}]);

        match Service::from_serde_value(&service_json) {
            Ok(services) => {
                assert_eq!(services.len(), 1);
                let service = Service::new(
                    200,
                    "svc1",
                    &model::service::Transport::TCP,
                    &Some("host:9000".to_string()),
                );
                assert_eq!(services, vec![service]);
            }
            _ => {}
        }
    }

    #[test]
    fn service_try_into_value() {
        let svc = Service::new(
            200,
            "svc1",
            &model::service::Transport::TCP,
            &Some("host:9000".to_string()),
        );

        let result: Result<Value, AppError> = svc.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn logindata_new() {
        let login_data = LoginData::new(
            &authenticator::AuthnType::ScramSha256,
            &Some(authenticator::AuthnMessage::Payload("data1".to_string())),
        );

        assert_eq!(login_data.authn_type, authenticator::AuthnType::ScramSha256);
        assert_eq!(
            login_data.message,
            Some(authenticator::AuthnMessage::Payload("data1".to_string()))
        );
    }

    #[test]
    fn logindata_from_serde_value_when_invalid_object() {
        let login_data_json =
            json!({"authnTypeINVALID": "scramSha256", "message": {"payload": "data1"}});

        match LoginData::from_serde_value(&login_data_json) {
            Ok(login_data) => panic!("Unexpected successful result: data={:?}", login_data),
            _ => {}
        }
    }

    #[test]
    fn logindata_from_serde_value_when_valid_object() {
        let login_data_json = json!({"authnType": "scramSha256", "message": {"payload": "data1"}});

        match LoginData::from_serde_value(&login_data_json) {
            Ok(login_data_list) => {
                assert_eq!(login_data_list.len(), 1);
                let login_data = LoginData::new(
                    &authenticator::AuthnType::ScramSha256,
                    &Some(authenticator::AuthnMessage::Payload("data1".to_string())),
                );
                assert_eq!(login_data_list, vec![login_data]);
            }
            _ => {}
        }
    }

    #[test]
    fn logindata_from_serde_value_when_invalid_list() {
        let login_data_json =
            json!([{"authnTypeINVALID": "scramSha256", "message": {"payload": "data1"}}]);

        match LoginData::from_serde_value(&login_data_json) {
            Ok(login_data) => panic!("Unexpected successful result: data={:?}", login_data),
            _ => {}
        }
    }

    #[test]
    fn logindata_from_serde_value_when_valid_list() {
        let login_data_json =
            json!([{"authnType": "scramSha256", "message": {"payload": "data1"}}]);

        match LoginData::from_serde_value(&login_data_json) {
            Ok(login_data_list) => {
                assert_eq!(login_data_list.len(), 1);
                let login_data = LoginData::new(
                    &authenticator::AuthnType::ScramSha256,
                    &Some(authenticator::AuthnMessage::Payload("data1".to_string())),
                );
                assert_eq!(login_data_list, vec![login_data]);
            }
            _ => {}
        }
    }

    #[test]
    fn logindata_try_into_value() {
        let login_data = LoginData::new(
            &authenticator::AuthnType::ScramSha256,
            &Some(authenticator::AuthnMessage::Payload("data1".to_string())),
        );

        let result: Result<Value, AppError> = login_data.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"authnType": "scramSha256", "message": {"payload": "data1"}})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }

    #[test]
    fn connection_new() {
        let conn = Connection::new(
            "svc1",
            &vec![
                vec!["b0".to_string(), "b1".to_string()],
                vec!["b2".to_string(), "b3".to_string()],
            ],
        );

        assert_eq!(conn.service_name, "svc1");
        assert_eq!(conn.binds.len(), 2);
        assert_eq!(conn.binds[0], vec!["b0".to_string(), "b1".to_string()]);
        assert_eq!(conn.binds[1], vec!["b2".to_string(), "b3".to_string()]);
    }

    #[test]
    fn connection_from_serde_value_when_invalid_object() {
        let conn_json = json!({"service_name_INVALID": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match Connection::from_serde_value(&conn_json) {
            Ok(proxies) => panic!("Unexpected successful result: conns={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn connection_from_serde_value_when_valid_object() {
        let conn_json = json!({"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match Connection::from_serde_value(&conn_json) {
            Ok(conns) => {
                assert_eq!(conns.len(), 1);
                let conn = Connection::new(
                    "svc1",
                    &vec![
                        vec!["b0".to_string(), "b1".to_string()],
                        vec!["b2".to_string(), "b3".to_string()],
                    ],
                );
                assert_eq!(conns, vec![conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn connection_from_serde_value_when_invalid_list() {
        let conn_json =
            json!([{"service_name_INVALID": "svc1", "binds": [["b0","b1"],["b2","b3"]]}]);

        match Connection::from_serde_value(&conn_json) {
            Ok(proxies) => panic!("Unexpected successful result: conns={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn connection_from_serde_value_when_valid_list() {
        let conn_json = json!([{"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]}]);

        match Connection::from_serde_value(&conn_json) {
            Ok(conns) => {
                assert_eq!(conns.len(), 1);
                let conn = Connection::new(
                    "svc1",
                    &vec![
                        vec!["b0".to_string(), "b1".to_string()],
                        vec!["b2".to_string(), "b3".to_string()],
                    ],
                );
                assert_eq!(conns, vec![conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn connection_try_into_value() {
        let conn = Connection::new(
            "svc1",
            &vec![
                vec!["b0".to_string(), "b1".to_string()],
                vec!["b2".to_string(), "b3".to_string()],
            ],
        );

        let result: Result<Value, AppError> = conn.try_into();
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
