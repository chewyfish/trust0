use std::borrow::Borrow;

use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::request::Request;
use crate::error::AppError;
use crate::model;

/// Container struct for controller responses
pub const CODE_OK: u16 = 200;
pub const CODE_CREATED: u16 = 201;
pub const CODE_BAD_REQUEST: u16 = 400;
pub const CODE_UNAUTHORIZED: u16 = 401;
pub const CODE_FORBIDDEN: u16 = 403;
pub const CODE_NOT_FOUND: u16 = 404;
pub const CODE_INTERNAL_SERVER_ERROR: u16 = 500;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Response  {
    pub code: u16,
    pub message: Option<String>,
    pub request: Request,
    pub data: Option<Value>
}

impl Response {

    /// Response constructor
    pub fn new(
        code: u16,
        message: &Option<String>,
        request: &Request,
        data: &Option<Value>) -> Self {

        Self {
            code,
            message: message.clone(),
            request: request.clone(),
            data: data.clone()
        }
    }

    /// Process command response text
    pub fn parse(data: &str) -> Result<Response, AppError> {

        serde_json::from_str(data).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to parse response JSON: val={}", data), Box::new(err)))
    }
}

/// Represents the contextual mTLS client connection
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct User {
    user_id: u64,
    name: String,
    status: String
}

impl User {

    /// About constructor
    pub fn new(
        user_id: u64,
        name: &str,
        status: &str) -> Self {

        Self {
            user_id,
            name: name.to_string(),
            status: status.to_string()
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting User to serde Value".to_string(), Box::new(err))
        )
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct About {
    cert_subject: Option<String>,
    cert_alt_subj: Option<String>,
    cert_context: Option<String>,
    user: Option<User>
}

impl About {

    /// About constructor
    pub fn new(
        cert_subject: &Option<String>,
        cert_alt_subj: &Option<String>,
        cert_context: &Option<String>,
        user: &Option<User>) -> Self {

        Self {
            cert_subject: cert_subject.clone(),
            cert_alt_subj: cert_alt_subj.clone(),
            cert_context: cert_context.clone(),
            user: user.clone()
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting About to serde Value".to_string(), Box::new(err))
        )
    }
}

/// Represents an active service proxy, available for use by client
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Proxy {
    pub service: Service,
    pub gateway_host: Option<String>,
    pub gateway_port: u16,
    pub client_port: Option<u16>
}

impl Proxy {

    /// Service constructor
    pub fn new(
        service: &Service,
        gateway_host: &Option<String>,
        gateway_port: u16,
        client_port: &Option<u16>) -> Self {

        Self {
            service: service.clone(),
            gateway_host: gateway_host.clone(),
            gateway_port,
            client_port: *client_port
        }
    }

    /// Construct Proxy(ies) from serde Value
    pub fn from_serde_value(value: &Value) -> Result<Vec<Proxy>, AppError> {

        if let Value::Array(values) = &value {
            Ok(values.iter()
                .map(|v| serde_json::from_value(v.clone()).map_err(|err|
                    AppError::GenWithMsgAndErr("Error converting serde Value::Array to Proxy".to_string(), Box::new(err))))
                .collect::<Result<Vec<Proxy>, AppError>>()?)

        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(|err|
                AppError::GenWithMsgAndErr("Error converting serde Value to Proxy".to_string(), Box::new(err)))?])

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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting Proxy to serde Value".to_string(), Box::new(err))
        )
    }
}

/// Represents an authorized service for connected mTLS device user
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Service {
    pub id: u64,
    pub name: String,
    pub transport: model::service::Transport,
    pub address: Option<String>
}

impl Service {

    /// Service constructor
    pub fn new(
        id: u64,
        name: &str,
        transport: &model::service::Transport,
        address: Option<String>) -> Self {

        Self {
            id,
            name: name.to_string(),
            transport: transport.clone(),
            address
        }
    }

    /// Construct Service(s) from serde Value
    pub fn from_serde_value(value: &Value) -> Result<Vec<Service>, AppError> {

        if let Value::Array(values) = &value {
            Ok(values.iter()
                .map(|v| serde_json::from_value(v.clone()).map_err(|err|
                    AppError::GenWithMsgAndErr("Error converting serde Value to Service".to_string(), Box::new(err))))
                .collect::<Result<Vec<Service>, AppError>>()?)

        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(|err|
                AppError::GenWithMsgAndErr("Error converting serde Value to Service".to_string(), Box::new(err)))?])

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
        Service::new(service.service_id, &service.name, &service.transport, address)
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
        Self::new(value.id, &value.name, &value.transport, host, port)    }
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting Service to serde Value".to_string(), Box::new(err))
        )
    }
}

/// Represents active service proxy connections for connected mTLS device user
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
pub struct Connection {
    pub service_name: String,
    pub binds: Vec<Vec<String>>,
}

impl Connection {

    /// Connection constructor
    pub fn new(
        service_name: &str,
        binds: Vec<Vec<String>>) -> Self {

        Self {
            service_name: service_name.to_string(),
            binds
        }
    }

    /// Construct Connection(s) from serde Value
    pub fn from_serde_value(value: &Value) -> Result<Vec<Connection>, AppError> {

        if let Value::Array(values) = &value {
            Ok(values.iter()
                .map(|v| serde_json::from_value(v.clone()).map_err(|err|
                    AppError::GenWithMsgAndErr("Error converting serde Value to Connection".to_string(), Box::new(err))))
                .collect::<Result<Vec<Connection>, AppError>>()?)

        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(|err|
                AppError::GenWithMsgAndErr("Error converting serde Value to Connection".to_string(), Box::new(err)))?])

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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting Connection to serde Value".to_string(), Box::new(err))
        )
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use serde_json::json;
    use super::*;

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
                assert_eq!(response.request, Request::Start { service_name: "svc1".to_string(), local_port: 3000 });
                assert!(response.data.is_some());
                assert_eq!(response.data.unwrap(), json!([1, 2]));
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn user_try_into() {

        let user = User::new(100, "user100", "Active");

        let result: Result<Value, AppError> = user.try_into();
        match result {
            Ok(value) => {
                assert_eq!(value, json!({"user_id": 100, "name": "user100", "status": "Active"}));
            }
            Err(err) =>panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn about_try_into() {

        let user = User::new(100, "user100", "Active");
        let about = About::new(&Some("csubj1".to_string()), &Some("casubj1".to_string()), &Some("cctxt1".to_string()), &Some(user));

        let result: Result<Value, AppError> = about.try_into();
        match result {
            Ok(value) => {
                assert_eq!(value, json!({"cert_subject": "csubj1", "cert_alt_subj": "casubj1", "cert_context": "cctxt1", "user": {"user_id": 100, "name": "user100", "status": "Active"}}));
            }
            Err(err) =>panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn proxy_from_serde_value_when_invalid() {

        let proxy_json = json!({"service_INVALID": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501});

        match Proxy::from_serde_value(&proxy_json) {
            Ok(proxies) => panic!("Unexpected successful result: proxies={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn proxy_from_serde_value_when_valid() {

        let proxy_json = json!({"service": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501});

        match Proxy::from_serde_value(&proxy_json) {
            Ok(proxies) => {
                assert_eq!(proxies.len(), 1);
                let svc = Service::new(200, "svc1", &model::service::Transport::TCP, Some("host:9000".to_string()));
                let proxy = Proxy::new(&svc, &Some("gwhost1".to_string()), 8400, &Some(8501));
                assert_eq!(proxies, vec![proxy]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxy_try_into() {

        let svc = Service::new(200, "svc1", &model::service::Transport::TCP, Some("host:9000".to_string()));
        let proxy = Proxy::new(&svc, &Some("gwhost1".to_string()), 8400, &Some(8501));

        let result: Result<Value, AppError> = proxy.try_into();
        match result {
            Ok(value) => {
                assert_eq!(value, json!({"service": {"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}, "gateway_host": "gwhost1", "gateway_port": 8400, "client_port": 8501}));
            }
            Err(err) =>panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn service_from_serde_value_when_invalid() {

        let service_json = json!({"id_INVALID": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"});

        match Service::from_serde_value(&service_json) {
            Ok(services) => panic!("Unexpected successful result: svcs={:?}", services),
            _ => {}
        }
    }

    #[test]
    fn service_from_serde_value_when_valid() {

        let service_json = json!({"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"});

        match Service::from_serde_value(&service_json) {
            Ok(services) => {
                assert_eq!(services.len(), 1);
                let service = Service::new(200, "svc1", &model::service::Transport::TCP, Some("host:9000".to_string()));
                assert_eq!(services, vec![service]);
            }
            _ => {}
        }
    }

    #[test]
    fn service_try_into() {

        let svc = Service::new(200, "svc1", &model::service::Transport::TCP, Some("host:9000".to_string()));

        let result: Result<Value, AppError> = svc.try_into();
        match result {
            Ok(value) => {
                assert_eq!(value, json!({"id": 200, "name": "svc1", "transport": "TCP", "address": "host:9000"}));
            }
            Err(err) =>panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn connection_from_serde_value_when_invalid() {

        let conn_json = json!({"service_name_INVALID": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match Connection::from_serde_value(&conn_json) {
            Ok(proxies) => panic!("Unexpected successful result: conns={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn connection_from_serde_value_when_valid() {

        let conn_json = json!({"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match Connection::from_serde_value(&conn_json) {
            Ok(conns) => {
                assert_eq!(conns.len(), 1);
                let conn = Connection::new("svc1", vec![vec!["b0".to_string(),"b1".to_string()],vec!["b2".to_string(),"b3".to_string()]]);
                assert_eq!(conns, vec![conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn connection_try_into() {

        let conn = Connection::new("svc1", vec![vec!["b0".to_string(),"b1".to_string()],vec!["b2".to_string(),"b3".to_string()]]);

        let result: Result<Value, AppError> = conn.try_into();
        match result {
            Ok(value) => {
                assert_eq!(value, json!({"service_name": "svc1", "binds": [["b0","b1"],["b2","b3"]]}));
            }
            Err(err) =>panic!("Unexpected result: err={:?}", err)
        }
    }

}