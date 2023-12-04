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

        serde_json::from_str(&data).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to parse response JSON: val={}", data), Box::new(err)))
    }
}

/// Represents the contextual mTLS client connection
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting User to serde Value".to_string(), Box::new(err))
        )
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

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting About to serde Value".to_string(), Box::new(err))
        )
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
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
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
            client_port: client_port.clone()
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting Proxy to serde Value".to_string(), Box::new(err))
        )
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
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
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

impl Into<model::service::Service> for Service {
    fn into(self) -> model::service::Service {
        let mut host = "";
        let mut port = 0;
        if let Some(address) = &self.address {
            let addr_parts: Vec<&str> = address.split(':').collect();
            if addr_parts.len() == 2 {
                host = *addr_parts.get(0).unwrap();
                port = (*addr_parts.get(1).unwrap()).parse::<u16>().unwrap_or(0);
            }
        }
        model::service::Service::new(self.id, &self.name, &self.transport, host, port)
    }
}

impl TryInto<Value> for Service {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting Service to serde Value".to_string(), Box::new(err))
        )
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
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
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
        serde_json::to_value(self).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting Connection to serde Value".to_string(), Box::new(err))
        )
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
