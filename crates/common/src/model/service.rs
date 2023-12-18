use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub enum Transport {
    #[default]
    TCP,
    UDP,
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct Service {
    pub service_id: u64,
    pub name: String,
    pub transport: Transport,
    pub host: String,
    pub port: u16,
}

impl Service {
    /// Service constructor
    pub fn new(service_id: u64, name: &str, transport: &Transport, host: &str, port: u16) -> Self {
        Self {
            service_id,
            name: name.to_string(),
            transport: transport.clone(),
            host: host.to_string(),
            port,
        }
    }
}

unsafe impl Send for Service {}
