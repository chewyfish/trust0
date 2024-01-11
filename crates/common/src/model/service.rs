use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub enum Transport {
    #[default]
    TCP,
    UDP,
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
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

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn service_new() {
        let service = Service::new(200, "svc200", &Transport::TCP, "host1", 3000);
        assert_eq!(service.service_id, 200);
        assert_eq!(service.name, "svc200");
        assert_eq!(service.transport, Transport::TCP);
        assert_eq!(service.host, "host1");
        assert_eq!(service.port, 3000);
    }
}
