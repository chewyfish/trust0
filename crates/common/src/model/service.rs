use serde_derive::{Deserialize, Serialize};

/// Network transport type
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub enum Transport {
    /// TCP transport
    #[default]
    TCP,
    /// UDP transport
    UDP,
}

/// Service model struct
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Service ID (unique across services)
    pub service_id: u64,
    /// Service key name (unique across services)
    pub name: String,
    /// Service transport type
    pub transport: Transport,
    /// Service address host (used in gateway proxy connections)
    pub host: String,
    /// Service address port (used in gateway proxy connections)
    pub port: u16,
}

impl Service {
    /// Service constructor
    ///
    /// # Arguments
    ///
    /// * `service_id` - Service ID (unique across services)
    /// * `name` - Service key name (unique across services)
    /// * `transport` - Network transport type for service
    /// * `host` - Service address host (used in gateway proxy connections)
    /// * `port` - Service address port (used in gateway proxy connections)
    ///
    /// # Returns
    ///
    /// A newly constructed [`Service`] object.
    ///
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
