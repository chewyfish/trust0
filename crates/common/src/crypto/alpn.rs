use std::fmt;

use regex::Regex;

pub const PROTOCOL_CONTROL_PLANE: &str = "T0CP";
pub const PROTOCOL_SERVICE: &str = "T0SRV";
pub const PROTOCOL_SERVICE_PARSE_REGEX: &str = r"^T0SRV(\d+)$";

/// Trust0 utilized ALPN protocol negotiation to determine connection type: Control Plane; Service Proxy
#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    /// REPL control plane connection type
    ControlPlane,
    /// Service (proxy) connection type
    Service(u64),
}

impl Protocol {
    /// Parse ALPN string
    ///
    /// # Arguments
    ///
    /// * `alpn_str` - Serialized [`Protocol`] value
    ///
    /// # Returns
    ///
    /// A deserialized [`Protocol`] object corresponding to given value. Otherwise if invalid, `None` is returned.
    ///
    pub fn parse(alpn_str: &str) -> Option<Protocol> {
        if alpn_str.eq(PROTOCOL_CONTROL_PLANE) {
            return Some(Protocol::ControlPlane);
        }

        let service_regex = Regex::new(PROTOCOL_SERVICE_PARSE_REGEX).unwrap();
        if service_regex.is_match(alpn_str) {
            return Some(Protocol::Service(
                service_regex.captures(alpn_str).unwrap()[1]
                    .parse()
                    .unwrap(),
            ));
        }

        None
    }

    /// Create service protocol ALPN string
    ///
    /// # Arguments
    ///
    /// * `service_id` - A service ID value
    ///
    /// # Returns
    ///
    /// The serialized string value for the corresponding [`Protocol::Service`] for this service.
    ///
    pub fn create_service_protocol(service_id: u64) -> String {
        format!("{}{}", PROTOCOL_SERVICE, service_id)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let protocol_str = match self {
            Protocol::ControlPlane => PROTOCOL_CONTROL_PLANE.to_string(),
            Protocol::Service(service_id) => Self::create_service_protocol(*service_id),
        };
        write!(fmt, "{}", &protocol_str)
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn protocol_parse_when_valid_control_plane() {
        let protocol = Protocol::parse(PROTOCOL_CONTROL_PLANE);

        assert!(protocol.is_some());
        assert_eq!(protocol.unwrap(), Protocol::ControlPlane);
    }

    #[test]
    fn protocol_parse_when_valid_service() {
        let protocol = Protocol::parse(&format!("{}{}", PROTOCOL_SERVICE, 200));

        assert!(protocol.is_some());
        assert_eq!(protocol.unwrap(), Protocol::Service(200));
    }

    #[test]
    fn protocol_parse_when_invalid_service() {
        let protocol = Protocol::parse(&format!("{}{}", PROTOCOL_SERVICE, "NaN"));

        assert!(protocol.is_none());
    }

    #[test]
    fn protocol_create_service_protocol() {
        assert_eq!(
            Protocol::create_service_protocol(200),
            format!("{}{}", PROTOCOL_SERVICE, 200)
        );
    }
}
