use regex::Regex;

pub const PROTOCOL_CONTROL_PLANE: &str = "T0CP";
pub const PROTOCOL_SERVICE: &str = "T0SRV";
pub const PROTOCOL_SERVICE_PARSE_REGEX: &str = r"^T0SRV(\d+)$";

/// Trust0 utilized ALPN protocol negotiation to determine connection type: Control Plane; Service Proxy
#[derive(Debug, PartialEq)]
pub enum Protocol {
    ControlPlane,
    Service(u64)
}

impl Protocol {

    /// Parse ALPN string
    pub fn parse(alpn_str: &str) -> Option<Protocol> {

        if alpn_str.eq(PROTOCOL_CONTROL_PLANE) {
           return Some(Protocol::ControlPlane);
        }

        let service_regex = Regex::new(PROTOCOL_SERVICE_PARSE_REGEX).unwrap();
        if service_regex.is_match(alpn_str) {
            return Some(Protocol::Service(service_regex.captures(alpn_str).unwrap()[1].parse().unwrap()));
        }

        None
    }

    /// Create service protocol ALPN string
    pub fn create_service_protocol(service_id: u64) -> String {
        format!("{}{}", PROTOCOL_SERVICE, service_id)
    }

    /// Stringify protocol
    pub fn to_string(&self) -> String {
        match self {
            Protocol::ControlPlane => PROTOCOL_CONTROL_PLANE.to_string(),
            Protocol::Service(service_id) => Self::create_service_protocol(*service_id)
        }
    }
}
