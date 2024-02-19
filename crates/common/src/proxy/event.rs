use crate::proxy::proxy_base::ProxyType;
use std::net::SocketAddr;

/// Proxy-related events (to be used as channel messages)
#[derive(Debug)]
pub enum ProxyEvent {
    /// Closed proxy event (contains the corresponding proxy key value)
    Closed(String),
    /// Data message to send on proxy (contains: proxy key; destination socket address; message data)
    Message(String, SocketAddr, Vec<u8>),
}

impl ProxyEvent {
    /// Produces key value for given proxy address context
    ///
    /// # Arguments
    ///
    /// * `proxy_type` - Type of proxy
    /// * `socket_addr1` - (optional) Connected socket pair address 1
    /// * `socket_addr2` - (optional) Connected socket pair address 2
    ///
    /// # Returns
    ///
    /// A proxy key value, which will be unique across all currently active proxies.
    ///
    pub fn key_value(
        proxy_type: &ProxyType,
        socket_addr1: &Option<SocketAddr>,
        socket_addr2: &Option<SocketAddr>,
    ) -> String {
        let client_addr = match socket_addr1 {
            Some(client_addr) => format!("{:?}", client_addr),
            None => "client_addr_NA".to_string(),
        };
        let server_addr = match socket_addr2 {
            Some(server_addr) => format!("{:?}", server_addr),
            None => "server_addr_NA".to_string(),
        };

        format!(
            "{}:{:?},{:?}",
            &proxy_type.key_value(),
            &client_addr,
            &server_addr
        )
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxyevt_construction() {
        let _ = ProxyEvent::Closed("msg1".to_string());
        let _ = ProxyEvent::Message(
            "msg1".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            vec![0x10],
        );
    }

    #[test]
    fn proxyevt_debug() {
        assert_eq!(
            format!("{:?}", ProxyEvent::Closed("msg1".to_string())),
            "Closed(\"msg1\")".to_string()
        );
        assert_eq!(
            format!(
                "{:?}",
                ProxyEvent::Message(
                    "msg1".to_string(),
                    "127.0.0.1:1234".parse().unwrap(),
                    vec![0x10]
                )
            ),
            "Message(\"msg1\", 127.0.0.1:1234, [16])".to_string()
        );
    }

    #[test]
    fn proxyevt_key_value_when_addr1_and_noaddr2() {
        let key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &Some("127.0.0.1:1234".parse().unwrap()),
            &None,
        );
        assert_eq!(key, "T&T:\"127.0.0.1:1234\",\"server_addr_NA\"".to_string());
    }

    #[test]
    fn proxyevt_key_value_when_noaddr1_and_addr2() {
        let key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &None,
            &Some("127.0.0.1:5678".parse().unwrap()),
        );
        assert_eq!(key, "T&T:\"client_addr_NA\",\"127.0.0.1:5678\"".to_string());
    }

    #[test]
    fn proxyevt_key_value_when_noaddr1_and_noaddr2() {
        let key = ProxyEvent::key_value(&ProxyType::TcpAndTcp, &None, &None);
        assert_eq!(key, "T&T:\"client_addr_NA\",\"server_addr_NA\"".to_string());
    }

    #[test]
    fn proxyevt_key_value_when_addr1_and_addr2() {
        let key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &Some("127.0.0.1:1234".parse().unwrap()),
            &Some("127.0.0.1:5678".parse().unwrap()),
        );
        assert_eq!(key, "T&T:\"127.0.0.1:1234\",\"127.0.0.1:5678\"".to_string());
    }
}
