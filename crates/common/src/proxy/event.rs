use crate::proxy::proxy_base::ProxyType;
use std::net::SocketAddr;

/// Proxy-related events (to be used as channel messages)
#[derive(Debug)]
pub enum ProxyEvent {
    Closed(String),                       // argument: proxy key
    Message(String, SocketAddr, Vec<u8>), // arguments: proxy key, destination addr, and data
}

impl ProxyEvent {
    /// Produces key value for given proxy address context
    pub fn key_value(
        proxy_type: &ProxyType,
        socket_addr1: Option<SocketAddr>,
        socket_addr2: Option<SocketAddr>,
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
