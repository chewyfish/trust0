use crate::error::AppError;

/// Types of proxies
pub enum ProxyType {
    /// Proxy a channel and a TCP stream
    ChannelAndTcp,
    /// Proxy 2 TCP streams
    TcpAndTcp,
    /// Proxy a TCP stream and a UDP socket
    TcpAndUdp,
}

impl ProxyType {
    /// Short unique key for proxy type
    ///
    /// # Returns
    ///
    /// A string representing the proxy (will be unique across all active proxies).
    ///
    pub fn key_value(&self) -> String {
        match self {
            ProxyType::ChannelAndTcp => "C&T".to_string(),
            ProxyType::TcpAndTcp => "T&T".to_string(),
            ProxyType::TcpAndUdp => "T&U".to_string(),
        }
    }
}

/// Trait implemented by all proxy stream types
pub trait ProxyStream: Send {
    /// Disconnect active proxy
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of proxy disconnection.
    ///
    fn disconnect(&mut self) -> Result<(), AppError>;
}

// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn proxytype_key_value() {
        assert_eq!(ProxyType::ChannelAndTcp.key_value(), "C&T".to_string());
        assert_eq!(ProxyType::TcpAndTcp.key_value(), "T&T".to_string());
        assert_eq!(ProxyType::TcpAndUdp.key_value(), "T&U".to_string());
    }
}
