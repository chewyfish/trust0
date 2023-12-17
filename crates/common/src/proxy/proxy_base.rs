use crate::error::AppError;

/// Types of proxies
pub enum ProxyType {
    ChannelAndTcp,
    TcpAndTcp,
    TcpAndUdp
}

impl ProxyType {

    /// Short unique key for proxy type
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

    // Disconnect active proxy
    fn disconnect(&mut self) -> Result<(), AppError>;
}
