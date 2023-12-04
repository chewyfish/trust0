use std::sync::mpsc::Sender;
use anyhow::Result;

use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::net::tls_server::server_std;
use trust0_common::proxy::executor::ProxyExecutorEvent;

/// Represents the gateway and client proxy stream addresses respectively for a connected proxy
pub type ProxyAddrs = (String, String);

/// Service proxy trait for the gateway end of the proxy (implementations are transport-layer,... specific)
pub trait GatewayServiceProxy: Send {

    /// Startup service proxy (for clients to connect to desired service)
    fn startup(&mut self) -> Result<(), AppError>;

    /// Shutdown service proxy
    fn shutdown(&mut self);
}

/// Gateway service proxy visitor trait (implementations are transport-layer,... specific)
pub trait GatewayServiceProxyVisitor: server_std::ServerVisitor + Send {

    /// Service accessor
    fn get_service(&self) -> &Service;

    /// Gateway host for service proxy
    fn get_proxy_host(&self) -> &Option<String>;

    /// Gateway port for service proxy
    fn get_proxy_port(&self) -> u16;

    /// Client and gateway stream addresses list for proxy connections (else None if no proxy active)
    /// Returns list of tuple of (client address, gateway address)
    fn get_proxy_addrs_for_user(&self, user_id: u64) -> Vec<ProxyAddrs>;

    /// Shutdown the active service proxy connections. Consider either all connections or for given user ID.
    fn shutdown_connections(&mut self, proxy_tasks_sender: Sender<ProxyExecutorEvent>, user_id: Option<u64>) -> Result<(), AppError>;

    /// Remove proxy for given proxy key. Returns true if service proxy contained proxy key (and removed)
    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
}
