use anyhow::Result;
use std::sync::mpsc::Sender;

use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::proxy::executor::ProxyExecutorEvent;

/// Service proxy trait for the client end of the proxy (implementations are transport-layer,... specific)
pub trait ClientServiceProxy: Send {
    /// Startup proxy listener (for clients to connect to gateway proxy for service)
    fn startup(&mut self) -> Result<(), AppError>;
}

/// Client service proxy visitor trait (implementations are transport-layer,... specific)
pub trait ClientServiceProxyVisitor: Send {
    /// Service accessor
    fn get_service(&self) -> &Service;

    /// Client port for service proxy
    fn get_client_proxy_port(&self) -> u16;

    /// Gateway host for service proxy
    fn get_gateway_proxy_host(&self) -> &str;

    /// Gateway port for service proxy
    fn get_gateway_proxy_port(&self) -> u16;

    /// Request a server shutdown
    fn set_shutdown_requested(&mut self);

    /// Shutdown proxy connection for service
    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    ) -> Result<(), AppError>;

    /// Remove proxy for given proxy key. Returns whether removed else not found
    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::mock;

    // mocks
    // =====

    mock! {
        pub CliSvcProxyVisitor {}
        impl ClientServiceProxyVisitor for CliSvcProxyVisitor {
            fn get_service(&self) -> &Service;
            fn get_client_proxy_port(&self) -> u16;
            fn get_gateway_proxy_host(&self) -> &str;
            fn get_gateway_proxy_port(&self) -> u16;
            fn set_shutdown_requested(&mut self);
            fn shutdown_connections(&mut self, proxy_tasks_sender: Sender<ProxyExecutorEvent>) -> Result<(), AppError>;
            fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool;
        }
    }
}
