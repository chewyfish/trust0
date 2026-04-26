use anyhow::Result;
use std::sync::{Arc, Mutex};

use crate::control::tls::message::ConnectionAddrs;
use crate::error::AppError;
use crate::model::service::Service;

/// Simple tuple to hold proxy address information for connected session
#[derive(Clone, PartialEq, Debug, Default)]
pub struct ProxyAddrs(pub u16, pub String, pub u16);

impl ProxyAddrs {
    /// Client port accessor
    ///
    /// # Returns
    ///
    /// Client server port for service proxy
    ///
    pub fn get_client_port(&self) -> u16 {
        self.0
    }

    /// Gateway host accessor
    ///
    /// # Returns
    ///
    /// Gateway server host for service proxy
    ///
    pub fn get_gateway_host(&self) -> &str {
        &self.1
    }

    /// Gateway port accessor
    ///
    /// # Returns
    ///
    /// Gateway server port for service proxy
    ///
    pub fn get_gateway_port(&self) -> u16 {
        self.2
    }
}

/// Trust0 client controller service management (of proxy connections)
pub trait ClientControlServiceMgr: Send {
    /// Proxy addresses for active service proxy
    ///
    /// # Arguments
    ///
    /// * `service_id` - service ID
    ///
    /// # Returns
    ///
    /// If found, proxy addresses associated to service.
    ///
    fn get_proxy_addrs_for_service(&self, service_id: i64) -> Option<ProxyAddrs>;

    /// Active service proxy visitors accessor
    ///
    /// # Returns
    ///
    /// List of active service proxy visitor objects.
    ///
    fn get_service_proxies(&self) -> Vec<Arc<Mutex<dyn ClientControlServiceProxyVisitor>>>;

    /// Startup new proxy service to allow clients to connect/communicate to given service
    ///
    /// # Arguments
    ///
    /// * `service` - service model object
    /// * `proxy_addrs` - address pair for proxy
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the started proxy's proxy address pair.
    ///
    fn startup(
        &mut self,
        service: &Service,
        proxy_addrs: &ProxyAddrs,
    ) -> Result<ProxyAddrs, AppError>;

    /// Shutdown all service proxies or a single service proxy (all connections, listeners, ...)
    ///
    /// # Arguments
    ///
    /// * `service_id` - If supplied, close specific service proxy, else close all service proxies
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the shutdown operation.
    ///
    fn shutdown(&mut self, service_id: Option<i64>) -> Result<(), AppError>;

    /// Shutdown service proxy connection.
    ///
    /// # Arguments
    ///
    /// * `service_id` - Service ID
    /// * `proxy_key` - Key value corresponding to service proxy
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the shutdown operation.
    ///
    fn shutdown_connection(&mut self, service_id: i64, proxy_key: &str) -> Result<(), AppError>;
}

/// Client controller service proxy visitor trait (implementations are transport-layer,... specific)
pub trait ClientControlServiceProxyVisitor: Send {
    /// Service accessor
    fn get_service(&self) -> Service;

    /// Client and gateway proxy key and stream addresses list for proxy connections (else None if no proxy active)
    /// Returns list of tuple of (proxy key, (client address, gateway address))
    fn get_proxy_keys(&self) -> Vec<(String, ConnectionAddrs)>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::mock;

    // mocks
    // =====
    //
    mock! {
        pub ClientControlSvcMgr {}
        impl ClientControlServiceMgr for ClientControlSvcMgr {
            fn get_proxy_addrs_for_service(&self, service_id: i64) -> Option<ProxyAddrs>;
            fn get_service_proxies(&self) -> Vec<Arc<Mutex<dyn ClientControlServiceProxyVisitor>>>;
            fn startup(&mut self, service: &Service, proxy_addrs: &ProxyAddrs) -> Result<ProxyAddrs, AppError>;
            fn shutdown(&mut self, service_id: Option<i64>) -> Result<(), AppError>;
            fn shutdown_connection(&mut self, service_id: i64, proxy_key: &str) -> Result<(), AppError>;
        }
    }

    mock! {
        pub ClientControlSvcProxyVisitor {}
        impl ClientControlServiceProxyVisitor for ClientControlSvcProxyVisitor {
            fn get_service(&self) -> Service;
            fn get_proxy_keys(&self) -> Vec<(String, ConnectionAddrs)>;
        }
        unsafe impl Send for ClientControlSvcProxyVisitor {}
    }
}
