use std::collections::HashMap;
use std::ops::DerefMut;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use anyhow::Result;

use trust0_common::error::AppError;
use trust0_common::logging::info;
use trust0_common::model::service::{Service, Transport};
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::ProxyExecutorEvent;
use trust0_common::target;
use crate::config::AppConfig;
use crate::service::proxy::proxy::ClientServiceProxyVisitor;
use crate::service::proxy::tcp_proxy::TcpClientProxyServerVisitor;
use crate::service::proxy::udp_proxy::{UdpClientProxy, UdpClientProxyServerVisitor};
use super::proxy::proxy::ClientServiceProxy;
use super::proxy::tcp_proxy::TcpClientProxy;

/// Simple tuple to hold proxy address information for connected session
#[derive(Clone, Debug, Default)]
pub struct ProxyAddrs(pub u16, pub String, pub u16);

impl ProxyAddrs {

    /// Client port accessor
    pub fn get_client_port(&self) -> u16 {
        self.0
    }

    /// Gateway host accessor
    pub fn get_gateway_host(&self) -> &str {
        &self.1
    }

    /// Gateway port accessor
    pub fn get_gateway_port(&self) -> u16 {
        self.2
    }

}
/// Manage service connections for client session.  Only one of these should be constructed.
pub struct ClientServiceMgr {
    app_config: Arc<AppConfig>,
    service_proxies: HashMap<u64, Arc<Mutex<dyn ClientServiceProxy>>>,
    service_proxy_visitors: HashMap<u64, Arc<Mutex<dyn ClientServiceProxyVisitor>>>,
    service_proxy_threads: HashMap<u64, JoinHandle<Result<(), AppError>>>,
    service_addrs: HashMap<u64, ProxyAddrs>,
    services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>,
    proxy_events_sender: Sender<ProxyEvent>,
    proxy_tasks_sender: Sender<ProxyExecutorEvent>
}

impl ClientServiceMgr {

    /// ServiceMgr constructor
    pub fn new(app_config: Arc<AppConfig>,
               proxy_tasks_sender: Sender<ProxyExecutorEvent>,
               proxy_events_sender: Sender<ProxyEvent>)
        -> Self {

        Self {
            app_config,
            service_proxies: HashMap::new(),
            service_proxy_visitors: HashMap::new(),
            service_proxy_threads: HashMap::new(),
            service_addrs: HashMap::new(),
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_events_sender,
            proxy_tasks_sender
        }
    }

    pub fn poll_proxy_events(service_mgr: Arc<Mutex<dyn ServiceMgr>>, proxy_events_receiver: Receiver<ProxyEvent>)
        -> Result<(), AppError> {
        'EVENTS:
        loop {
            let proxy_event = proxy_events_receiver.recv().map_err(|err|
                AppError::GenWithMsgAndErr("Error receiving proxy event".to_string(), Box::new(err)))?;

            if let ProxyEvent::Closed(proxy_key) = proxy_event {
                let service_id = service_mgr.lock().unwrap().get_proxy_service_for_proxy_key(&proxy_key).unwrap_or(u64::MAX);

                if let Some(proxy_visitor) = service_mgr.lock().unwrap().get_proxy_visitor_for_service(service_id) {
                    if proxy_visitor.lock().unwrap().remove_proxy_for_key(&proxy_key) {
                        continue 'EVENTS;
                    }
                }
            }
        }
    }
}

impl ServiceMgr for ClientServiceMgr {

    fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<u64> {
        self.services_by_proxy_key.lock().unwrap().get(proxy_key).cloned()
    }

    fn get_proxy_addrs_for_service(&self, service_id: u64) -> Option<&ProxyAddrs> {
        self.service_addrs.get(&service_id)
    }

    fn get_proxy_visitor_for_service(&self, service_id: u64) -> Option<&Arc<Mutex<dyn ClientServiceProxyVisitor>>> {
        self.service_proxy_visitors.get(&service_id)
    }

    fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent> {
        self.proxy_tasks_sender.clone()
    }

    fn startup(&mut self,
               service: &Service,
               proxy_addrs: &ProxyAddrs)
        -> Result<ProxyAddrs, AppError> {

        // Service proxy already started
        // - - - - - - - - - - - - - - -
        if let Some(ProxyAddrs(cli_proxy_port, gw_proxy_host, gw_proxy_port)) = self.service_addrs.get(&service.service_id) {
            return Ok(ProxyAddrs(*cli_proxy_port, gw_proxy_host.clone(), *gw_proxy_port));
        }

        // Startup new proxy for service
        // - - - - - - - - - - - - - - -
        let service_proxy: Arc<Mutex<dyn ClientServiceProxy>>;
        let service_proxy_visitor: Arc<Mutex<dyn ClientServiceProxyVisitor>>;
        let service_proxy_thread: JoinHandle<Result<(), AppError>>;

        match service.transport {

            // Starts up TCP service proxy
            Transport::TCP => {
                let tcp_proxy_visitor = Arc::new(Mutex::new(TcpClientProxyServerVisitor::new(
                    self.app_config.clone(),
                    service.clone(),
                    proxy_addrs.get_client_port(),
                    proxy_addrs.get_gateway_host(),
                    proxy_addrs.get_gateway_port(),
                    self.proxy_tasks_sender.clone(),
                    self.proxy_events_sender.clone(),
                    self.services_by_proxy_key.clone())?));

                service_proxy = Arc::new(Mutex::new(TcpClientProxy::new(
                    self.app_config.clone(),
                    tcp_proxy_visitor.clone(),
                    proxy_addrs.get_client_port())));

                service_proxy_visitor = tcp_proxy_visitor;

                let service_proxy_closure = service_proxy.clone();
                service_proxy_thread = thread::spawn(move || {
                    service_proxy_closure.lock().unwrap().startup()
                });
            }

            // Starts up UDP service proxy
            Transport::UDP => {
                let (server_socket_channel_sender, server_socket_channel_receiver) = mpsc::channel();

                let udp_proxy_visitor = Arc::new(Mutex::new(UdpClientProxyServerVisitor::new(
                    self.app_config.clone(),
                    service.clone(),
                    proxy_addrs.get_client_port(),
                    proxy_addrs.get_gateway_host(),
                    proxy_addrs.get_gateway_port(),
                    server_socket_channel_sender,
                    self.proxy_tasks_sender.clone(),
                    self.proxy_events_sender.clone(),
                    self.services_by_proxy_key.clone())?));

                service_proxy = Arc::new(Mutex::new(UdpClientProxy::new(
                    self.app_config.clone(),
                    server_socket_channel_receiver,
                    udp_proxy_visitor.clone(),
                    proxy_addrs.get_client_port())?));

                service_proxy_visitor = udp_proxy_visitor;

                let service_proxy_closure = service_proxy.clone();
                service_proxy_thread = thread::spawn(move || {
                    service_proxy_closure.lock().unwrap().startup()
                });
            }
        }

        self.service_addrs.insert(service.service_id, proxy_addrs.clone());
        self.service_proxies.insert(service.service_id, service_proxy);
        self.service_proxy_visitors.insert(service.service_id, service_proxy_visitor);
        self.service_proxy_threads.insert(service.service_id, service_proxy_thread);

        Ok(proxy_addrs.clone())
    }

    fn shutdown(&mut self) -> Result<(), AppError> {
        let mut errors: Vec<String> = vec![];

        self.service_proxy_visitors.iter().for_each(|(proxy_service_id, proxy_visitor)| {
            let mut proxy_visitor = proxy_visitor.lock().unwrap();

            proxy_visitor.deref_mut().set_shutdown_requested(true);

            if let Err(err) = proxy_visitor.deref_mut().shutdown_connections(self.clone_proxy_tasks_sender()) {
                errors.push(format!("Failed shutting down service proxy: svc_id={}, err={:?}", proxy_service_id, err));
            } else {
                info(&target!(), &format!("Service proxy shutdown: svc_id={}", proxy_service_id));
            }
        });

        if !errors.is_empty() {
            return Err(AppError::General(format!("Error shutting down services: err(s)={}", errors.join(","))));
        }

        Ok(())
    }
}

pub trait ServiceMgr : Send {

    /// Active proxy service's ID for given proxy key
    fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<u64>;

    /// Proxy addresses for active service proxy
    fn get_proxy_addrs_for_service(&self, service_id: u64) -> Option<&ProxyAddrs>;

    /// Active proxy visitor for given service
    fn get_proxy_visitor_for_service(&self, service_id: u64) -> Option<&Arc<Mutex<dyn ClientServiceProxyVisitor>>>;

        /// Clone proxy tasks sender
    fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent>;

    /// Startup new proxy service to allow clients to connect/communicate to given service
    fn startup(&mut self,
               service: &Service,
               proxy_addrs: &ProxyAddrs)
               -> Result<ProxyAddrs, AppError>;

    /// Shutdown all connected services, and respective proxy connections/listeners
    fn shutdown(&mut self) -> Result<(), AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use mockall::mock;
    use super::*;

    // mocks
    // =====

    mock! {
        pub SvcMgr {}
        impl ServiceMgr for SvcMgr {
            fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<u64>;
            fn get_proxy_addrs_for_service(&self, service_id: u64) -> Option<&'static ProxyAddrs>;
            fn get_proxy_visitor_for_service(&self, service_id: u64) -> Option<&'static Arc<Mutex<dyn ClientServiceProxyVisitor>>>;
            fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent>;
            fn startup(&mut self, service: &Service, proxy_addrs: &ProxyAddrs) -> Result<ProxyAddrs, AppError>;
            fn shutdown(&mut self) -> Result<(), AppError>;
        }
    }
}