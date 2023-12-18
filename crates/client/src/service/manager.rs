use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;

use anyhow::Result;

use super::proxy::proxy_base::ClientServiceProxy;
use super::proxy::tcp_proxy::TcpClientProxy;
use crate::config::AppConfig;
use crate::service::proxy::proxy_base::ClientServiceProxyVisitor;
use crate::service::proxy::tcp_proxy::TcpClientProxyServerVisitor;
use crate::service::proxy::udp_proxy::{UdpClientProxy, UdpClientProxyServerVisitor};
use trust0_common::error::AppError;
use trust0_common::logging::info;
use trust0_common::model::service::{Service, Transport};
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::ProxyExecutorEvent;
use trust0_common::target;

/// Simple tuple to hold proxy address information for connected session
#[derive(Clone, PartialEq, Debug, Default)]
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

/// Handles management of service proxy connections
pub trait ServiceMgr: Send {
    /// Active proxy service's ID for given proxy key
    fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<u64>;

    /// Proxy addresses for active service proxy
    fn get_proxy_addrs_for_service(&self, service_id: u64) -> Option<ProxyAddrs>;

    /// Active proxy visitor for given service
    fn get_proxy_visitor_for_service(
        &self,
        service_id: u64,
    ) -> Option<&Arc<Mutex<dyn ClientServiceProxyVisitor>>>;

    /// Clone proxy tasks sender
    fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent>;

    /// Startup new proxy service to allow clients to connect/communicate to given service
    fn startup(
        &mut self,
        service: &Service,
        proxy_addrs: &ProxyAddrs,
    ) -> Result<ProxyAddrs, AppError>;

    /// Shutdown all connected services, and respective proxy connections/listeners
    fn shutdown(&mut self) -> Result<(), AppError>;
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
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    testing_mode: bool,
}

impl ClientServiceMgr {
    /// ServiceMgr constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        proxy_tasks_sender: Sender<ProxyExecutorEvent>,
        proxy_events_sender: Sender<ProxyEvent>,
    ) -> Self {
        Self {
            app_config,
            service_proxies: HashMap::new(),
            service_proxy_visitors: HashMap::new(),
            service_proxy_threads: HashMap::new(),
            service_addrs: HashMap::new(),
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_events_sender,
            proxy_tasks_sender,
            testing_mode: false,
        }
    }

    /// Listen and process any proxy events (blocking)
    pub fn poll_proxy_events(
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        proxy_events_receiver: Receiver<ProxyEvent>,
    ) -> Result<(), AppError> {
        loop {
            Self::process_next_proxy_event(&service_mgr, &proxy_events_receiver)?;
        }
    }

    /// Process next queued proxy event (blocking). Returns whether processing occurred
    fn process_next_proxy_event(
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        proxy_events_receiver: &Receiver<ProxyEvent>,
    ) -> Result<bool, AppError> {
        let proxy_event = proxy_events_receiver.recv().map_err(|err| {
            AppError::GenWithMsgAndErr("Error receiving proxy event".to_string(), Box::new(err))
        })?;

        if let ProxyEvent::Closed(proxy_key) = proxy_event {
            let service_id = service_mgr
                .lock()
                .unwrap()
                .get_proxy_service_for_proxy_key(&proxy_key)
                .unwrap_or(u64::MAX);

            if let Some(proxy_visitor) = service_mgr
                .lock()
                .unwrap()
                .get_proxy_visitor_for_service(service_id)
            {
                if proxy_visitor
                    .lock()
                    .unwrap()
                    .remove_proxy_for_key(&proxy_key)
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

impl ServiceMgr for ClientServiceMgr {
    fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<u64> {
        self.services_by_proxy_key
            .lock()
            .unwrap()
            .get(proxy_key)
            .cloned()
    }

    fn get_proxy_addrs_for_service(&self, service_id: u64) -> Option<ProxyAddrs> {
        self.service_addrs.get(&service_id).cloned()
    }

    fn get_proxy_visitor_for_service(
        &self,
        service_id: u64,
    ) -> Option<&Arc<Mutex<dyn ClientServiceProxyVisitor>>> {
        self.service_proxy_visitors.get(&service_id)
    }

    fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent> {
        self.proxy_tasks_sender.clone()
    }

    fn startup(
        &mut self,
        service: &Service,
        proxy_addrs: &ProxyAddrs,
    ) -> Result<ProxyAddrs, AppError> {
        // Service proxy already started
        // - - - - - - - - - - - - - - -
        if let Some(ProxyAddrs(cli_proxy_port, gw_proxy_host, gw_proxy_port)) =
            self.service_addrs.get(&service.service_id)
        {
            return Ok(ProxyAddrs(
                *cli_proxy_port,
                gw_proxy_host.clone(),
                *gw_proxy_port,
            ));
        }

        // Startup new proxy for service
        // - - - - - - - - - - - - - - -
        let service_proxy: Arc<Mutex<dyn ClientServiceProxy>>;
        let service_proxy_visitor: Arc<Mutex<dyn ClientServiceProxyVisitor>>;

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
                    self.services_by_proxy_key.clone(),
                )?));

                service_proxy = Arc::new(Mutex::new(TcpClientProxy::new(
                    self.app_config.clone(),
                    tcp_proxy_visitor.clone(),
                    proxy_addrs.get_client_port(),
                )));

                service_proxy_visitor = tcp_proxy_visitor;

                if !self.testing_mode {
                    let service_proxy_closure = service_proxy.clone();
                    let service_proxy_thread =
                        thread::spawn(move || service_proxy_closure.lock().unwrap().startup());
                    self.service_proxy_threads
                        .insert(service.service_id, service_proxy_thread);
                }
            }

            // Starts up UDP service proxy
            Transport::UDP => {
                let (server_socket_channel_sender, server_socket_channel_receiver) =
                    mpsc::channel();

                let udp_proxy_visitor = Arc::new(Mutex::new(UdpClientProxyServerVisitor::new(
                    self.app_config.clone(),
                    service.clone(),
                    proxy_addrs.get_client_port(),
                    proxy_addrs.get_gateway_host(),
                    proxy_addrs.get_gateway_port(),
                    server_socket_channel_sender,
                    self.proxy_tasks_sender.clone(),
                    self.proxy_events_sender.clone(),
                    self.services_by_proxy_key.clone(),
                )?));

                service_proxy = Arc::new(Mutex::new(UdpClientProxy::new(
                    self.app_config.clone(),
                    server_socket_channel_receiver,
                    udp_proxy_visitor.clone(),
                    proxy_addrs.get_client_port(),
                )?));

                service_proxy_visitor = udp_proxy_visitor;

                if !self.testing_mode {
                    let service_proxy_closure = service_proxy.clone();
                    let service_proxy_thread =
                        thread::spawn(move || service_proxy_closure.lock().unwrap().startup());
                    self.service_proxy_threads
                        .insert(service.service_id, service_proxy_thread);
                }
            }
        }

        self.service_addrs
            .insert(service.service_id, proxy_addrs.clone());
        self.service_proxies
            .insert(service.service_id, service_proxy);
        self.service_proxy_visitors
            .insert(service.service_id, service_proxy_visitor);

        Ok(proxy_addrs.clone())
    }

    fn shutdown(&mut self) -> Result<(), AppError> {
        let mut errors: Vec<String> = vec![];

        self.service_proxy_visitors
            .iter()
            .for_each(|(proxy_service_id, proxy_visitor)| {
                let mut proxy_visitor = proxy_visitor.lock().unwrap();

                proxy_visitor.deref_mut().set_shutdown_requested();

                if let Err(err) = proxy_visitor
                    .deref_mut()
                    .shutdown_connections(self.clone_proxy_tasks_sender())
                {
                    errors.push(format!(
                        "Failed shutting down service proxy: svc_id={}, err={:?}",
                        proxy_service_id, err
                    ));
                } else {
                    info(
                        &target!(),
                        &format!("Service proxy shutdown: svc_id={}", proxy_service_id),
                    );
                }
            });

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error shutting down services: err(s)={}",
                errors.join(",")
            )));
        }

        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::config;
    use crate::service::proxy::proxy_base::tests::MockCliSvcProxyVisitor;
    use mockall::{mock, predicate};
    use std::net::SocketAddr;
    use std::str::FromStr;

    // mocks
    // =====

    mock! {
        pub SvcMgr {}
        impl ServiceMgr for SvcMgr {
            fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<u64>;
            fn get_proxy_addrs_for_service(&self, service_id: u64) -> Option<ProxyAddrs>;
            fn get_proxy_visitor_for_service(&self, service_id: u64) -> Option<&'static Arc<Mutex<dyn ClientServiceProxyVisitor>>>;
            fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent>;
            fn startup(&mut self, service: &Service, proxy_addrs: &ProxyAddrs) -> Result<ProxyAddrs, AppError>;
            fn shutdown(&mut self) -> Result<(), AppError>;
        }
    }

    // tests
    // =====

    #[test]
    fn clisvcmgr_process_next_proxy_event_when_ignorable_evt() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let events_channel = mpsc::channel();
        let proxy_key = "proxykey1".to_string();
        let proxy_svc_id = 123;

        let mut proxy_visitor = MockCliSvcProxyVisitor::new();
        proxy_visitor
            .expect_remove_proxy_for_key()
            .with(predicate::eq(proxy_key.clone()))
            .never();

        let mut service_mgr =
            ClientServiceMgr::new(app_config, mpsc::channel().0, events_channel.0.clone());
        service_mgr.testing_mode = true;
        service_mgr
            .services_by_proxy_key
            .lock()
            .unwrap()
            .insert(proxy_key.clone(), proxy_svc_id);
        service_mgr
            .service_proxy_visitors
            .insert(proxy_svc_id, Arc::new(Mutex::new(proxy_visitor)));
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(service_mgr));

        let msg = ProxyEvent::Message(
            proxy_key.clone(),
            SocketAddr::from_str("127.0.0.1:3000").unwrap(),
            "data".as_bytes().to_vec(),
        );
        events_channel.0.send(msg).unwrap();

        match ClientServiceMgr::process_next_proxy_event(&service_mgr, &events_channel.1) {
            Ok(processed) => {
                assert_eq!(processed, false);
            }
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn clisvcmgr_process_next_proxy_event_when_closed_evt() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let events_channel = mpsc::channel();
        let proxy_key = "proxykey1".to_string();
        let proxy_svc_id = 123;

        let mut proxy_visitor = MockCliSvcProxyVisitor::new();
        proxy_visitor
            .expect_remove_proxy_for_key()
            .with(predicate::eq(proxy_key.clone()))
            .times(1)
            .return_once(|_| true);

        let mut service_mgr =
            ClientServiceMgr::new(app_config, mpsc::channel().0, events_channel.0.clone());
        service_mgr.testing_mode = true;
        service_mgr
            .services_by_proxy_key
            .lock()
            .unwrap()
            .insert(proxy_key.clone(), proxy_svc_id);
        service_mgr
            .service_proxy_visitors
            .insert(proxy_svc_id, Arc::new(Mutex::new(proxy_visitor)));
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(service_mgr));

        let msg = ProxyEvent::Closed(proxy_key.clone());
        events_channel.0.send(msg).unwrap();

        match ClientServiceMgr::process_next_proxy_event(&service_mgr, &events_channel.1) {
            Ok(processed) => {
                assert_eq!(processed, true);
            }
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn clisvcmgr_startup_when_already_started() {
        let service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::TCP,
            host: "localhost".to_string(),
            port: 8200,
        };
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let proxy_addrs = ProxyAddrs(3000, "gwhost1".to_string(), 8000);

        let mut service_mgr =
            ClientServiceMgr::new(app_config, mpsc::channel().0, mpsc::channel().0);
        service_mgr.testing_mode = true;
        service_mgr
            .service_addrs
            .insert(service.service_id, proxy_addrs.clone());

        let orig_svc_addrs_len = service_mgr.service_addrs.len();
        let orig_svc_proxies_len = service_mgr.service_proxies.len();
        let orig_svc_proxy_visitors_len = service_mgr.service_proxy_visitors.len();

        match service_mgr.startup(&service, &proxy_addrs) {
            Ok(result_proxy_addrs) => {
                assert_eq!(result_proxy_addrs, proxy_addrs);
            }
            Err(err) => {
                panic!("Unexpected startup result: err={:?}", &err);
            }
        }

        assert_eq!(service_mgr.service_addrs.len(), orig_svc_addrs_len);
        assert_eq!(service_mgr.service_proxies.len(), orig_svc_proxies_len);
        assert_eq!(
            service_mgr.service_proxy_visitors.len(),
            orig_svc_proxy_visitors_len
        );
    }

    #[test]
    fn clisvcmgr_start_when_tcp_service() {
        let service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::TCP,
            host: "localhost".to_string(),
            port: 8200,
        };
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let proxy_addrs = ProxyAddrs(3000, "gwhost1".to_string(), 8000);

        let mut service_mgr =
            ClientServiceMgr::new(app_config, mpsc::channel().0, mpsc::channel().0);
        service_mgr.testing_mode = true;

        let orig_svc_addrs_len = service_mgr.service_addrs.len();
        let orig_svc_proxies_len = service_mgr.service_proxies.len();
        let orig_svc_proxy_visitors_len = service_mgr.service_proxy_visitors.len();

        match service_mgr.startup(&service, &proxy_addrs) {
            Ok(result_proxy_addrs) => {
                assert_eq!(result_proxy_addrs, proxy_addrs);
            }
            Err(err) => {
                panic!("Unexpected startup result: err={:?}", &err);
            }
        }

        assert_eq!(service_mgr.service_addrs.len(), orig_svc_addrs_len + 1);
        assert_eq!(service_mgr.service_proxies.len(), orig_svc_proxies_len + 1);
        assert_eq!(
            service_mgr.service_proxy_visitors.len(),
            orig_svc_proxy_visitors_len + 1
        );
    }

    #[test]
    fn clisvcmgr_start_when_udp_service() {
        let service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::UDP,
            host: "localhost".to_string(),
            port: 8200,
        };
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let proxy_addrs = ProxyAddrs(3000, "gwhost1".to_string(), 8000);

        let mut service_mgr =
            ClientServiceMgr::new(app_config, mpsc::channel().0, mpsc::channel().0);
        service_mgr.testing_mode = true;

        let orig_svc_addrs_len = service_mgr.service_addrs.len();
        let orig_svc_proxies_len = service_mgr.service_proxies.len();
        let orig_svc_proxy_visitors_len = service_mgr.service_proxy_visitors.len();

        match service_mgr.startup(&service, &proxy_addrs) {
            Ok(result_proxy_addrs) => {
                assert_eq!(result_proxy_addrs, proxy_addrs);
            }
            Err(err) => {
                panic!("Unexpected startup result: err={:?}", &err);
            }
        }

        assert_eq!(service_mgr.service_addrs.len(), orig_svc_addrs_len + 1);
        assert_eq!(service_mgr.service_proxies.len(), orig_svc_proxies_len + 1);
        assert_eq!(
            service_mgr.service_proxy_visitors.len(),
            orig_svc_proxy_visitors_len + 1
        );
    }

    #[test]
    fn clisvcmgr_shutdown_when_2_service_proxies() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());

        let mut proxy_visitor200 = MockCliSvcProxyVisitor::new();
        proxy_visitor200
            .expect_set_shutdown_requested()
            .times(1)
            .return_once(|| ());
        proxy_visitor200
            .expect_shutdown_connections()
            .times(1)
            .return_once(|_| Ok(()));
        let mut proxy_visitor201 = MockCliSvcProxyVisitor::new();
        proxy_visitor201
            .expect_set_shutdown_requested()
            .times(1)
            .return_once(|| ());
        proxy_visitor201
            .expect_shutdown_connections()
            .times(1)
            .return_once(|_| Ok(()));

        let mut service_mgr =
            ClientServiceMgr::new(app_config, mpsc::channel().0, mpsc::channel().0);
        service_mgr.testing_mode = true;
        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(proxy_visitor200)));
        service_mgr
            .service_proxy_visitors
            .insert(201, Arc::new(Mutex::new(proxy_visitor201)));

        if let Err(err) = service_mgr.shutdown() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
