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

/// Handles management of service proxy connections
pub trait ServiceMgr: Send {
    /// Active proxy service's ID for given proxy key
    ///
    /// # Arguments
    ///
    /// * `proxy_key` - key value for a service proxy
    ///
    /// # Returns
    ///
    /// If found, service ID associated to proxy key.
    ///
    fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<i64>;

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
    /// List of active service proxy visitor object.
    ///
    fn get_service_proxies(&self) -> Vec<Arc<Mutex<dyn ClientServiceProxyVisitor>>>;

    /// Active proxy visitor for given service
    ///
    /// # Arguments
    ///
    /// * `service_id` - service ID
    ///
    /// # Returns
    ///
    /// If found, service proxy visitor object for given service ID.
    ///
    fn get_proxy_visitor_for_service(
        &self,
        service_id: i64,
    ) -> Option<&Arc<Mutex<dyn ClientServiceProxyVisitor>>>;

    /// Clone proxy tasks sender
    ///
    /// # Returns
    ///
    /// Cloned proxy tasks channel sender
    ///
    #[allow(dead_code)]
    fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent>;

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

/// Manage service connections for client session.  Only one of these should be constructed.
pub struct ClientServiceMgr {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Active service proxies
    service_proxies: HashMap<i64, Arc<Mutex<dyn ClientServiceProxy>>>,
    /// Active service proxy visitors
    service_proxy_visitors: HashMap<i64, Arc<Mutex<dyn ClientServiceProxyVisitor>>>,
    /// Service proxy server threads (polls new connections,...)
    service_proxy_threads: HashMap<i64, JoinHandle<Result<(), AppError>>>,
    /// Proxy address pair for service proxy
    service_addrs: HashMap<i64, ProxyAddrs>,
    /// Service IDs map keyed on proxy connection key
    services_by_proxy_key: Arc<Mutex<HashMap<String, i64>>>,
    /// Proxy events channel sender
    proxy_events_sender: Sender<ProxyEvent>,
    /// Proxy executor events channel sender
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    /// Toggled when used in testing
    testing_mode: bool,
}

impl ClientServiceMgr {
    /// ServiceMgr constructor
    ///
    /// # Arguments
    ///
    /// * `app_confid` - Application configuration object
    /// * `proxy_tasks_sender` - Proxy executor events channel sender
    /// * `proxy_events_sender` - Proxy events channel sender
    ///
    /// # Returns
    ///
    /// A newly constructed [`ClientServiceMgr`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        proxy_events_sender: &Sender<ProxyEvent>,
    ) -> Self {
        Self {
            app_config: app_config.clone(),
            service_proxies: HashMap::new(),
            service_proxy_visitors: HashMap::new(),
            service_proxy_threads: HashMap::new(),
            service_addrs: HashMap::new(),
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_events_sender: proxy_events_sender.clone(),
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            testing_mode: false,
        }
    }

    /// Listen and process any proxy events (blocking)
    ///
    /// # Arguments
    ///
    /// * `service_mgr` - Service manager
    /// * `proxy_events_receiver` - Proxy events channel receiver
    ///
    /// # Arguments
    ///
    /// A [`Result`] indicating success/failure of the polling operation.
    ///
    pub fn poll_proxy_events(
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        proxy_events_receiver: Receiver<ProxyEvent>,
    ) -> Result<(), AppError> {
        loop {
            Self::process_next_proxy_event(&service_mgr, &proxy_events_receiver)?;
        }
    }

    /// Process next queued proxy event (blocking). Returns whether processing occurred
    ///
    /// # Arguments
    ///
    /// * `service_mgr` - Service manager
    /// * `proxy_events_receiver` - Proxy events channel receiver
    ///
    /// # Arguments
    ///
    /// A [`Result`] containing an indicator if any processing occurred.
    ///
    fn process_next_proxy_event(
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        proxy_events_receiver: &Receiver<ProxyEvent>,
    ) -> Result<bool, AppError> {
        let proxy_event = proxy_events_receiver.recv().map_err(|err| {
            AppError::General(format!("Error receiving proxy event: err={:?}", &err))
        })?;

        if let ProxyEvent::Closed(proxy_key) = proxy_event {
            let service_id = service_mgr
                .lock()
                .unwrap()
                .get_proxy_service_for_proxy_key(&proxy_key)
                .unwrap_or(i64::MAX);

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
    fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<i64> {
        self.services_by_proxy_key
            .lock()
            .unwrap()
            .get(proxy_key)
            .cloned()
    }

    fn get_proxy_addrs_for_service(&self, service_id: i64) -> Option<ProxyAddrs> {
        self.service_addrs.get(&service_id).cloned()
    }

    fn get_service_proxies(&self) -> Vec<Arc<Mutex<dyn ClientServiceProxyVisitor>>> {
        self.service_proxy_visitors.values().cloned().collect()
    }

    fn get_proxy_visitor_for_service(
        &self,
        service_id: i64,
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
                    &self.app_config,
                    service,
                    proxy_addrs.get_client_port(),
                    proxy_addrs.get_gateway_host(),
                    proxy_addrs.get_gateway_port(),
                    &self.proxy_tasks_sender,
                    &self.proxy_events_sender,
                    &self.services_by_proxy_key,
                )?));

                service_proxy = Arc::new(Mutex::new(TcpClientProxy::new(
                    &self.app_config,
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
                    &self.app_config,
                    service,
                    proxy_addrs.get_client_port(),
                    proxy_addrs.get_gateway_host(),
                    proxy_addrs.get_gateway_port(),
                    &server_socket_channel_sender,
                    &self.proxy_tasks_sender,
                    &self.proxy_events_sender,
                    &self.services_by_proxy_key,
                )?));

                service_proxy = Arc::new(Mutex::new(UdpClientProxy::new(
                    &self.app_config,
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

    fn shutdown(&mut self, service_id: Option<i64>) -> Result<(), AppError> {
        let mut errors: Vec<String> = vec![];

        let mut removed_service_ids = Vec::new();

        self.service_proxy_visitors
            .iter()
            .filter(|(proxy_service_id, _)| {
                service_id.is_none() || (*proxy_service_id == service_id.as_ref().unwrap())
            })
            .for_each(|(proxy_service_id, proxy_visitor)| {
                let mut proxy_visitor = proxy_visitor.lock().unwrap();

                proxy_visitor.deref_mut().set_shutdown_requested();

                if let Err(err) = proxy_visitor
                    .deref_mut()
                    .shutdown_connections(&self.proxy_tasks_sender)
                {
                    errors.push(format!(
                        "Failed shutting down service proxy: svc_id={}, err={:?}",
                        proxy_service_id, err
                    ));
                } else {
                    removed_service_ids.push(*proxy_service_id);
                    info(
                        &target!(),
                        &format!("Service proxy shutdown: svc_id={}", proxy_service_id),
                    );
                }
            });

        for removed_service_id in &removed_service_ids {
            _ = self.service_proxies.remove(removed_service_id);
            _ = self.service_proxy_visitors.remove(removed_service_id);
            _ = self.service_proxy_threads.remove(removed_service_id);
            _ = self.service_addrs.remove(removed_service_id)
        }

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error shutting down services: err(s)={}",
                errors.join(",")
            )));
        }

        Ok(())
    }

    fn shutdown_connection(&mut self, service_id: i64, proxy_key: &str) -> Result<(), AppError> {
        if let Some(proxy_visitor) = self.service_proxy_visitors.get(&service_id) {
            match proxy_visitor
                .lock()
                .unwrap()
                .shutdown_connection(&self.proxy_tasks_sender, proxy_key)
            {
                Ok(()) => info(
                    &target!(),
                    &format!(
                        "Service proxy connection shutdown: svc_id={}, proxy_stream={}",
                        service_id, proxy_key
                    ),
                ),
                Err(err) => {
                    return Err(AppError::General(
                        format!(
                            "Failed shutting down service proxy connection: svc_id={}, proxy_stream={}, err={:?}",
                            service_id,
                            &proxy_key,
                            &err
                    )))
                }
            }
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
            fn get_proxy_service_for_proxy_key(&self, proxy_key: &str) -> Option<i64>;
            fn get_proxy_addrs_for_service(&self, service_id: i64) -> Option<ProxyAddrs>;
            fn get_service_proxies(&self) -> Vec<Arc<Mutex<dyn ClientServiceProxyVisitor>>>;
            fn get_proxy_visitor_for_service(&self, service_id: i64) -> Option<&'static Arc<Mutex<dyn ClientServiceProxyVisitor>>>;
            fn clone_proxy_tasks_sender(&self) -> Sender<ProxyExecutorEvent>;
            fn startup(&mut self, service: &Service, proxy_addrs: &ProxyAddrs) -> Result<ProxyAddrs, AppError>;
            fn shutdown(&mut self, service_id: Option<i64>) -> Result<(), AppError>;
            fn shutdown_connection(&mut self, service_id: i64, proxy_key: &str) -> Result<(), AppError>;
        }
    }

    // tests
    // =====

    #[test]
    fn clisvcmgr_new() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());

        let service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);

        assert!(service_mgr.service_proxies.is_empty());
        assert!(service_mgr.service_proxy_visitors.is_empty());
        assert!(service_mgr.service_proxy_threads.is_empty());
        assert!(service_mgr.service_addrs.is_empty());
        assert!(service_mgr.services_by_proxy_key.lock().unwrap().is_empty());
        assert!(!service_mgr.testing_mode);
    }

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
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &events_channel.0);
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
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &events_channel.0);
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
    fn clisvcmgr_get_proxy_service_for_proxy_key() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr
            .services_by_proxy_key
            .lock()
            .unwrap()
            .insert("key1".to_string(), 200);

        let service_id = service_mgr.get_proxy_service_for_proxy_key("key1");

        assert!(service_id.is_some());
        assert_eq!(service_id.unwrap(), 200);
    }

    #[test]
    fn clisvcmgr_get_proxy_addrs_for_service() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr
            .service_addrs
            .insert(200, ProxyAddrs(1234, "host1".to_string(), 5678));

        let proxy_addrs = service_mgr.get_proxy_addrs_for_service(200);

        assert!(proxy_addrs.is_some());
        assert_eq!(
            proxy_addrs.unwrap(),
            ProxyAddrs(1234, "host1".to_string(), 5678)
        );
    }

    #[test]
    fn clisvcmgr_get_service_proxies() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(MockCliSvcProxyVisitor::new())));

        let service_proxies = service_mgr.get_service_proxies();

        assert_eq!(service_proxies.len(), 1);
    }

    #[test]
    fn clisvcmgr_get_proxy_visitor_for_service_when_found() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(MockCliSvcProxyVisitor::new())));

        let service_proxy = service_mgr.get_proxy_visitor_for_service(200);

        assert!(service_proxy.is_some());
    }

    #[test]
    fn clisvcmgr_get_proxy_visitor_for_service_when_not_found() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(MockCliSvcProxyVisitor::new())));

        let service_proxy = service_mgr.get_proxy_visitor_for_service(201);

        assert!(service_proxy.is_none());
    }

    #[test]
    fn clisvcmgr_clone_proxy_tasks_sender() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let proxy_tasks_channel = mpsc::channel();
        let service_mgr =
            ClientServiceMgr::new(&app_config, &proxy_tasks_channel.0, &mpsc::channel().0);

        let proxy_tasks_sender = service_mgr.clone_proxy_tasks_sender();
        proxy_tasks_sender
            .send(ProxyExecutorEvent::Close("key1".to_string()))
            .unwrap();

        match proxy_tasks_channel.1.try_recv() {
            Ok(event) => match event {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key1".to_string()),
                ProxyExecutorEvent::OpenChannelAndTcpProxy(_, _) => {
                    panic!("Unexpected open channel&tcp proxy event")
                }
                ProxyExecutorEvent::OpenTcpAndTcpProxy(_, _) => {
                    panic!("Unexpected open tcp&tcp proxy event")
                }
                ProxyExecutorEvent::OpenTcpAndUdpProxy(_, _) => {
                    panic!("Unexpected open tcp&udp proxy event")
                }
            },
            Err(err) => panic!("Unexpected receive channel result: err={:?}", &err),
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
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
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
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
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
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
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
    fn clisvcmgr_shutdown_when_all_services_and_2_service_proxies() {
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
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr.testing_mode = true;
        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(proxy_visitor200)));
        service_mgr
            .service_proxy_visitors
            .insert(201, Arc::new(Mutex::new(proxy_visitor201)));

        if let Err(err) = service_mgr.shutdown(None) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(service_mgr.service_proxy_visitors.is_empty());
    }

    #[test]
    fn clisvcmgr_shutdown_when_one_service() {
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
        proxy_visitor201.expect_set_shutdown_requested().never();
        proxy_visitor201.expect_shutdown_connections().never();

        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);
        service_mgr.testing_mode = true;
        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(proxy_visitor200)));
        service_mgr
            .service_proxy_visitors
            .insert(201, Arc::new(Mutex::new(proxy_visitor201)));

        if let Err(err) = service_mgr.shutdown(Some(200)) {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(service_mgr.service_proxy_visitors.len(), 1);
        assert!(service_mgr.service_proxy_visitors.contains_key(&201));
    }

    #[test]
    fn gwsvcmgr_shutdown_connection_when_proxy_shutdown_succeeds() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());

        let mut proxy200_visitor = MockCliSvcProxyVisitor::new();
        proxy200_visitor
            .expect_shutdown_connection()
            .with(predicate::always(), predicate::eq("key1".to_string()))
            .times(1)
            .return_once(move |_, _| Ok(()));
        let mut proxy201_visitor = MockCliSvcProxyVisitor::new();
        proxy201_visitor.expect_shutdown_connection().never();

        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);

        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(proxy200_visitor)));
        service_mgr
            .service_proxy_visitors
            .insert(201, Arc::new(Mutex::new(proxy201_visitor)));

        let result = service_mgr.shutdown_connection(200, "key1");

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn gwsvcmgr_shutdown_connection_when_proxy_shutdown_fails() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());

        let mut proxy200_visitor = MockCliSvcProxyVisitor::new();
        proxy200_visitor
            .expect_shutdown_connection()
            .with(predicate::always(), predicate::eq("key1".to_string()))
            .times(1)
            .return_once(move |_, _| Err(AppError::General("shutdown failed".to_string())));
        let mut proxy201_visitor = MockCliSvcProxyVisitor::new();
        proxy201_visitor.expect_shutdown_connection().never();

        let mut service_mgr =
            ClientServiceMgr::new(&app_config, &mpsc::channel().0, &mpsc::channel().0);

        service_mgr
            .service_proxy_visitors
            .insert(200, Arc::new(Mutex::new(proxy200_visitor)));
        service_mgr
            .service_proxy_visitors
            .insert(201, Arc::new(Mutex::new(proxy201_visitor)));

        let result = service_mgr.shutdown_connection(200, "key1");

        if result.is_ok() {
            panic!("Unexpected successful result");
        }
    }
}
