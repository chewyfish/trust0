use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use trust0_common::control::tls::message::ConnectionAddrs;

use crate::config::AppConfig;
use crate::service::proxy::proxy_base::{ClientServiceProxy, ClientServiceProxyVisitor};
use crate::service::proxy::proxy_client::ClientVisitor;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::net::stream_utils;
use trust0_common::net::tcp_server::{conn_std, server_std};
use trust0_common::net::tls_client::client_std;
use trust0_common::net::tls_client::conn_std::TlsClientConnection;
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::{ProxyExecutorEvent, ProxyKey};
use trust0_common::proxy::proxy_base::ProxyType;
use trust0_common::sync;

/// Client service proxy (TCP service client <-> TCP trust0 client)
pub struct TcpClientProxy {
    /// TCP server for accepting client connections
    tcp_server: server_std::Server,
    /// Visitor pattern for TCP server class
    _server_visitor: Arc<Mutex<TcpClientProxyServerVisitor>>,
}

impl TcpClientProxy {
    /// TcpClientProxy constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `server_visitor` - Visitor pattern for TCP server class
    /// * `proxy_port` - Server listening port
    ///
    /// # Returns
    ///
    /// A newly constructed [`TcpClientProxy`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        server_visitor: Arc<Mutex<TcpClientProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Self {
        Self {
            tcp_server: server_std::Server::new(
                server_visitor.clone(),
                &app_config.client_host,
                proxy_port,
            ),
            _server_visitor: server_visitor,
        }
    }
}

impl ClientServiceProxy for TcpClientProxy {
    fn startup(&mut self) -> Result<(), AppError> {
        self.tcp_server.bind_listener()?;
        self.tcp_server.poll_new_connections()
    }
}

unsafe impl Send for TcpClientProxy {}

/// tcp_server::server_std::Server strategy visitor pattern implementation
pub struct TcpClientProxyServerVisitor {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Service model object corresponding to proxy
    service: Service,
    /// Client proxy server listening port
    client_proxy_port: u16,
    /// Gateway proxy host
    gateway_proxy_host: String,
    /// Gateway proxy port
    gateway_proxy_port: u16,
    /// Channel sender for executor events
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    /// Channel sender for proxy-related events
    proxy_events_sender: Sender<ProxyEvent>,
    /// Map of services by proxy key (shared across service proxies)
    services_by_proxy_key: Arc<Mutex<HashMap<String, i64>>>,
    /// Map of proxy addresses by proxy key
    proxy_addrs_by_proxy_key: HashMap<ProxyKey, ConnectionAddrs>,
    /// State to control proxy shutdown
    shutdown_requested: bool,
}

impl TcpClientProxyServerVisitor {
    #![allow(clippy::too_many_arguments)]
    /// TcpClientProxyServerVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service` - Service model object corresponding to proxy
    /// * `client_proxy_port` - Client proxy server listening port
    /// * `gateway_proxy_host` - Gateway proxy host
    /// * `gateway_proxy_port` - Gateway proxy port
    /// * `proxy_tasks_sender` - Channel sender for executor events
    /// * `proxy_events_sender` - Channel sender for proxy-related events
    /// * `services_by_proxy_key` - Map of services by proxy key (shared across service proxies)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`TcpClientProxyServerVisitor`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service: &Service,
        client_proxy_port: u16,
        gateway_proxy_host: &str,
        gateway_proxy_port: u16,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        proxy_events_sender: &Sender<ProxyEvent>,
        services_by_proxy_key: &Arc<Mutex<HashMap<String, i64>>>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port,
            gateway_proxy_host: gateway_proxy_host.to_string(),
            gateway_proxy_port,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: proxy_events_sender.clone(),
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        })
    }
}

impl server_std::ServerVisitor for TcpClientProxyServerVisitor {
    fn create_client_conn(
        &mut self,
        tcp_stream: TcpStream,
    ) -> Result<conn_std::Connection, AppError> {
        let conn_visitor = ClientConnVisitor::new()?;

        let connection = conn_std::Connection::new(Box::new(conn_visitor), tcp_stream)?;

        Ok(connection)
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        // Make connection to gateway proxy

        let mut tls_client_config = self.app_config.tls_client_config.clone();
        tls_client_config.alpn_protocols =
            vec![alpn::Protocol::create_service_protocol(self.service.service_id).into_bytes()];

        let mut tls_client = client_std::Client::new(
            Box::new(ClientVisitor::new()),
            tls_client_config,
            &self.gateway_proxy_host,
            self.gateway_proxy_port,
            true,
        );

        tls_client.connect()?;

        let tls_client_conn = tls_client.get_connection().as_ref().unwrap();

        let gateway_stream = stream_utils::clone_std_tcp_stream(
            tls_client_conn.get_tcp_stream(),
            "tcp-proxy-server",
        )?;

        // Send request to proxy executor to startup new proxy

        let tcp_stream = connection.get_tcp_stream_as_ref();
        let proxy_key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &tcp_stream.peer_addr().ok(),
            &tcp_stream.local_addr().ok(),
        );
        let client_stream = stream_utils::clone_std_tcp_stream(tcp_stream, "tcp-proxy-server")?;

        let proxy_conn_addrs = tls_client_conn.get_session_addrs().clone();

        let open_proxy_request = ProxyExecutorEvent::OpenTcpAndTcpProxy(
            proxy_key.clone(),
            (
                client_stream,
                gateway_stream,
                Arc::new(Mutex::new(Box::<TcpStream>::new(connection.into()))),
                Arc::new(Mutex::new(Box::<TlsClientConnection>::new(
                    tls_client.into(),
                ))),
                self.proxy_events_sender.clone(),
            ),
        );

        let proxy_key_copy = proxy_key.clone();
        sync::send_mpsc_channel_message(
            &self.proxy_tasks_sender,
            open_proxy_request,
            Box::new(move || {
                format!(
                    "Error while sending request for new TCP proxy: proxy_key={},",
                    &proxy_key_copy
                )
            }),
        )?;

        // Setup proxy maps

        self.services_by_proxy_key
            .lock()
            .unwrap()
            .insert(proxy_key.clone(), self.service.service_id);

        self.proxy_addrs_by_proxy_key
            .insert(proxy_key, proxy_conn_addrs.clone());

        Ok(())
    }

    fn get_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

impl ClientServiceProxyVisitor for TcpClientProxyServerVisitor {
    fn get_service(&self) -> Service {
        self.service.clone()
    }

    fn get_client_proxy_port(&self) -> u16 {
        self.client_proxy_port
    }

    fn get_gateway_proxy_host(&self) -> &str {
        &self.gateway_proxy_host
    }

    fn get_gateway_proxy_port(&self) -> u16 {
        self.gateway_proxy_port
    }

    fn get_proxy_keys(&self) -> Vec<(String, ConnectionAddrs)> {
        self.proxy_addrs_by_proxy_key
            .iter()
            .map(|(key, addrs)| (key.clone(), addrs.clone()))
            .collect()
    }

    fn set_shutdown_requested(&mut self) {
        self.shutdown_requested = true;
    }

    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
    ) -> Result<(), AppError> {
        let mut errors: Vec<String> = vec![];

        for proxy_key in self.proxy_addrs_by_proxy_key.keys() {
            let proxy_key_copy = proxy_key.clone();
            if let Err(err) = sync::send_mpsc_channel_message(
                proxy_tasks_sender,
                ProxyExecutorEvent::Close(proxy_key.clone()),
                Box::new(move || {
                    format!("Error while sending request to close a TCP proxy connection: proxy_stream={},", &proxy_key_copy)
                }),
            ) {
                errors.push(format!("{:?}", err));
            }

            self.services_by_proxy_key.lock().unwrap().remove(proxy_key);
        }

        if errors.is_empty() {
            self.proxy_addrs_by_proxy_key.clear();
        } else {
            return Err(AppError::General(format!(
                "Errors closing proxy connection(s), err={}",
                errors.join(", ")
            )));
        }

        Ok(())
    }

    fn shutdown_connection(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        proxy_key: &str,
    ) -> Result<(), AppError> {
        let proxy_key_copy = proxy_key.to_string();
        sync::send_mpsc_channel_message(
            proxy_tasks_sender,
            ProxyExecutorEvent::Close(proxy_key.to_string()),
            Box::new(move || {
                format!(
                    "Error while sending request to close a TCP proxy connection: proxy_stream={},",
                    &proxy_key_copy
                )
            }),
        )?;
        self.remove_proxy_for_key(proxy_key);
        Ok(())
    }

    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool {
        return match self.proxy_addrs_by_proxy_key.contains_key(proxy_key) {
            true => {
                self.services_by_proxy_key.lock().unwrap().remove(proxy_key);
                self.proxy_addrs_by_proxy_key.remove(proxy_key);
                true
            }

            false => false,
        };
    }
}

/// tcp_server::std_conn::Connection strategy visitor pattern implementation
pub struct ClientConnVisitor {}

impl ClientConnVisitor {
    /// ClientConnVisitor constructor
    ///
    /// # Returns
    ///
    /// A [`Result`] containin a newly constructed [`ClientConnVisitor`] object.
    ///
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {})
    }
}

impl conn_std::ConnectionVisitor for ClientConnVisitor {
    fn send_error_response(&mut self, _err: &AppError) {}
}

unsafe impl Send for ClientConnVisitor {}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use crate::service::proxy::proxy_base;
    use std::sync;
    use std::sync::mpsc::TryRecvError;
    use trust0_common::model::service::Transport;
    use trust0_common::net::stream_utils;
    use trust0_common::net::tcp_server::conn_std::ConnectionVisitor;
    use trust0_common::net::tcp_server::server_std::ServerVisitor;

    #[test]
    fn tcpcliproxy_new() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let server_visitor = Arc::new(Mutex::new(TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        }));

        let _ = TcpClientProxy::new(&app_config, server_visitor, 3000);
    }

    #[test]
    fn tcpsvrproxyvisit_new() {
        let server_visitor = TcpClientProxyServerVisitor::new(
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            3000,
            "gwhost1",
            2000,
            &sync::mpsc::channel().0,
            &sync::mpsc::channel().0,
            &Arc::new(Mutex::new(HashMap::new())),
        );

        assert!(server_visitor.is_ok());
    }

    #[test]
    fn tcpsvrproxyvisit_create_client_conn() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        };

        if let Err(err) = server_visitor.create_client_conn(
            stream_utils::clone_std_tcp_stream(
                &connected_tcp_stream.server_stream.0,
                "test-tcp-proxy-server",
            )
            .unwrap(),
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn tcpsvrproxyvisit_on_conn_accepted() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let (proxy_events_sender, proxy_events_receiver) = sync::mpsc::channel();
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::new()));

        let tcp_listener = std::net::TcpListener::bind("localhost:0").unwrap();
        let gateway_proxy_port = tcp_listener.local_addr().unwrap().port();
        let tls_server_config = Arc::new(
            proxy_base::tests::create_tls_server_config(vec![
                alpn::Protocol::create_service_protocol(200).into_bytes(),
            ])
            .unwrap(),
        );
        proxy_base::tests::spawn_tls_server_listener(tcp_listener, tls_server_config, 1).unwrap();

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "localhost".to_string(),
                port: 4000,
            },
            client_proxy_port: 3000,
            gateway_proxy_host: "localhost".to_string(),
            gateway_proxy_port,
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        };

        let client_conn = server_visitor
            .create_client_conn(
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.client_stream.0,
                    "test-proxy-client",
                )
                .unwrap(),
            )
            .unwrap();

        if let Err(err) = server_visitor.on_conn_accepted(client_conn) {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_proxy_key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &connected_tcp_stream.client_stream.0.peer_addr().ok(),
            &connected_tcp_stream.client_stream.0.local_addr().ok(),
        );

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::OpenTcpAndTcpProxy(proxy_key, _) => {
                    assert_eq!(
                        proxy_key, expected_proxy_key,
                        "Received proxy task mismatch: act-key={}, exp-key={}",
                        &proxy_key, &expected_proxy_key
                    );
                }
                ProxyExecutorEvent::Close(key) => {
                    panic!("Unexpected received close proxy task: key={:?}", &key)
                }
                ProxyExecutorEvent::OpenChannelAndTcpProxy(key, _) => panic!(
                    "Unexpected received open channel&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndUdpProxy(key, _) => panic!(
                    "Unexpected received open tcp&udp proxy task: key={:?}",
                    &key
                ),
            },
            Err(err) => panic!("Unexpected received proxy task error: err={:?}", &err),
        }

        match proxy_events_receiver.try_recv() {
            Ok(proxy_event) => panic!("Unexpected received proxy event: event={:?}", &proxy_event),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected received disconnected proxy event result: err={:?}",
                &err
            ),
            _ => {}
        }

        assert!(services_by_proxy_key
            .lock()
            .unwrap()
            .contains_key(&expected_proxy_key));
        assert_eq!(
            *services_by_proxy_key
                .lock()
                .unwrap()
                .get(&expected_proxy_key)
                .unwrap(),
            200
        );
        assert!(server_visitor
            .proxy_addrs_by_proxy_key
            .contains_key(&expected_proxy_key));
    }

    #[test]
    fn tcpsvrproxyvisit_accessors_and_mutators() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        };

        assert!(!server_visitor.get_shutdown_requested());
        server_visitor.set_shutdown_requested();
        assert!(server_visitor.get_shutdown_requested());
        assert_eq!(server_visitor.get_service(), service);
        assert_eq!(server_visitor.get_client_proxy_port(), 3000);
        assert_eq!(server_visitor.get_gateway_proxy_host(), "gwhost1");
        assert_eq!(server_visitor.get_gateway_proxy_port(), 2000);
    }

    #[test]
    fn tcpsvrproxyvisit_shutdown_connections() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::from([(
                "key1".to_string(),
                ("addr1".to_string(), "addr2".to_string()),
            )]),
            shutdown_requested: false,
        };

        if let Err(err) = server_visitor.shutdown_connections(&proxy_tasks_sender) {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key1".to_string()),
                ProxyExecutorEvent::OpenTcpAndTcpProxy(key, _) => panic!(
                    "Unexpected received open tcp&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenChannelAndTcpProxy(key, _) => panic!(
                    "Unexpected received open channel&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndUdpProxy(key, _) => panic!(
                    "Unexpected received open tcp&udp proxy task: key={:?}",
                    &key
                ),
            },
            Err(err) => panic!("Unexpected received proxy task error: err={:?}", &err),
        }

        assert!(services_by_proxy_key.lock().unwrap().is_empty());
        assert!(server_visitor.proxy_addrs_by_proxy_key.is_empty());
    }

    #[test]
    fn tcpsvrproxyvisit_shutdown_connection_when_proxy_key_known() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::from([(
                "key1".to_string(),
                ("addr1".to_string(), "addr2".to_string()),
            )]),
            shutdown_requested: false,
        };

        if let Err(err) = server_visitor.shutdown_connection(&proxy_tasks_sender, "key1") {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key1".to_string()),
                ProxyExecutorEvent::OpenTcpAndTcpProxy(key, _) => panic!(
                    "Unexpected received open tcp&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenChannelAndTcpProxy(key, _) => panic!(
                    "Unexpected received open channel&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndUdpProxy(key, _) => panic!(
                    "Unexpected received open tcp&udp proxy task: key={:?}",
                    &key
                ),
            },
            Err(err) => panic!("Unexpected received proxy task error: err={:?}", &err),
        }

        assert!(services_by_proxy_key.lock().unwrap().is_empty());
        assert!(server_visitor.proxy_addrs_by_proxy_key.is_empty());
    }

    #[test]
    fn tcpsvrproxyvisit_shutdown_connection_when_proxy_key_unknown() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::from([(
                "key1".to_string(),
                ("addr1".to_string(), "addr2".to_string()),
            )]),
            shutdown_requested: false,
        };

        if let Err(err) = server_visitor.shutdown_connection(&proxy_tasks_sender, "key2") {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key2".to_string()),
                ProxyExecutorEvent::OpenTcpAndTcpProxy(key, _) => panic!(
                    "Unexpected received open tcp&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenChannelAndTcpProxy(key, _) => panic!(
                    "Unexpected received open channel&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndUdpProxy(key, _) => panic!(
                    "Unexpected received open tcp&udp proxy task: key={:?}",
                    &key
                ),
            },
            Err(err) => panic!("Unexpected received proxy task error: err={:?}", &err),
        }

        assert_eq!(services_by_proxy_key.lock().unwrap().len(), 1);
        assert!(services_by_proxy_key.lock().unwrap().contains_key("key1"));
        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
        assert!(server_visitor.proxy_addrs_by_proxy_key.contains_key("key1"));
    }

    #[test]
    fn tcpsvrproxyvisit_shutdown_connection_when_sending_fails() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: Service::default(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::from([(
                "key1".to_string(),
                ("addr1".to_string(), "addr2".to_string()),
            )]),
            shutdown_requested: false,
        };

        let proxy_tasks_sender = sync::mpsc::channel().0;

        if server_visitor
            .shutdown_connection(&proxy_tasks_sender, "key1")
            .is_ok()
        {
            panic!("Unexpected successful result");
        }

        assert_eq!(services_by_proxy_key.lock().unwrap().len(), 1);
        assert!(services_by_proxy_key.lock().unwrap().contains_key("key1"));
        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
        assert!(server_visitor.proxy_addrs_by_proxy_key.contains_key("key1"));
    }

    #[test]
    fn tcpsvrproxyvisit_remove_proxy_for_key_when_not_exists() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::from([
            ("key1".to_string(), 200),
            ("key2".to_string(), 201),
        ])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::from([(
                "key2".to_string(),
                ("addr1".to_string(), "addr2".to_string()),
            )]),
            shutdown_requested: false,
        };

        assert!(!server_visitor.remove_proxy_for_key("key1"));

        assert!(services_by_proxy_key.lock().unwrap().contains_key("key1"));
        assert_eq!(services_by_proxy_key.lock().unwrap().len(), 2);
        assert!(server_visitor.proxy_addrs_by_proxy_key.contains_key("key2"));
        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
    }

    #[test]
    fn tcpsvrproxyvisit_remove_proxy_for_key_when_exists() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::from([
            ("key1".to_string(), 200),
            ("key2".to_string(), 201),
        ])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = TcpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: service.clone(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: services_by_proxy_key.clone(),
            proxy_addrs_by_proxy_key: HashMap::from([
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string()),
                ),
                (
                    "key3".to_string(),
                    ("addr5".to_string(), "addr6".to_string()),
                ),
            ]),
            shutdown_requested: false,
        };

        assert!(server_visitor.remove_proxy_for_key("key2"));

        assert!(!services_by_proxy_key.lock().unwrap().contains_key("key2"));
        assert_eq!(services_by_proxy_key.lock().unwrap().len(), 1);
        assert!(!server_visitor.proxy_addrs_by_proxy_key.contains_key("key2"));
        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
    }

    #[test]
    fn tcpsvrproxyvisit_get_proxy_keys() {
        let server_visitor = TcpClientProxyServerVisitor {
            app_config: Arc::new(config::tests::create_app_config(None).unwrap()),
            service: Service::default(),
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            proxy_addrs_by_proxy_key: HashMap::from([
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string()),
                ),
                (
                    "key3".to_string(),
                    ("addr5".to_string(), "addr6".to_string()),
                ),
            ]),
            shutdown_requested: false,
        };

        let expected_proxy_keys = vec![
            (
                "key2".to_string(),
                ("addr3".to_string(), "addr4".to_string()),
            ),
            (
                "key3".to_string(),
                ("addr5".to_string(), "addr6".to_string()),
            ),
        ];

        let mut proxy_keys = server_visitor.get_proxy_keys();
        proxy_keys.sort();

        assert_eq!(proxy_keys, expected_proxy_keys);
    }

    #[test]
    fn cliconnvisit_new() {
        let visitor = ClientConnVisitor::new();
        assert!(visitor.is_ok());
    }

    #[test]
    fn cliconnvisit_send_error_response() {
        let mut visitor = ClientConnVisitor {};
        visitor.send_error_response(&AppError::StreamEOF);
    }
}
