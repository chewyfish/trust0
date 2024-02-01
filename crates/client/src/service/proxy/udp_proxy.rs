use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::Result;

use crate::config::AppConfig;
use crate::service::proxy::proxy_base::{
    ClientServiceProxy, ClientServiceProxyVisitor, ProxyConnAddrs,
};
use crate::service::proxy::proxy_client::ClientVisitor;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::model::service::Service;
use trust0_common::net::tls_client::client_std;
use trust0_common::net::tls_client::conn_std::TlsClientConnection;
use trust0_common::net::udp_server::server_std;
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::{ProxyExecutorEvent, ProxyKey};
use trust0_common::proxy::proxy_base::ProxyType;
use trust0_common::target;

/// Client service proxy (UDP service client <-> TCP trust0 client)
pub struct UdpClientProxy {
    udp_server: server_std::Server,
    server_socket_channel_receiver: Arc<Mutex<Receiver<ProxyEvent>>>,
    _server_visitor: Arc<Mutex<UdpClientProxyServerVisitor>>,
}

impl UdpClientProxy {
    /// UdpClientProxy constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        server_socket_channel_receiver: Receiver<ProxyEvent>,
        server_visitor: Arc<Mutex<UdpClientProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Result<Self, AppError> {
        Ok(Self {
            udp_server: server_std::Server::new(
                server_visitor.clone(),
                &app_config.client_host,
                proxy_port,
            )?,
            server_socket_channel_receiver: Arc::new(Mutex::new(server_socket_channel_receiver)),
            _server_visitor: server_visitor,
        })
    }

    /// Startup client-bound message processor thread
    fn spawn_client_bound_message_processor(&self, server_socket: UdpSocket) {
        let server_socket_channel_receiver = self.server_socket_channel_receiver.clone();

        thread::spawn(move || loop {
            match server_socket_channel_receiver.lock().unwrap().recv() {
                Err(err) => error(
                    &target!(),
                    &format!("Error receiving socket event: err={:?}", err),
                ),

                Ok(proxy_event) => {
                    if let ProxyEvent::Message(proxy_key, socket_addr, data) = proxy_event {
                        if let Err(err) =
                            server_std::Server::send_message(&server_socket, &socket_addr, &data)
                        {
                            error(
                                &target!(),
                                &format!(
                                    "Error processing message channel: proxy_stream={}, err={:?}",
                                    &proxy_key, &err
                                ),
                            );
                        }
                    }
                }
            }
        });
    }
}

impl ClientServiceProxy for UdpClientProxy {
    fn startup(&mut self) -> Result<(), AppError> {
        // bind UDP (server) socket
        self.udp_server.bind_listener()?;

        // Start thread to listen/relay client-destined messages
        self.spawn_client_bound_message_processor(self.udp_server.clone_server_socket()?);

        // Poll for new service-destined messages (blocking)
        self.udp_server.poll_new_messages()
    }
}

unsafe impl Send for UdpClientProxy {}

/// udp_server::server_std::Server strategy visitor pattern implementation
pub struct UdpClientProxyServerVisitor {
    app_config: Arc<AppConfig>,
    service: Service,
    client_proxy_port: u16,
    gateway_proxy_host: String,
    gateway_proxy_port: u16,
    server_socket_channel_sender: Sender<ProxyEvent>,
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    proxy_events_sender: Sender<ProxyEvent>,
    services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>,
    socket_channel_senders_by_proxy_key: HashMap<String, Sender<ProxyEvent>>,
    proxy_addrs_by_proxy_key: HashMap<ProxyKey, ProxyConnAddrs>,
    shutdown_requested: bool,
}

impl UdpClientProxyServerVisitor {
    #![allow(clippy::too_many_arguments)]
    /// UdpClientProxyServerVisitor constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        service: Service,
        client_proxy_port: u16,
        gateway_proxy_host: &str,
        gateway_proxy_port: u16,
        server_socket_channel_sender: Sender<ProxyEvent>,
        proxy_tasks_sender: Sender<ProxyExecutorEvent>,
        proxy_events_sender: Sender<ProxyEvent>,
        services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            app_config,
            service,
            client_proxy_port,
            gateway_proxy_host: gateway_proxy_host.to_string(),
            gateway_proxy_port,
            server_socket_channel_sender,
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key,
            socket_channel_senders_by_proxy_key: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        })
    }

    /// Stringified tuple client and gateway connection addresses
    ///
    /// # Arguments
    ///
    /// * `gateway_stream` - TCP stream for gateway proxy TLS client connection
    ///
    /// # Returns
    ///
    /// A [`ProxyConnAddrs`] object corresponding to connection socket address pair (local, peer).
    ///
    fn create_proxy_addrs(gateway_stream: &TcpStream) -> ProxyConnAddrs {
        let local_addr = match gateway_stream.local_addr() {
            Ok(addr) => format!("{:?}", addr),
            Err(_) => "(NA)".to_string(),
        };
        let peer_addr = match gateway_stream.peer_addr() {
            Ok(addr) => format!("{:?}", addr),
            Err(_) => "(NA)".to_string(),
        };

        (local_addr, peer_addr)
    }
}

impl server_std::ServerVisitor for UdpClientProxyServerVisitor {
    fn on_message_received(
        &mut self,
        local_addr: &SocketAddr,
        peer_addr: &SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), AppError> {
        let proxy_key = ProxyEvent::key_value(
            &ProxyType::ChannelAndTcp,
            Some(*peer_addr),
            Some(*local_addr),
        );

        // New client socket, setup service proxy
        // - - - - - - - - - - - - - - - - - - -
        if !self
            .socket_channel_senders_by_proxy_key
            .contains_key(&proxy_key)
        {
            let (socket_channel_sender, socket_channel_receiver) = mpsc::channel();

            // Make connection to gateway proxy
            let mut tls_client_config = self.app_config.tls_client_config.clone();
            tls_client_config.alpn_protocols =
                vec![alpn::Protocol::create_service_protocol(self.service.service_id).into_bytes()];

            let mut tls_client = client_std::Client::new(
                Box::new(ClientVisitor::new()),
                tls_client_config,
                self.gateway_proxy_host.clone(),
                self.gateway_proxy_port,
            );

            tls_client.connect()?;

            let gateway_stream = tls_client
                .get_connection()
                .as_ref()
                .unwrap()
                .get_tcp_stream()
                .try_clone()
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Error trying to clone gateway proxy TLS stream".to_string(),
                        Box::new(err),
                    )
                })?;

            let proxy_conn_addrs = UdpClientProxyServerVisitor::create_proxy_addrs(&gateway_stream);

            // Send request to proxy executor to startup new proxy
            let open_proxy_request = ProxyExecutorEvent::OpenChannelAndTcpProxy(
                proxy_key.clone(),
                (
                    *peer_addr,
                    socket_channel_receiver,
                    self.server_socket_channel_sender.clone(),
                    gateway_stream,
                    Arc::new(Mutex::new(Box::<TlsClientConnection>::new(
                        tls_client.into(),
                    ))),
                    self.proxy_events_sender.clone(),
                ),
            );

            self.proxy_tasks_sender
                .send(open_proxy_request)
                .map_err(|err| {
                    AppError::General(format!(
                        "Error while sending request for new UDP proxy: proxy_key={}, err={:?}",
                        &proxy_key, &err
                    ))
                })?;

            // Setup proxy maps
            self.socket_channel_senders_by_proxy_key
                .insert(proxy_key.clone(), socket_channel_sender);
            self.services_by_proxy_key
                .lock()
                .unwrap()
                .insert(proxy_key.clone(), self.service.service_id);
            self.proxy_addrs_by_proxy_key
                .insert(proxy_key.clone(), proxy_conn_addrs);
        }

        // Send service-bound message to appropriate channel
        // - - - - - - - - - - - - - - - - - - - - - - - - -
        if let Some(socket_channel_sender) =
            self.socket_channel_senders_by_proxy_key.get(&proxy_key)
        {
            return match socket_channel_sender.send(ProxyEvent::Message(
                proxy_key.clone(),
                *peer_addr,
                data,
            )) {
                Ok(()) => Ok(()),
                Err(err) => Err(AppError::GenWithMsgAndErr(
                    format!(
                        "Error while sending message to socket channel: proxy_stream={}",
                        &proxy_key
                    ),
                    Box::new(err),
                )),
            };
        }
        Ok(())
    }

    fn get_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

impl ClientServiceProxyVisitor for UdpClientProxyServerVisitor {
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

    fn get_proxy_keys(&self) -> Vec<(String, ProxyConnAddrs)> {
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
            if let Err(err) = proxy_tasks_sender.send(ProxyExecutorEvent::Close(proxy_key.clone()))
            {
                errors.push(format!("Error while sending request to close a UDP proxy connection: proxy_stream={}, err={:?}", &proxy_key, err));
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
        if let Err(err) = proxy_tasks_sender.send(ProxyExecutorEvent::Close(proxy_key.to_string()))
        {
            Err(AppError::General(
                format!("Error while sending request to close a UDP proxy connection: proxy_stream={}, err={:?}", &proxy_key, &err)))
        } else {
            self.remove_proxy_for_key(proxy_key);
            Ok(())
        }
    }

    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool {
        let proxy_key = proxy_key.to_string();

        return match self.proxy_addrs_by_proxy_key.contains_key(&proxy_key) {
            true => {
                self.services_by_proxy_key
                    .lock()
                    .unwrap()
                    .remove(&proxy_key);
                self.proxy_addrs_by_proxy_key.remove(&proxy_key);
                true
            }

            false => false,
        };
    }
}

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
    use trust0_common::net::udp_server::server_std::ServerVisitor;

    #[test]
    fn udpcliproxy_new() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let server_visitor = Arc::new(Mutex::new(UdpClientProxyServerVisitor {
            app_config: app_config.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::UDP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            client_proxy_port: 3000,
            gateway_proxy_host: "gwhost1".to_string(),
            gateway_proxy_port: 2000,
            server_socket_channel_sender: mpsc::channel().0,
            proxy_tasks_sender: mpsc::channel().0,
            proxy_events_sender: mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            socket_channel_senders_by_proxy_key: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        }));

        let _ = UdpClientProxy::new(app_config, mpsc::channel().1, server_visitor, 3000);
    }

    #[test]
    fn udpsvrproxyvisit_new() {
        let server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::UDP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            mpsc::channel().0,
            mpsc::channel().0,
            Arc::new(Mutex::new(HashMap::new())),
        );

        assert!(server_visitor.is_ok());
    }

    #[test]
    fn tcpsvrproxyvisit_create_proxy_addrs() {
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let connected_tcp_local_addr = connected_tcp_stream.client_stream.0.local_addr().unwrap();
        let connected_tcp_peer_addr = connected_tcp_stream.client_stream.0.peer_addr().unwrap();

        let expected_proxy_addrs = (
            format!("{:?}", connected_tcp_local_addr),
            format!("{:?}", connected_tcp_peer_addr),
        );

        let proxy_addrs =
            UdpClientProxyServerVisitor::create_proxy_addrs(&connected_tcp_stream.client_stream.0);

        assert_eq!(proxy_addrs, expected_proxy_addrs);
    }

    #[test]
    fn udpsvrproxyvisit_on_message_received_when_new_service_proxy_needed() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let (proxy_tasks_sender, proxy_tasks_receiver) = mpsc::channel();
        let (proxy_events_sender, proxy_events_receiver) = mpsc::channel();
        let connected_udp_stream = stream_utils::ConnectedUdpSocket::new().unwrap();
        let connected_udp_local_addr = connected_udp_stream.server_socket.0.local_addr().unwrap();
        let connected_udp_peer_addr = connected_udp_stream.client_socket.0.local_addr().unwrap();
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::new()));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };
        let expected_proxy_key = ProxyEvent::key_value(
            &ProxyType::ChannelAndTcp,
            Some(connected_udp_peer_addr.clone()),
            Some(connected_udp_local_addr.clone()),
        );
        let expected_msg_data = "data1".as_bytes().to_vec();

        let tcp_listener = std::net::TcpListener::bind("localhost:0").unwrap();
        let gateway_proxy_port = tcp_listener.local_addr().unwrap().port();
        let tls_server_config = Arc::new(
            proxy_base::tests::create_tls_server_config(vec![
                alpn::Protocol::create_service_protocol(200).into_bytes(),
            ])
            .unwrap(),
        );
        proxy_base::tests::spawn_tls_server_listener(tcp_listener, tls_server_config, 1).unwrap();

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(app_config),
            service.clone(),
            3000,
            "localhost",
            gateway_proxy_port,
            mpsc::channel().0,
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key.clone(),
        )
        .unwrap();

        if let Err(err) = server_visitor.on_message_received(
            &connected_udp_local_addr,
            &connected_udp_peer_addr,
            expected_msg_data.clone(),
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }

        let socket_channel_receiver = match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::OpenChannelAndTcpProxy(proxy_key, proxy_context) => {
                    assert_eq!(
                        proxy_key, expected_proxy_key,
                        "Received proxy task mismatch: act-key={}, exp-key={}",
                        &proxy_key, &expected_proxy_key
                    );
                    proxy_context.1
                }
                ProxyExecutorEvent::Close(key) => {
                    panic!("Unexpected received close proxy task: key={:?}", &key)
                }
                ProxyExecutorEvent::OpenTcpAndTcpProxy(key, _) => panic!(
                    "Unexpected received open tcp&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndUdpProxy(key, _) => panic!(
                    "Unexpected received open tcp&udp proxy task: key={:?}",
                    &key
                ),
            },
            Err(err) => panic!("Unexpected received proxy task error: err={:?}", &err),
        };

        match proxy_events_receiver.try_recv() {
            Ok(proxy_event) => panic!("Unexpected received proxy event: event={:?}", &proxy_event),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected received disconnected proxy event result: err={:?}",
                &err
            ),
            _ => {}
        }

        match socket_channel_receiver.try_recv() {
            Ok(proxy_event) => {
                match proxy_event {
                    ProxyEvent::Message(proxy_key, peer_addr, data) => {
                        assert_eq!(
                            proxy_key, expected_proxy_key,
                            "Received socket channel proxy event mismatch: act-key={}, exp-key={}",
                            &proxy_key, &expected_proxy_key
                        );
                        assert_eq!(peer_addr, connected_udp_peer_addr,
                               "Received socket channel proxy event mismatch: act-addr={}, exp-addr={}", &peer_addr, &connected_udp_peer_addr);
                        assert_eq!(data, expected_msg_data,
                               "Received socket channel proxy event mismatch: act-data={:?}, exp-data={:?}", &data, &expected_msg_data);
                    }
                    ProxyEvent::Closed(msg) => panic!(
                        "Unexpected received closed socket channel proxy event: msg={}",
                        &msg
                    ),
                }
            }
            Err(err) => panic!("Unexpected received socket channel error: err={:?}", &err),
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
            .socket_channel_senders_by_proxy_key
            .contains_key(&expected_proxy_key));
        assert!(server_visitor
            .proxy_addrs_by_proxy_key
            .contains_key(&expected_proxy_key));
    }

    #[test]
    fn udpsvrproxyvisit_on_message_received_when_new_service_proxy_not_needed() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let (proxy_tasks_sender, proxy_tasks_receiver) = mpsc::channel();
        let (proxy_events_sender, proxy_events_receiver) = mpsc::channel();
        let (socket_channel_sender, socket_channel_receiver) = mpsc::channel();
        let connected_udp_stream = stream_utils::ConnectedUdpSocket::new().unwrap();
        let connected_udp_local_addr = connected_udp_stream.server_socket.0.local_addr().unwrap();
        let connected_udp_peer_addr = connected_udp_stream.client_socket.0.local_addr().unwrap();
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::new()));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };
        let expected_proxy_key = ProxyEvent::key_value(
            &ProxyType::ChannelAndTcp,
            Some(connected_udp_peer_addr.clone()),
            Some(connected_udp_local_addr.clone()),
        );
        let expected_msg_data = "data1".as_bytes().to_vec();

        let tcp_listener = std::net::TcpListener::bind("localhost:0").unwrap();
        let gateway_proxy_port = tcp_listener.local_addr().unwrap().port();
        let tls_server_config = Arc::new(
            proxy_base::tests::create_tls_server_config(vec![
                alpn::Protocol::create_service_protocol(200).into_bytes(),
            ])
            .unwrap(),
        );
        proxy_base::tests::spawn_tls_server_listener(tcp_listener, tls_server_config, 1).unwrap();

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(app_config),
            service.clone(),
            3000,
            "localhost",
            gateway_proxy_port,
            mpsc::channel().0,
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key.clone(),
        )
        .unwrap();
        server_visitor
            .socket_channel_senders_by_proxy_key
            .insert(expected_proxy_key.clone(), socket_channel_sender);

        if let Err(err) = server_visitor.on_message_received(
            &connected_udp_local_addr,
            &connected_udp_peer_addr,
            expected_msg_data.clone(),
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::Close(key) => {
                    panic!("Unexpected received close proxy task: key={:?}", &key)
                }
                ProxyExecutorEvent::OpenChannelAndTcpProxy(key, _) => panic!(
                    "Unexpected received open channel&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndTcpProxy(key, _) => panic!(
                    "Unexpected received open tcp&tcp proxy task: key={:?}",
                    &key
                ),
                ProxyExecutorEvent::OpenTcpAndUdpProxy(key, _) => panic!(
                    "Unexpected received open tcp&udp proxy task: key={:?}",
                    &key
                ),
            },
            Err(err) if TryRecvError::Disconnected == err => {
                panic!("Unexpected received proxy task error: err={:?}", &err)
            }
            Err(_) => {}
        };

        match proxy_events_receiver.try_recv() {
            Ok(proxy_event) => panic!("Unexpected received proxy event: event={:?}", &proxy_event),
            Err(err) if TryRecvError::Disconnected == err => panic!(
                "Unexpected received disconnected proxy event result: err={:?}",
                &err
            ),
            _ => {}
        }

        match socket_channel_receiver.try_recv() {
            Ok(proxy_event) => {
                match proxy_event {
                    ProxyEvent::Message(proxy_key, peer_addr, data) => {
                        assert_eq!(
                            proxy_key, expected_proxy_key,
                            "Received socket channel proxy event mismatch: act-key={}, exp-key={}",
                            &proxy_key, &expected_proxy_key
                        );
                        assert_eq!(peer_addr, connected_udp_peer_addr,
                               "Received socket channel proxy event mismatch: act-addr={}, exp-addr={}", &peer_addr, &connected_udp_peer_addr);
                        assert_eq!(data, expected_msg_data,
                               "Received socket channel proxy event mismatch: act-data={:?}, exp-data={:?}", &data, &expected_msg_data);
                    }
                    ProxyEvent::Closed(msg) => panic!(
                        "Unexpected received closed socket channel proxy event: msg={}",
                        &msg
                    ),
                }
            }
            Err(err) => panic!("Unexpected received socket channel error: err={:?}", &err),
        }

        assert!(services_by_proxy_key.lock().unwrap().is_empty());
        assert!(server_visitor.proxy_addrs_by_proxy_key.is_empty());
    }

    #[test]
    fn udpsvrproxyvisit_accessors_and_mutators() {
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            service.clone(),
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            mpsc::channel().0,
            mpsc::channel().0,
            Arc::new(Mutex::new(HashMap::new())),
        )
        .unwrap();

        assert!(!server_visitor.shutdown_requested);
        server_visitor.set_shutdown_requested();
        assert!(server_visitor.shutdown_requested);
        assert_eq!(server_visitor.get_service(), service);
        assert_eq!(server_visitor.get_client_proxy_port(), 3000);
        assert_eq!(server_visitor.get_gateway_proxy_host(), "gwhost1");
        assert_eq!(server_visitor.get_gateway_proxy_port(), 2000);
    }

    #[test]
    fn udpsvrproxyvisit_shutdown_connections() {
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            service.clone(),
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            proxy_tasks_sender.clone(),
            mpsc::channel().0,
            services_by_proxy_key.clone(),
        )
        .unwrap();

        server_visitor.proxy_addrs_by_proxy_key = HashMap::from([(
            "key1".to_string(),
            ("addr1".to_string(), "addr2".to_string()),
        )]);

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
    fn udpsvrproxyvisit_shutdown_connection_when_proxy_key_known() {
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            service.clone(),
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            proxy_tasks_sender.clone(),
            mpsc::channel().0,
            services_by_proxy_key.clone(),
        )
        .unwrap();

        server_visitor.proxy_addrs_by_proxy_key = HashMap::from([(
            "key1".to_string(),
            ("addr1".to_string(), "addr2".to_string()),
        )]);

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
    fn udpsvrproxyvisit_shutdown_connection_when_proxy_key_unknown() {
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let services_by_proxy_key =
            Arc::new(Mutex::new(HashMap::from([("key1".to_string(), 200)])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            service.clone(),
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            proxy_tasks_sender.clone(),
            mpsc::channel().0,
            services_by_proxy_key.clone(),
        )
        .unwrap();

        server_visitor.proxy_addrs_by_proxy_key = HashMap::from([(
            "key1".to_string(),
            ("addr1".to_string(), "addr2".to_string()),
        )]);

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
    fn udpsvrproxyvisit_remove_proxy_for_key_when_not_exists() {
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::from([
            ("key1".to_string(), 200),
            ("key2".to_string(), 201),
        ])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            service.clone(),
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            mpsc::channel().0,
            mpsc::channel().0,
            services_by_proxy_key.clone(),
        )
        .unwrap();

        server_visitor.proxy_addrs_by_proxy_key = HashMap::from([(
            "key2".to_string(),
            ("addr1".to_string(), "addr2".to_string()),
        )]);

        assert!(!server_visitor.remove_proxy_for_key("key1"));

        assert!(services_by_proxy_key.lock().unwrap().contains_key("key1"));
        assert_eq!(services_by_proxy_key.lock().unwrap().len(), 2);
        assert!(server_visitor.proxy_addrs_by_proxy_key.contains_key("key2"));
        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
    }

    #[test]
    fn udpsvrproxyvisit_remove_proxy_for_key_when_exists() {
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::from([
            ("key1".to_string(), 200),
            ("key2".to_string(), 201),
        ])));
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::UDP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let mut server_visitor = UdpClientProxyServerVisitor::new(
            Arc::new(config::tests::create_app_config(None).unwrap()),
            service.clone(),
            3000,
            "gwhost1",
            2000,
            mpsc::channel().0,
            mpsc::channel().0,
            mpsc::channel().0,
            services_by_proxy_key.clone(),
        )
        .unwrap();

        server_visitor.proxy_addrs_by_proxy_key = HashMap::from([
            (
                "key2".to_string(),
                ("addr3".to_string(), "addr4".to_string()),
            ),
            (
                "key3".to_string(),
                ("addr5".to_string(), "addr6".to_string()),
            ),
        ]);

        assert!(server_visitor.remove_proxy_for_key("key2"));

        assert!(!services_by_proxy_key.lock().unwrap().contains_key("key2"));
        assert_eq!(services_by_proxy_key.lock().unwrap().len(), 1);
        assert!(!server_visitor.proxy_addrs_by_proxy_key.contains_key("key2"));
        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
    }
}
