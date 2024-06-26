use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::Result;
use trust0_common::control::tls::message::ConnectionAddrs;

use crate::config::AppConfig;
use crate::service::proxy::proxy_base::{ClientServiceProxy, ClientServiceProxyVisitor};
use crate::service::proxy::proxy_client::ClientVisitor;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::model::service::Service;
use trust0_common::net::stream_utils;
use trust0_common::net::tls_client::client_std;
use trust0_common::net::tls_client::conn_std::TlsClientConnection;
use trust0_common::net::udp_server::server_std;
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::{ProxyExecutorEvent, ProxyKey};
use trust0_common::proxy::proxy_base::ProxyType;
use trust0_common::{sync, target};

/// Client service proxy (UDP service client <-> TCP trust0 client)
pub struct UdpClientProxy {
    udp_server: server_std::Server,
    server_socket_channel_receiver: Arc<Mutex<Receiver<ProxyEvent>>>,
    _server_visitor: Arc<Mutex<UdpClientProxyServerVisitor>>,
}

impl UdpClientProxy {
    /// UdpClientProxy constructor
    pub fn new(
        app_config: &Arc<AppConfig>,
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

                Ok(proxy_event) => match proxy_event {
                    ProxyEvent::Message(proxy_key, socket_addr, data) => {
                        if let Err(err) = server_std::Server::send_message(
                            &server_socket,
                            &socket_addr,
                            data.as_slice(),
                        ) {
                            error(
                                &target!(),
                                &format!(
                                    "Error processing message channel: proxy_stream={}, err={:?}",
                                    &proxy_key, &err
                                ),
                            );
                        }
                    }

                    ProxyEvent::Closed(_) => break,
                },
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
    services_by_proxy_key: Arc<Mutex<HashMap<String, i64>>>,
    socket_channel_senders_by_proxy_key: HashMap<String, Sender<ProxyEvent>>,
    proxy_addrs_by_proxy_key: HashMap<ProxyKey, ConnectionAddrs>,
    shutdown_requested: bool,
}

impl UdpClientProxyServerVisitor {
    #![allow(clippy::too_many_arguments)]
    /// UdpClientProxyServerVisitor constructor
    pub fn new(
        app_config: &Arc<AppConfig>,
        service: &Service,
        client_proxy_port: u16,
        gateway_proxy_host: &str,
        gateway_proxy_port: u16,
        server_socket_channel_sender: &Sender<ProxyEvent>,
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
            server_socket_channel_sender: server_socket_channel_sender.clone(),
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: proxy_events_sender.clone(),
            services_by_proxy_key: services_by_proxy_key.clone(),
            socket_channel_senders_by_proxy_key: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            shutdown_requested: false,
        })
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
            &Some(*peer_addr),
            &Some(*local_addr),
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
                &self.gateway_proxy_host,
                self.gateway_proxy_port,
                true,
            );

            tls_client.connect()?;

            let tls_client_conn = tls_client.get_connection().as_ref().unwrap();

            let gateway_stream = stream_utils::clone_std_tcp_stream(
                tls_client_conn.get_tcp_stream(),
                "udp-proxy-server",
            )?;

            let proxy_conn_addrs = tls_client_conn.get_session_addrs().clone();

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

            let proxy_key_copy = proxy_key.clone();
            sync::send_mpsc_channel_message(
                &self.proxy_tasks_sender,
                open_proxy_request,
                Box::new(move || {
                    format!(
                        "Error while sending request for new UDP proxy: proxy_key={},",
                        &proxy_key_copy
                    )
                }),
            )?;

            // Setup proxy maps
            self.socket_channel_senders_by_proxy_key
                .insert(proxy_key.clone(), socket_channel_sender);
            self.services_by_proxy_key
                .lock()
                .unwrap()
                .insert(proxy_key.clone(), self.service.service_id);
            self.proxy_addrs_by_proxy_key
                .insert(proxy_key.clone(), proxy_conn_addrs.clone());
        }

        // Send service-bound message to appropriate channel
        // - - - - - - - - - - - - - - - - - - - - - - - - -
        if let Some(socket_channel_sender) =
            self.socket_channel_senders_by_proxy_key.get(&proxy_key)
        {
            let proxy_key_copy = proxy_key.clone();
            sync::send_mpsc_channel_message(
                socket_channel_sender,
                ProxyEvent::Message(proxy_key.clone(), *peer_addr, data),
                Box::new(move || {
                    format!(
                        "Error while sending message to socket channel: proxy_stream={},",
                        &proxy_key_copy
                    )
                }),
            )
        } else {
            Ok(())
        }
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

    fn get_proxy_keys(&self) -> Vec<(String, ConnectionAddrs)> {
        self.proxy_addrs_by_proxy_key
            .iter()
            .map(|(key, addrs)| (key.clone(), addrs.clone()))
            .collect()
    }

    fn set_shutdown_requested(&mut self) {
        // Shutdown UDP server message poller
        self.shutdown_requested = true;

        // Shutdown client-bound message poller
        if let Err(err) = sync::send_mpsc_channel_message(
            &self.server_socket_channel_sender,
            ProxyEvent::Closed("Service proxy shutting down".to_string()),
            Box::new(|| {
                "Error sending proxy closed event to client-bound message poller:".to_string()
            }),
        ) {
            error(&target!(), &format!("{:?}", &err));
        }
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
                    format!("Error while sending request to close a UDP proxy connection: proxy_stream={},", &proxy_key_copy)
                }),
            ) {
                errors.push(format!("{:?}", &err));
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
                    "Error while sending request to close a UDP proxy connection: proxy_stream={},",
                    &proxy_key_copy
                )
            }),
        )?;
        self.remove_proxy_for_key(proxy_key);
        Ok(())
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

        let _ = UdpClientProxy::new(&app_config, mpsc::channel().1, server_visitor, 3000);
    }

    #[test]
    fn udpcliproxy_spawn_client_bound_message_processor() {
        let app_config = Arc::new(config::tests::create_app_config(None).unwrap());
        let connected_udp_stream = stream_utils::ConnectedUdpSocket::new().unwrap();
        let server_socket_channel = mpsc::channel();
        let server_visitor = Arc::new(Mutex::new(
            UdpClientProxyServerVisitor::new(
                &app_config,
                &Service::default(),
                3000,
                "gwhost1",
                2000,
                &server_socket_channel.0,
                &mpsc::channel().0,
                &mpsc::channel().0,
                &Arc::new(Mutex::new(HashMap::new())),
            )
            .unwrap(),
        ));
        let client_proxy = UdpClientProxy::new(
            &app_config,
            server_socket_channel.1,
            server_visitor.clone(),
            3000,
        )
        .unwrap();

        client_proxy.spawn_client_bound_message_processor(connected_udp_stream.server_socket.0);

        server_socket_channel
            .0
            .send(ProxyEvent::Message(
                "key1".to_string(),
                connected_udp_stream.client_socket.1,
                "hi".as_bytes().to_vec(),
            ))
            .unwrap();

        server_visitor.lock().unwrap().set_shutdown_requested();
    }

    #[test]
    fn udpsvrproxyvisit_new() {
        let server_visitor = UdpClientProxyServerVisitor::new(
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::UDP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &Arc::new(Mutex::new(HashMap::new())),
        );

        assert!(server_visitor.is_ok());
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
            &Some(connected_udp_peer_addr.clone()),
            &Some(connected_udp_local_addr.clone()),
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
            &Arc::new(app_config),
            &service,
            3000,
            "localhost",
            gateway_proxy_port,
            &mpsc::channel().0,
            &proxy_tasks_sender,
            &proxy_events_sender,
            &services_by_proxy_key,
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
            &Some(connected_udp_peer_addr.clone()),
            &Some(connected_udp_local_addr.clone()),
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
            &Arc::new(app_config),
            &service,
            3000,
            "localhost",
            gateway_proxy_port,
            &mpsc::channel().0,
            &proxy_tasks_sender,
            &proxy_events_sender,
            &services_by_proxy_key,
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
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service,
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &Arc::new(Mutex::new(HashMap::new())),
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

        assert!(!server_visitor.shutdown_requested);
        server_visitor.set_shutdown_requested();
        assert!(server_visitor.shutdown_requested);
        assert_eq!(server_visitor.get_service(), service);
        assert_eq!(server_visitor.get_client_proxy_port(), 3000);
        assert_eq!(server_visitor.get_gateway_proxy_host(), "gwhost1");
        assert_eq!(server_visitor.get_gateway_proxy_port(), 2000);

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
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service,
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &proxy_tasks_sender,
            &mpsc::channel().0,
            &services_by_proxy_key,
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
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service,
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &proxy_tasks_sender,
            &mpsc::channel().0,
            &services_by_proxy_key,
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
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service,
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &proxy_tasks_sender,
            &mpsc::channel().0,
            &services_by_proxy_key,
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
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service,
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &services_by_proxy_key,
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
            &Arc::new(config::tests::create_app_config(None).unwrap()),
            &service,
            3000,
            "gwhost1",
            2000,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &mpsc::channel().0,
            &services_by_proxy_key,
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
