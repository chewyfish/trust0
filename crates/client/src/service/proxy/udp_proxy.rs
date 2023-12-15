use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use anyhow::Result;
use trust0_common::crypto::alpn;

use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::model::service::Service;
use trust0_common::net::udp_server::server_std;
use trust0_common::net::tls_client::client_std;
use trust0_common::net::tls_client::conn_std::TlsClientConnection;
use trust0_common::net::udp_server::server_std::Server;
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::{ProxyExecutorEvent, ProxyKey};
use trust0_common::proxy::proxy::ProxyType;
use trust0_common::target;
use crate::config::AppConfig;
use crate::service::proxy::proxy::{ClientServiceProxy, ClientServiceProxyVisitor};
use crate::service::proxy::proxy_client::ClientVisitor;

/// Client service proxy (UDP service client <-> TCP trust0 client)
pub struct UdpClientProxy {
    udp_server: server_std::Server,
    server_socket_channel_receiver: Arc<Mutex<Receiver<ProxyEvent>>>,
    _server_visitor: Arc<Mutex<UdpClientProxyServerVisitor>>
}

impl UdpClientProxy {
    /// UdpClientProxy constructor
    pub fn new(
        _app_config: Arc<AppConfig>,
        server_socket_channel_receiver: Receiver<ProxyEvent>,
        server_visitor: Arc<Mutex<UdpClientProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Result<Self, AppError> {
        Ok(Self {
            udp_server: server_std::Server::new(
                server_visitor.clone(),
                proxy_port
            )?,
            server_socket_channel_receiver: Arc::new(Mutex::new(server_socket_channel_receiver)),
            _server_visitor: server_visitor,
        })
    }

    /// Startup client-bound message processor thread
    fn spawn_client_bound_message_processor(&self, server_socket: UdpSocket) {
        let server_socket_channel_receiver = self.server_socket_channel_receiver.clone();

        thread::spawn(move || {
            loop {
                match server_socket_channel_receiver.lock().unwrap().recv() {
                    Err(err) => error(&target!(), &format!("Error receiving socket event: err={:?}", err)),

                    Ok(proxy_event) => {
                        if let ProxyEvent::Message(proxy_key, socket_addr, data) = proxy_event {
                            if let Err(err) = Server::send_message(&server_socket, &socket_addr, &data) {
                                error(&target!(), &format!("Error processing message channel: proxy_stream={}, err={:?}", &proxy_key, &err));
                            }
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
    proxy_keys: HashSet<ProxyKey>,
    shutdown_requested: bool
}

impl UdpClientProxyServerVisitor {

    /// UdpClientProxyServerVisitor constructor
    pub fn new(app_config: Arc<AppConfig>,
               service: Service,
               client_proxy_port: u16,
               gateway_proxy_host: &str,
               gateway_proxy_port: u16,
               server_socket_channel_sender: Sender<ProxyEvent>,
               proxy_tasks_sender: Sender<ProxyExecutorEvent>,
               proxy_events_sender: Sender<ProxyEvent>,
               services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>)
        -> Result<Self, AppError> {

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
            proxy_keys: HashSet::new(),
            shutdown_requested: false
        })
    }
}

impl server_std::ServerVisitor for UdpClientProxyServerVisitor {

    fn on_message_received(&mut self, local_addr: &SocketAddr, peer_addr: &SocketAddr, data: Vec<u8>)
        -> Result<(), AppError> {

        let proxy_key = ProxyEvent::key_value(&ProxyType::ChannelAndTcp, Some(peer_addr.clone()), Some(local_addr.clone()));

        // New client socket, setup service proxy
        // - - - - - - - - - - - - - - - - - - -
        if !self.socket_channel_senders_by_proxy_key.contains_key(&proxy_key) {

            let (socket_channel_sender, socket_channel_receiver) = mpsc::channel();

            // Make connection to gateway proxy
            let mut tls_client_config = self.app_config.tls_client_config.clone();
            tls_client_config.alpn_protocols = vec![alpn::Protocol::create_service_protocol(self.service.service_id).into_bytes()];

            let mut tls_client = client_std::Client::new(
                Box::new(ClientVisitor::new()),
                tls_client_config,
                self.gateway_proxy_host.clone(),
                self.gateway_proxy_port);

            tls_client.connect()?;

            let gateway_stream = tls_client.get_connection().as_ref().unwrap().get_tls_conn_as_ref().sock.try_clone().map_err(|err|
                AppError::GenWithMsgAndErr("Error trying to clone gateway proxy TLS stream".to_string(), Box::new(err)))?;

            // Send request to proxy executor to startup new proxy
            let open_proxy_request = ProxyExecutorEvent::OpenChannelAndTcpProxy(
                proxy_key.clone(),
                (
                    peer_addr.clone(),
                    socket_channel_receiver,
                    self.server_socket_channel_sender.clone(),
                    gateway_stream,
                    Arc::new(Mutex::new(Box::<TlsClientConnection>::new(tls_client.into()))),
                    self.proxy_events_sender.clone()
                )
            );

            self.proxy_tasks_sender.send(open_proxy_request).map_err(|err|
                AppError::General(format!("Error while sending request for new UDP proxy: proxy_key={}, err={:?}", &proxy_key, &err)))?;

            // Setup proxy maps
            self.socket_channel_senders_by_proxy_key.insert(proxy_key.clone(), socket_channel_sender);
            self.services_by_proxy_key.lock().unwrap().insert(proxy_key.clone(), self.service.service_id);
            self.proxy_keys.insert(proxy_key.clone());

        }

        // Send service-bound message to appropriate channel
        // - - - - - - - - - - - - - - - - - - - - - - - - -
        if let Some(socket_channel_sender) = self.socket_channel_senders_by_proxy_key.get(&proxy_key) {
            return match socket_channel_sender.send(ProxyEvent::Message(proxy_key.clone(), peer_addr.clone(), data)) {
                Ok(()) => Ok(()),
                Err(err) => Err(AppError::GenWithMsgAndErr(
                    format!("Error while sending message to socket channel: proxy_stream={}", &proxy_key),
                    Box::new(err)))
            }
        }
        Ok(())
    }

    fn get_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

impl ClientServiceProxyVisitor for UdpClientProxyServerVisitor {

    fn get_service(&self) -> &Service {
        &self.service
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

    fn set_shutdown_requested(&mut self) {
        self.shutdown_requested = true;
    }

    fn shutdown_connections(&mut self, proxy_tasks_sender: Sender<ProxyExecutorEvent>) -> Result<(), AppError> {

        let mut errors: Vec<String> = vec![];

        for proxy_key in self.proxy_keys.iter() {

            if let Err(err) = proxy_tasks_sender.send(ProxyExecutorEvent::Close(proxy_key.clone())) {
                errors.push(format!("Error while sending request to close a UDP proxy connection: proxy_stream={}, err={:?}", &proxy_key, err));
            }

            self.services_by_proxy_key.lock().unwrap().remove(proxy_key);
        }

        if errors.is_empty() {
            self.proxy_keys.clear();
        } else {
            return Err(AppError::General(format!("Errors closing proxy connection(s), err={}", errors.join(", "))));
        }

        Ok(())
    }

    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool {

        let proxy_key = proxy_key.to_string();

        return match self.proxy_keys.contains(&proxy_key) {

            true => {
                self.services_by_proxy_key.lock().unwrap().remove(&proxy_key);
                self.proxy_keys.remove(&proxy_key);
                true
            }

            false => false
        }
    }
}
