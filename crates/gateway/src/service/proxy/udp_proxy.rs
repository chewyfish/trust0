use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;

use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;

use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::net::tls_server::conn_std::TlsServerConnection;
use trust0_common::net::tls_server::{conn_std, server_std};
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::ProxyExecutorEvent;
use trust0_common::proxy::proxy_base::ProxyType;
use crate::client::connection::ClientConnVisitor;
use crate::config::AppConfig;
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy_base::{GatewayServiceProxy, GatewayServiceProxyVisitor, ProxyAddrs};

/// Gateway service proxy (TCP trust0 gateway <-> UDP service)
pub struct UdpGatewayProxy {
    tls_server: server_std::Server,
    _server_visitor: Arc<Mutex<UdpGatewayProxyServerVisitor>>
}

impl UdpGatewayProxy {

    /// UdpGatewayProxy constructor
    pub fn new(
        _app_config: Arc<AppConfig>,
        server_visitor: Arc<Mutex<UdpGatewayProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Self {

        Self {
            tls_server: server_std::Server::new(
                server_visitor.clone(),
                proxy_port
            ),
            _server_visitor: server_visitor,
        }
    }
}

impl GatewayServiceProxy for UdpGatewayProxy {

    fn startup(&mut self) -> Result<(), AppError> {
        self.tls_server.bind_listener()?;
        self.tls_server.poll_new_connections()
    }

    fn shutdown(&mut self) {
        self.tls_server.shutdown();
    }
}

unsafe impl Send for UdpGatewayProxy {}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct UdpGatewayProxyServerVisitor {
    app_config: Arc<AppConfig>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    service: Service,
    proxy_host: Option<String>,
    proxy_port: u16,
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    proxy_events_sender: Sender<ProxyEvent>,
    services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>,
    users_by_proxy_addrs: HashMap<ProxyAddrs, u64>,
    proxy_addrs_by_proxy_key: HashMap<String, ProxyAddrs>,
    proxy_keys_by_user: HashMap<u64, Vec<String>>
}

impl UdpGatewayProxyServerVisitor {

    #[allow(clippy::too_many_arguments)]
    /// UdpGatewayProxyServerVisitor constructor
    pub fn new(app_config: Arc<AppConfig>,
               service_mgr: Arc<Mutex<dyn ServiceMgr>>,
               service: Service,
               proxy_host: Option<String>,
               proxy_port: u16,
               proxy_tasks_sender: Sender<ProxyExecutorEvent>,
               proxy_events_sender: Sender<ProxyEvent>,
               services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>)
        -> Result<Self, AppError> {

        Ok(Self {
            app_config,
            service_mgr,
            service,
            proxy_host,
            proxy_port,
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key,
            users_by_proxy_addrs: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_user: HashMap::new()
        })
    }

    /// Stringified tuple client and gateway connection addresses
    fn create_proxy_addrs(tls_conn: &TlsServerConnection) -> ProxyAddrs {

        let peer_addr = match &tls_conn.sock.peer_addr() {
            Ok(addr) => format!("{:?}", addr),
            Err(_) => "(NA)".to_string()
        };
        let local_addr = match &tls_conn.sock.local_addr() {
            Ok(addr) => format!("{:?}", addr),
            Err(_) => "(NA)".to_string()
        };

        (peer_addr, local_addr)
    }
}

impl server_std::ServerVisitor for UdpGatewayProxyServerVisitor {

    fn create_client_conn(&mut self, tls_conn: TlsServerConnection) -> Result<conn_std::Connection, AppError> {

        let mut conn_visitor = ClientConnVisitor::new(
            self.app_config.clone(),
            self.service_mgr.clone());

        let alpn_protocol = conn_visitor.process_authorization(&tls_conn, Some(self.service.service_id))?;

        let user_id = conn_visitor.get_user().as_ref().unwrap().user_id;
        self.users_by_proxy_addrs.insert(UdpGatewayProxyServerVisitor::create_proxy_addrs(&tls_conn), user_id);

        let connection = conn_std::Connection::new(Box::new(conn_visitor), tls_conn, alpn_protocol)?;

        Ok(connection)
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {

        // Make connection to service

        let mut service_addr = None;
        let mut response_err = None;

        let resolved_host = self.app_config.dns_client.query_addrs(self.service.host.as_str()).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed resolving host: host={}", &self.service.host), Box::new(err)))?;

        let udp_socket = UdpSocket::bind(format!("{}:0", &self.app_config.gateway_service_reply_host))
            .map_err(|err| AppError::GenWithMsgAndErr(
                format!("Error binding service reply UDP socket: reply_host={}", &self.app_config.gateway_service_reply_host),Box::new(err)))?;

        for host_addr in resolved_host.into_iter() {

            let remote_addr = SocketAddr::new(host_addr, self.service.port);

            match udp_socket.connect(remote_addr) {
                Ok(()) => {
                    service_addr = Some(remote_addr);
                    udp_socket.set_nonblocking(true).map_err(|err|
                        AppError::GenWithMsgAndErr(format!("Failed making socket non-blocking: socket={:?}", &udp_socket), Box::new(err)))?;
                    break;
                },
                Err(err) => response_err = Some(err)
            }
        }

        if service_addr.is_none() {
            return match response_err {
                Some(err) => Err(AppError::GenWithMsgAndErr(format!("Failed connect to service endpoint(s): svc={:?}", &self.service), Box::new(err))),
                None => Err(AppError::General(format!("No resolved service endpoints: svc={:?}", &self.service)))
            }
        }

        let service_addr = service_addr.unwrap();

        // Send request to proxy executor to startup new proxy

        let tls_conn = connection.get_tls_conn_as_ref();
        let proxy_addrs = UdpGatewayProxyServerVisitor::create_proxy_addrs(tls_conn);
        let proxy_key = ProxyEvent::key_value(&ProxyType::TcpAndUdp, udp_socket.local_addr().ok(), Some(service_addr));
        let client_stream = tls_conn.sock.try_clone().map_err(|err|
            AppError::GenWithMsgAndErr(format!("Unable to clone client service proxy stream: client_stream={:?}", &tls_conn.sock), Box::new(err)))?;

        let open_proxy_request = ProxyExecutorEvent::OpenTcpAndUdpProxy(
            proxy_key.clone(),
            (
                client_stream,
                udp_socket,
                Arc::new(Mutex::new(Box::<TlsServerConnection>::new(connection.into()))),
                self.proxy_events_sender.clone()
            )
        );

        self.proxy_tasks_sender.send(open_proxy_request).map_err(|err|
            AppError::General(format!("Error while sending request for new TCP proxy: proxy_key={}, err={:?}", &proxy_key, &err)))?;

        // Set up proxy maps

        self.services_by_proxy_key.lock().unwrap().insert(proxy_key.clone(), self.service.service_id);

        let user_id = self.users_by_proxy_addrs.get(&proxy_addrs).ok_or(
            AppError::General(format!("Unknown user for proxy address pair: addrs={:?}", &proxy_addrs)))?;

        self.proxy_addrs_by_proxy_key.insert(proxy_key.clone(), proxy_addrs.clone());

        if let Some(proxy_keys) = self.proxy_keys_by_user.get_mut(user_id) {
            proxy_keys.push(proxy_key.clone());
        } else {
            self.proxy_keys_by_user.insert(*user_id, vec![proxy_key.clone()]);
        }

        Ok(())
    }
}

impl GatewayServiceProxyVisitor for UdpGatewayProxyServerVisitor {

    fn get_service(&self) -> Service {
        self.service.clone()
    }

    fn get_proxy_host(&self) -> Option<String> {
        self.proxy_host.clone()
    }

    fn get_proxy_port(&self) -> u16 {
        self.proxy_port
    }

    fn get_proxy_addrs_for_user(&self, user_id: u64) -> Vec<ProxyAddrs> {

        self.users_by_proxy_addrs.iter()
            .filter_map(|(proxy_addrs, uid)| {
                if user_id == *uid { Some(proxy_addrs.clone()) } else { None }})
            .collect()
    }

    fn shutdown_connections(&mut self, proxy_tasks_sender: Sender<ProxyExecutorEvent>, user_id: Option<u64>)
        -> Result<(), AppError> {

        let mut errors: Vec<String> = vec![];

        let proxy_keys_lists: Vec<Vec<String>> = self.proxy_keys_by_user.iter()
            .filter(|(uid, _)| {
                user_id.is_none() || (**uid == user_id.unwrap())
            })
            .map(|item| item.1)
            .cloned()
            .collect();

        for proxy_keys in proxy_keys_lists {

            for proxy_key in proxy_keys {
                if let Err(err) = proxy_tasks_sender.send(ProxyExecutorEvent::Close(proxy_key.clone())) {
                    errors.push(format!("Error while sending request to close a TCP proxy connection: proxy_stream={}, err={:?}", &proxy_key, err));
                } else {
                    self.remove_proxy_for_key(&proxy_key);
                }
            };

            if !errors.is_empty() {
                return Err(AppError::General(format!("Errors closing proxy connection(s), err={}", errors.join(", "))));
            }
        }

        Ok(())
    }

    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool {

        match self.proxy_addrs_by_proxy_key.get(proxy_key) {

            Some(proxy_addrs) => {
                let proxy_addrs = proxy_addrs.clone();
                let user_id = self.users_by_proxy_addrs.get(&proxy_addrs).unwrap();
                if let Some(proxy_keys) = self.proxy_keys_by_user.get_mut(user_id) {
                    proxy_keys.retain(|key| !key.eq(proxy_key))
                }
                self.proxy_addrs_by_proxy_key.remove(proxy_key);
                self.users_by_proxy_addrs.remove(&proxy_addrs);
                self.services_by_proxy_key.lock().unwrap().remove(&proxy_key.to_string());
                true
            }

            None => false
        }
    }
}
