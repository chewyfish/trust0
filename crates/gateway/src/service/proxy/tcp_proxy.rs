use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
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
use trust0_common::proxy::proxy::ProxyType;
use crate::client::connection::ClientConnVisitor;
use crate::config::AppConfig;
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy::{GatewayServiceProxy, GatewayServiceProxyVisitor, ProxyAddrs};

/// Gateway service proxy (TCP trust0 gateway <-> TCP service)
pub struct TcpGatewayProxy {
    tls_server: server_std::Server,
    _server_visitor: Arc<Mutex<TcpGatewayProxyServerVisitor>>
}

impl TcpGatewayProxy {

    /// TcpGatewayProxy constructor
    pub fn new(
        _app_config: Arc<AppConfig>,
        server_visitor: Arc<Mutex<TcpGatewayProxyServerVisitor>>,
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

impl GatewayServiceProxy for TcpGatewayProxy {

    fn startup(&mut self) -> Result<(), AppError> {
        self.tls_server.bind_listener()?;
        self.tls_server.poll_new_connections()
    }

    fn shutdown(&mut self) {
        self.tls_server.shutdown();
    }
}

unsafe impl Send for TcpGatewayProxy {}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct TcpGatewayProxyServerVisitor {
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

impl TcpGatewayProxyServerVisitor {

    /// TcpGatewayProxyServerVisitor constructor
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

impl server_std::ServerVisitor for TcpGatewayProxyServerVisitor {

    fn create_client_conn(&mut self, tls_conn: TlsServerConnection) -> Result<conn_std::Connection, AppError> {

        let mut conn_visitor = ClientConnVisitor::new(
            self.app_config.clone(),
            self.service_mgr.clone());

        let alpn_protocol = conn_visitor.process_authorization(&tls_conn, Some(self.service.service_id))?;

        let user_id = conn_visitor.get_user().as_ref().unwrap().user_id;
        self.users_by_proxy_addrs.insert(TcpGatewayProxyServerVisitor::create_proxy_addrs(&tls_conn), user_id);

        Ok(conn_std::Connection::new(Box::new(conn_visitor), tls_conn, alpn_protocol)?)
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {

        // Make connection to service

        let mut service_stream: Option<TcpStream> = None;
        let mut response_err = None;

        let resolved_host = self.app_config.dns_client.query_addrs(self.service.host.as_str()).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed resolving host: host={}", &self.service.host), Box::new(err)))?;

        for host_addr in resolved_host.into_iter() {

            let service_addr = SocketAddr::new(host_addr, self.service.port);

            match TcpStream::connect(service_addr) {
                Ok(socket) => {
                    socket.set_nonblocking(true).map_err(|err|
                        AppError::GenWithMsgAndErr(format!("Failed making socket non-blocking: socket={:?}", &socket), Box::new(err)))?;
                    service_stream = Some(socket);
                    break;
                },
                Err(err) => response_err = Some(err)
            }
        }

        if service_stream.is_none() {
            return match response_err {
                Some(err) => Err(AppError::GenWithMsgAndErr(format!("Failed connect to service endpoint(s): svc={:?}", &self.service), Box::new(err))),
                None => Err(AppError::General(format!("No resolved service endpoints: svc={:?}", &self.service)))
            }
        }

        let service_stream = service_stream.unwrap();

        // Send request to proxy executor to startup new proxy

        let tls_conn = connection.get_tls_conn_as_ref();
        let proxy_addrs = TcpGatewayProxyServerVisitor::create_proxy_addrs(&tls_conn);
        let proxy_key = ProxyEvent::key_value(&ProxyType::TcpAndTcp, tls_conn.sock.peer_addr().ok(), service_stream.peer_addr().ok());
        let client_stream = tls_conn.sock.try_clone().map_err(|err|
            AppError::GenWithMsgAndErr(format!("Unable to clone client service proxy stream: client_stream={:?}", &tls_conn.sock), Box::new(err)))?;
        let service_stream_copy = service_stream.try_clone().map_err(|err|
            AppError::GenWithMsgAndErr(format!("Unable to clone service stream: service_stream={:?}", &service_stream), Box::new(err)))?;

        let open_proxy_request = ProxyExecutorEvent::OpenTcpAndTcpProxy(
            proxy_key.clone(),
            (
                client_stream,
                service_stream,
                Arc::new(Mutex::new(Box::<TlsServerConnection>::new(connection.into()))),
                Arc::new(Mutex::new(Box::new(service_stream_copy))),
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

impl GatewayServiceProxyVisitor for TcpGatewayProxyServerVisitor {

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
            .map(|(proxy_addrs, uid)| {
                if user_id == *uid { Some(proxy_addrs.clone()) } else { None }})
            .flatten()
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
            }

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
                match self.proxy_keys_by_user.get_mut(user_id) {
                    Some(proxy_keys) => proxy_keys.retain(|key| !key.eq(proxy_key)),
                    None => {}
                }
                self.proxy_addrs_by_proxy_key.remove(proxy_key);
                self.users_by_proxy_addrs.remove(&proxy_addrs);
                self.services_by_proxy_key.lock().unwrap().remove(&proxy_key.to_string());
                return true;
            }

            None => return false
        }
    }
}