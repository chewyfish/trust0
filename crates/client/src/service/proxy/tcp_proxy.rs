use std::collections::{HashMap, HashSet};
use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::config::AppConfig;
use crate::service::proxy::proxy_base::{ClientServiceProxy, ClientServiceProxyVisitor};
use crate::service::proxy::proxy_client::ClientVisitor;
use trust0_common::crypto::alpn;
use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use trust0_common::net::tcp_server::{conn_std, server_std};
use trust0_common::net::tls_client::client_std;
use trust0_common::net::tls_client::conn_std::TlsClientConnection;
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::{ProxyExecutorEvent, ProxyKey};
use trust0_common::proxy::proxy_base::ProxyType;

/// Client service proxy (TCP service client <-> TCP trust0 client)
pub struct TcpClientProxy {
    tcp_server: server_std::Server,
    _server_visitor: Arc<Mutex<TcpClientProxyServerVisitor>>,
}

impl TcpClientProxy {
    /// TcpClientProxy constructor
    pub fn new(
        _app_config: Arc<AppConfig>,
        server_visitor: Arc<Mutex<TcpClientProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Self {
        Self {
            tcp_server: server_std::Server::new(server_visitor.clone(), proxy_port),
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
    app_config: Arc<AppConfig>,
    service: Service,
    client_proxy_port: u16,
    gateway_proxy_host: String,
    gateway_proxy_port: u16,
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    proxy_events_sender: Sender<ProxyEvent>,
    services_by_proxy_key: Arc<Mutex<HashMap<String, u64>>>,
    proxy_keys: HashSet<ProxyKey>,
    shutdown_requested: bool,
}

impl TcpClientProxyServerVisitor {
    #![allow(clippy::too_many_arguments)]
    /// TcpClientProxyServerVisitor constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        service: Service,
        client_proxy_port: u16,
        gateway_proxy_host: &str,
        gateway_proxy_port: u16,
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
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key,
            proxy_keys: HashSet::new(),
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

        // Send request to proxy executor to startup new proxy

        let tcp_stream = connection.get_tcp_stream_as_ref();
        let proxy_key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            tcp_stream.peer_addr().ok(),
            tcp_stream.local_addr().ok(),
        );
        let client_stream = tcp_stream.try_clone().map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Unable to clone client stream: client_stream={:?}",
                    &tcp_stream
                ),
                Box::new(err),
            )
        })?;

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

        self.proxy_tasks_sender
            .send(open_proxy_request)
            .map_err(|err| {
                AppError::General(format!(
                    "Error while sending request for new TCP proxy: proxy_key={}, err={:?}",
                    &proxy_key, &err
                ))
            })?;

        // Setup proxy maps

        self.services_by_proxy_key
            .lock()
            .unwrap()
            .insert(proxy_key.clone(), self.service.service_id);
        self.proxy_keys.insert(proxy_key);

        Ok(())
    }

    fn get_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

impl ClientServiceProxyVisitor for TcpClientProxyServerVisitor {
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

    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    ) -> Result<(), AppError> {
        let mut errors: Vec<String> = vec![];

        for proxy_key in self.proxy_keys.iter() {
            if let Err(err) = proxy_tasks_sender.send(ProxyExecutorEvent::Close(proxy_key.clone()))
            {
                errors.push(format!("Error while sending request to close a TCP proxy connection: proxy_stream={}, err={:?}", &proxy_key, err));
            }

            self.services_by_proxy_key.lock().unwrap().remove(proxy_key);
        }

        if errors.is_empty() {
            self.proxy_keys.clear();
        } else {
            return Err(AppError::General(format!(
                "Errors closing proxy connection(s), err={}",
                errors.join(", ")
            )));
        }

        Ok(())
    }

    fn remove_proxy_for_key(&mut self, proxy_key: &str) -> bool {
        let proxy_key = proxy_key.to_string();

        return match self.proxy_keys.contains(&proxy_key) {
            true => {
                self.services_by_proxy_key
                    .lock()
                    .unwrap()
                    .remove(&proxy_key);
                self.proxy_keys.remove(&proxy_key);
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
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {})
    }
}

impl conn_std::ConnectionVisitor for ClientConnVisitor {
    fn send_error_response(&mut self, _err: &AppError) {}
}

unsafe impl Send for ClientConnVisitor {}
