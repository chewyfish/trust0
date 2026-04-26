#[cfg(test)]
use ::time::macros::datetime;
use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use trust0_common::client::service::ProxyAddrs;
use trust0_common::control::tls;
use trust0_common::control::tls::message::{self, ConnectionAddrs};
use trust0_common::crypto::alpn;
use trust0_common::crypto::ca::{CertAccessContext, EntityType};
use trust0_common::error::AppError;
use trust0_common::model::service::Service;
#[cfg(test)]
use trust0_common::model::user;
use trust0_common::net::stream_utils;
use trust0_common::net::tls_client;
use trust0_common::net::tls_client::conn_std::TlsClientConnection;
use trust0_common::net::tls_server;
use trust0_common::net::tls_server::conn_std::TlsServerConnection;
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::ProxyExecutorEvent;
use trust0_common::proxy::proxy_base::ProxyType;
use trust0_common::sync;
#[cfg(test)]
use x509_parser::prelude::{ASN1Time, Validity};

use crate::config::AppConfig;
use crate::control;
use crate::control::client::device;
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy_base::{GatewayServiceProxy, GatewayServiceProxyVisitor};

/// Gateway-to-gateway service proxy (TCP trust0 client-gateway <-> TLS trust0 service-gateway)
pub struct ServiceGatewayProxy {
    /// TLS server (delegate) for given service proxy
    tls_server: tls_server::server_std::Server,
}

impl ServiceGatewayProxy {
    /// ServiceGatewayProxy constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `server_visitor` - Server visitor pattern object
    /// * `proxy_port` - Port to use for binding server listener
    ///
    /// # Returns
    ///
    /// A newly constructed [`ServiceGatewayProxy`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        server_visitor: Arc<Mutex<ServiceGatewayProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Self {
        Self {
            tls_server: tls_server::server_std::Server::new(
                server_visitor,
                &app_config.server_host,
                proxy_port,
                false,
            ),
        }
    }
}

impl GatewayServiceProxy for ServiceGatewayProxy {
    fn startup(&mut self) -> Result<(), AppError> {
        self.tls_server.bind_listener()?;
        self.tls_server.poll_new_connections()
    }

    fn shutdown(&mut self) {
        self.tls_server.shutdown();
    }
}

unsafe impl Send for ServiceGatewayProxy {}

/// tls_server::server_std::Server strategy visitor pattern implementation
pub struct ServiceGatewayProxyServerVisitor {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Service model object
    service: Service,
    /// Host address for proxy server listener
    proxy_host: Option<String>,
    /// Port for proxy server listener
    proxy_port: u16,
    /// Channel sender for proxy executor events
    proxy_tasks_sender: Sender<ProxyExecutorEvent>,
    /// Channel sender for proxy events
    proxy_events_sender: Sender<ProxyEvent>,
    /// Map of services by proxy key
    services_by_proxy_key: Arc<Mutex<HashMap<String, i64>>>,
    /// Map of device by proxy address context
    devices_by_proxy_addrs: HashMap<ConnectionAddrs, String>,
    /// Map of proxy address context by proxy key
    proxy_addrs_by_proxy_key: HashMap<String, ConnectionAddrs>,
    /// Map of proxy keys/addresses by device
    proxy_keys_by_device: HashMap<String, Vec<(String, ConnectionAddrs)>>,
    /// Service proxy addrs result from service startup on service-gateway
    service_gateway_proxy_addrs: ProxyAddrs,
}

impl ServiceGatewayProxyServerVisitor {
    #[allow(clippy::too_many_arguments)]
    /// ServiceGatewayProxyServerVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `service_mgr` - Service manager
    /// * `service` - Service model object
    /// * `proxy_host` - Host address for proxy server listener
    /// * `proxy_port` - Port for proxy server listener
    /// * `proxy_tasks_sender` - Channel sender for proxy executor events
    /// * `proxy_events_sender` - Channel sender for proxy events
    /// * `services_by_proxy_key` - Map of services by proxy key
    /// * `service_gateway_proxy_addrs` - Service proxy addrs result from service startup on service-gateway
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ServiceGatewayProxyServerVisitor`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        service: &Service,
        proxy_host: &Option<String>,
        proxy_port: u16,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        proxy_events_sender: &Sender<ProxyEvent>,
        services_by_proxy_key: &Arc<Mutex<HashMap<String, i64>>>,
        service_gateway_proxy_addrs: &ProxyAddrs,
    ) -> Result<Self, AppError> {
        Ok(Self {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: service.clone(),
            proxy_host: proxy_host.clone(),
            proxy_port,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: proxy_events_sender.clone(),
            services_by_proxy_key: services_by_proxy_key.clone(),
            devices_by_proxy_addrs: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::new(),
            service_gateway_proxy_addrs: service_gateway_proxy_addrs.clone(),
        })
    }

    /// Client connection authentication/authorization enforcement
    /// If valid auth, return tuple of: connection visitor; device ID; user ID; ALPN protocol
    ///
    /// # Arguments
    ///
    /// * `tls_conn` - TLS server connection object
    /// * `client_msg`: Optional initial message from client
    ///
    /// # Returns
    ///
    /// A [`Result`] containing tuple of: device ID; user ID; ALPN protocol
    ///
    #[cfg(not(test))]
    fn process_connection_authorization(
        &self,
        tls_conn: &TlsServerConnection,
        client_msg: Option<message::SessionMessage>,
    ) -> Result<(String, i64, alpn::Protocol), AppError> {
        let mut control_conn_visitor = control::client::connection::ClientConnVisitor::new(
            &self.app_config,
            &self.service_mgr,
        );
        let protocol = control_conn_visitor.process_authorization(
            tls_conn,
            Some(self.service.service_id),
            client_msg,
        )?;
        let device_id = control_conn_visitor.get_device().as_ref().unwrap().get_id();
        let user_id = control_conn_visitor.get_user().as_ref().unwrap().user_id;
        Ok((device_id.to_string(), user_id, protocol))
    }

    #[cfg(test)]
    fn process_connection_authorization(
        &self,
        _tls_conn: &TlsServerConnection,
        _client_msg: Option<message::SessionMessage>,
    ) -> Result<(String, i64, alpn::Protocol), AppError> {
        let mut control_conn_visitor = control::client::connection::ClientConnVisitor::new(
            &self.app_config,
            &self.service_mgr,
        );
        let device = device::Device {
            cert_subj: HashMap::new(),
            cert_alt_subj: HashMap::new(),
            cert_access_context: CertAccessContext {
                entity_type: EntityType::Client,
                platform: "plat1".to_string(),
                user_id: 100,
            },
            proxied_access_context: Some(CertAccessContext {
                entity_type: EntityType::Client,
                platform: "plat1".to_string(),
                user_id: 100,
            }),
            cert_serial_num: vec![0x03u8, 0xe8u8],
            cert_validity: Validity {
                not_before: ASN1Time::from(datetime!(2025-12-21 19:04:45.0 +00:00:00)),
                not_after: ASN1Time::from(datetime!(2100-01-01 0:00:00.0 +00:00:00)),
            },
        };
        let user = user::User::new(100, None, None, "name100", &user::Status::Active, &[]);
        control_conn_visitor.set_device(Some(device.clone()));
        control_conn_visitor.set_user(Some(user.clone()));
        control_conn_visitor.set_protocol(Some(alpn::Protocol::Service(200)));
        Ok((device.get_id(), user.user_id, alpn::Protocol::Service(200)))
    }
}

impl tls_server::server_std::ServerVisitor for ServiceGatewayProxyServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
        client_msg: Option<tls::message::SessionMessage>,
    ) -> Result<tls_server::conn_std::Connection, AppError> {
        let (device_id, _user_id, alpn_protocol) =
            self.process_connection_authorization(&tls_conn, client_msg)?;
        let conn_addrs = tls::message::Trust0Connection::create_connection_addrs(&tls_conn.sock);
        self.devices_by_proxy_addrs
            .insert(conn_addrs.clone(), device_id);
        tls_server::conn_std::Connection::new(
            Box::new(ServerConnVisitor::new()?),
            tls_conn,
            &conn_addrs,
            &alpn_protocol,
        )
    }

    fn on_tls_handshaking(&mut self, _accepted: &Accepted) -> Result<ServerConfig, AppError> {
        self.app_config.tls_server_config_builder.build()
    }

    fn on_server_msg_provider(
        &mut self,
        _server_conn: &rustls::ServerConnection,
        tcp_stream: &TcpStream,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        Ok(Some(tls::message::SessionMessage::new(
            &tls::message::DataType::Trust0Connection,
            &Some(
                serde_json::to_value(tls::message::Trust0Connection::new(
                    &tls::message::Trust0Connection::create_connection_addrs(tcp_stream),
                ))
                .unwrap(),
            ),
        )))
    }

    fn on_conn_accepted(
        &mut self,
        connection: tls_server::conn_std::Connection,
    ) -> Result<(), AppError> {
        // Make connection to service-gateway service proxy

        let mut tls_client_config = self
            .app_config
            .as_ref()
            .tls_client_config
            .as_ref()
            .unwrap()
            .clone();
        tls_client_config.alpn_protocols =
            vec![alpn::Protocol::create_service_protocol(self.service.service_id).into_bytes()];

        let device_id_parsed = device::Device::parse_id(
            self.devices_by_proxy_addrs
                .get(connection.get_session_addrs())
                .ok_or(AppError::General(format!(
                    "Unknown device for proxy session address pair: addrs={:?}",
                    connection.get_session_addrs()
                )))?
                .as_str(),
        )?;

        let mut tls_client = tls_client::client_std::Client::new(
            Box::new(ServiceGatewayClientVisitor::new(
                device_id_parsed.2.unwrap(),
            )),
            tls_client_config,
            self.service_gateway_proxy_addrs.get_gateway_host(),
            self.service_gateway_proxy_addrs.get_gateway_port(),
            true,
        );

        tls_client.connect()?;

        let tls_client_conn = tls_client.get_connection().as_ref().unwrap();

        let svcgw_stream = stream_utils::clone_std_tcp_stream(
            tls_client_conn.get_tcp_stream(),
            "svcgw-proxy-server",
        )?;

        // Send request to proxy executor to startup new proxy

        let tcp_stream = connection.get_tcp_stream();
        let proxy_addrs = connection.get_session_addrs().clone();
        let proxy_key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &tcp_stream.peer_addr().ok(),
            &svcgw_stream.peer_addr().ok(),
        );
        let client_stream = stream_utils::clone_std_tcp_stream(tcp_stream, "svcgw-proxy-server")?;

        let open_proxy_request = ProxyExecutorEvent::OpenTcpAndTcpProxy(
            proxy_key.clone(),
            (
                client_stream,
                svcgw_stream,
                Arc::new(Mutex::new(Box::<TlsServerConnection>::new(
                    connection.into(),
                ))),
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
                    "Error while sending request for new SVCGW proxy: proxy_key={},",
                    &proxy_key_copy
                )
            }),
        )?;

        // Set up proxy maps

        self.services_by_proxy_key
            .lock()
            .unwrap()
            .insert(proxy_key.clone(), self.service.service_id);

        let device_id = self
            .devices_by_proxy_addrs
            .get(&proxy_addrs)
            .ok_or(AppError::General(format!(
                "Unknown device for proxy address pair: addrs={:?}",
                &proxy_addrs
            )))?;

        self.proxy_addrs_by_proxy_key
            .insert(proxy_key.clone(), proxy_addrs.clone());

        if let Some(proxy_keys) = self.proxy_keys_by_device.get_mut(device_id) {
            proxy_keys.push((proxy_key.clone(), proxy_addrs.clone()));
        } else {
            self.proxy_keys_by_device.insert(
                device_id.clone(),
                vec![(proxy_key.clone(), proxy_addrs.clone())],
            );
        }

        Ok(())
    }
}

impl GatewayServiceProxyVisitor for ServiceGatewayProxyServerVisitor {
    fn get_service(&self) -> Service {
        self.service.clone()
    }

    fn get_proxy_host(&self) -> Option<String> {
        self.proxy_host.clone()
    }

    fn get_proxy_port(&self) -> u16 {
        self.proxy_port
    }

    fn get_proxy_keys_for_device(&self, device_id: &str) -> Vec<(String, ConnectionAddrs)> {
        self.proxy_keys_by_device
            .get(device_id)
            .unwrap_or(&vec![])
            .to_vec()
    }

    fn shutdown_connections(
        &mut self,
        proxy_tasks_sender: &Sender<ProxyExecutorEvent>,
        device_id: Option<String>,
    ) -> Result<(), AppError> {
        let mut errors: Vec<String> = vec![];

        let proxy_keys_lists: Vec<Vec<(String, ConnectionAddrs)>> = self
            .proxy_keys_by_device
            .iter()
            .filter(|(did, _)| {
                device_id.is_none() || (did.as_str() == device_id.as_ref().unwrap().as_str())
            })
            .map(|item| item.1)
            .cloned()
            .collect();

        for proxy_keys in proxy_keys_lists {
            for proxy_key in proxy_keys {
                let proxy_key_copy = proxy_key.0.clone();
                if let Err(err) = sync::send_mpsc_channel_message(
                    proxy_tasks_sender,
                    ProxyExecutorEvent::Close(proxy_key.0.clone()),
                    Box::new(move || {
                        format!("Error while sending request to close a TCP proxy connection: proxy_stream={},", &proxy_key_copy)
                    }),
                ) {
                    errors.push(format!("{:?}", &err));
                } else {
                    self.remove_proxy_for_key(&proxy_key.0);
                }
            }

            if !errors.is_empty() {
                return Err(AppError::General(format!(
                    "Errors closing proxy connection(s), err={}",
                    errors.join(", ")
                )));
            }
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
        match self.proxy_addrs_by_proxy_key.get(proxy_key) {
            Some(proxy_addrs) => {
                let proxy_addrs = proxy_addrs.clone();
                let device_id = self.devices_by_proxy_addrs.get(&proxy_addrs).unwrap();
                if let Some(proxy_keys) = self.proxy_keys_by_device.get_mut(device_id) {
                    proxy_keys.retain(|key| !key.0.eq(proxy_key));
                    if proxy_keys.is_empty() {
                        self.proxy_keys_by_device.remove(device_id);
                    }
                }
                self.proxy_addrs_by_proxy_key.remove(proxy_key);
                self.devices_by_proxy_addrs.remove(&proxy_addrs);
                self.services_by_proxy_key
                    .lock()
                    .unwrap()
                    .remove(&proxy_key.to_string());
                true
            }

            None => false,
        }
    }
}

/// tls_client::std_client::Client strategy visitor pattern implementation
pub struct ServiceGatewayClientVisitor {
    /// Trust0 client user ID
    proxied_user_id: i64,
}

unsafe impl Send for ServiceGatewayClientVisitor {}

impl ServiceGatewayClientVisitor {
    /// ClientVisitor constructor
    ///
    /// # Arguments
    ///
    /// * `proxied_user_id` - Trust0 client device user ID
    ///
    /// # Returns
    ///
    /// A newly constructed [`ServiceGatewayClientVisitor`]
    ///
    pub fn new(proxied_user_id: i64) -> Self {
        Self { proxied_user_id }
    }

    /// Generate client access context session message
    ///
    /// # Returns
    ///
    /// The [`tls::message::SessionMessage`] of a [`tls::message::DataType::ClientAccessContext`]
    /// message type for the given user client device access context
    ///
    fn create_access_session_message(
        &self,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        Ok(Some(tls::message::SessionMessage::new(
            &tls::message::DataType::ClientAccessContext,
            &Some(
                serde_json::to_value(tls::message::ClientAccessContext {
                    access: CertAccessContext {
                        entity_type: EntityType::Gateway,
                        platform: "".to_string(),
                        user_id: self.proxied_user_id,
                    },
                })
                .unwrap(),
            ),
        )))
    }
}

impl tls_client::client_std::ClientVisitor for ServiceGatewayClientVisitor {
    fn create_server_conn(
        &mut self,
        tls_conn: tls_client::conn_std::TlsClientConnection,
        server_msg: Option<tls::message::SessionMessage>,
    ) -> Result<tls_client::conn_std::Connection, AppError> {
        let conn_visitor = ClientConnVisitor::new()?;

        let session_addrs = match server_msg {
            Some(msg) if msg.data_type == tls::message::DataType::Trust0Connection => {
                let t0_conn =
                    serde_json::from_value::<tls::message::Trust0Connection>(msg.data.unwrap())
                        .map_err(|err| {
                            AppError::General(format!(
                                "Invalid Trust0Connection json: err={:?}",
                                &err
                            ))
                        })?;
                Some(t0_conn.binds)
            }
            _ => None,
        };
        let session_addrs = match session_addrs {
            Some(addrs) => addrs,
            None => tls::message::Trust0Connection::create_connection_addrs(&tls_conn.sock),
        };

        tls_client::conn_std::Connection::new(Box::new(conn_visitor), tls_conn, &session_addrs)
    }

    fn on_client_msg_provider(
        &mut self,
        _tls_conn: &TlsClientConnection,
    ) -> Result<Option<tls::message::SessionMessage>, AppError> {
        self.create_access_session_message()
    }
}

/// tls_server::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {}

impl ServerConnVisitor {
    /// ServerConnVisitor constructor
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ServerConnVisitor`] object.
    ///
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {})
    }
}

impl tls_server::conn_std::ConnectionVisitor for ServerConnVisitor {
    fn send_error_response(&mut self, _err: &AppError) {}
}

unsafe impl Send for ServerConnVisitor {}

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ClientConnVisitor {}

impl ClientConnVisitor {
    /// ClientConnVisitor constructor
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ClientConnVisitor`] object.
    ///
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {})
    }
}

impl tls_client::conn_std::ConnectionVisitor for ClientConnVisitor {
    fn send_error_response(&mut self, _err: &AppError) {}
}

unsafe impl Send for ClientConnVisitor {}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use crate::service::manager::tests::MockSvcMgr;
    use crate::service::proxy::proxy_base;
    use rustls::StreamOwned;
    use std::sync;
    use std::sync::mpsc::TryRecvError;
    use trust0_common::crypto::alpn;
    use trust0_common::model::service::Transport;
    use trust0_common::net::stream_utils;
    use trust0_common::net::tls_server::server_std::ServerVisitor;

    #[test]
    fn svcgwproxy_new() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));
        let server_visitor = Arc::new(Mutex::new(ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            devices_by_proxy_addrs: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::new(),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        }));

        let _ = ServiceGatewayProxy::new(&app_config, server_visitor, 3000);
    }

    #[test]
    fn svcgwsvrproxyvisit_new() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));

        let result = ServiceGatewayProxyServerVisitor::new(
            &app_config,
            &service_mgr,
            &Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            &Some("gwhost1".to_string()),
            2000,
            &sync::mpsc::channel().0,
            &sync::mpsc::channel().0,
            &Arc::new(Mutex::new(HashMap::new())),
            &ProxyAddrs(2000, "host1".to_string(), 8888),
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn svcgwsvrproxyvisit_create_client_conn() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let connected_tcp_peer_addr = connected_tcp_stream.server_stream.0.peer_addr().unwrap();
        let connected_tcp_local_addr = connected_tcp_stream.server_stream.0.local_addr().unwrap();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            devices_by_proxy_addrs: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::new(),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        if let Err(err) = server_visitor.create_client_conn(
            StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(
                    proxy_base::tests::create_tls_server_config(
                        true,
                        vec![alpn::Protocol::create_service_protocol(200).into_bytes()],
                    )
                    .unwrap(),
                ))
                .unwrap(),
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.server_stream.0,
                    "svcgw-proxy-server",
                )
                .unwrap(),
            ),
            None,
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_device_id = "C:03e8:100";
        let expected_proxy_addrs = (
            format!("{:?}", connected_tcp_peer_addr),
            format!("{:?}", connected_tcp_local_addr),
        );

        assert!(server_visitor
            .devices_by_proxy_addrs
            .contains_key(&expected_proxy_addrs));
        assert_eq!(
            *server_visitor
                .devices_by_proxy_addrs
                .get(&expected_proxy_addrs)
                .unwrap(),
            expected_device_id.to_string()
        );
    }

    #[test]
    fn svcgwsvrproxyvisit_on_server_msg_provider() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            devices_by_proxy_addrs: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::new(),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        let server_msg_result = server_visitor.on_server_msg_provider(
            &rustls::ServerConnection::new(Arc::new(
                proxy_base::tests::create_tls_server_config(
                    true,
                    vec![alpn::Protocol::create_service_protocol(200).into_bytes()],
                )
                .unwrap(),
            ))
            .unwrap(),
            &connected_tcp_stream.server_stream.0,
        );

        if let Err(err) = server_msg_result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let server_msg = server_msg_result.unwrap();

        assert!(server_msg.is_some());
        assert_eq!(
            server_msg.unwrap(),
            tls::message::SessionMessage::new(
                &tls::message::DataType::Trust0Connection,
                &Some(
                    serde_json::to_value(tls::message::Trust0Connection::new(
                        &tls::message::Trust0Connection::create_connection_addrs(
                            &connected_tcp_stream.server_stream.0,
                        )
                    ))
                    .unwrap()
                )
            )
        )
    }

    #[test]
    fn svcgwsvrproxyvisit_on_conn_accepted_when_service_unresolvable() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "host".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            devices_by_proxy_addrs: HashMap::new(),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::new(),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "invalid svcgw host".to_string(), 8888),
        };

        let client_conn = server_visitor
            .create_client_conn(
                StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(
                        proxy_base::tests::create_tls_server_config(
                            true,
                            vec![alpn::Protocol::create_service_protocol(200).into_bytes()],
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
                    stream_utils::clone_std_tcp_stream(
                        &connected_tcp_stream.server_stream.0,
                        "test-tcp-proxy-server",
                    )
                    .unwrap(),
                ),
                None,
            )
            .unwrap();

        match server_visitor.on_conn_accepted(client_conn) {
            Ok(()) => panic!("Unexpected successful result"),
            Err(err) => {
                if !err.to_string().contains("Failed to resolve server host") {
                    panic!("Unexpected result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn svcgwsvrproxyvisit_on_conn_accepted_when_successful() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();
        let (proxy_events_sender, proxy_events_receiver) = sync::mpsc::channel();
        let services_by_proxy_key = Arc::new(Mutex::new(HashMap::new()));
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let connected_tcp_peer_addr = connected_tcp_stream.server_stream.0.peer_addr().unwrap();
        let connected_tcp_local_addr = connected_tcp_stream.server_stream.0.local_addr().unwrap();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));
        let expected_device_id = "C:03e8:100";
        let expected_proxy_addrs = (
            format!("{:?}", connected_tcp_peer_addr),
            format!("{:?}", connected_tcp_local_addr),
        );

        let tcp_listener = std::net::TcpListener::bind("localhost:0").unwrap();
        let svcgw_proxy_port = tcp_listener.local_addr().unwrap().port();
        let tls_server_config = Arc::new(
            proxy_base::tests::create_tls_server_config(
                true,
                vec![alpn::Protocol::create_service_protocol(200).into_bytes()],
            )
            .unwrap(),
        );
        proxy_base::tests::spawn_tls_server_listener(tcp_listener, tls_server_config, 1).unwrap();

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svc200-host".to_string(),
                port: 2000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender,
            proxy_events_sender,
            services_by_proxy_key: services_by_proxy_key.clone(),
            devices_by_proxy_addrs: HashMap::from([(
                expected_proxy_addrs.clone(),
                expected_device_id.to_string(),
            )]),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::new(),
            service_gateway_proxy_addrs: ProxyAddrs(
                2000,
                "localhost".to_string(),
                svcgw_proxy_port,
            ),
        };

        let client_conn = server_visitor
            .create_client_conn(
                StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(
                        proxy_base::tests::create_tls_server_config(
                            true,
                            vec![alpn::Protocol::create_service_protocol(200).into_bytes()],
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
                    stream_utils::clone_std_tcp_stream(
                        &connected_tcp_stream.server_stream.0,
                        "test-tcp-proxy-server",
                    )
                    .unwrap(),
                ),
                None,
            )
            .unwrap();

        if let Err(err) = server_visitor.on_conn_accepted(client_conn) {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::OpenTcpAndTcpProxy(_, _) => {}
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

        assert!(!services_by_proxy_key.lock().unwrap().is_empty());
        assert!(!server_visitor.proxy_addrs_by_proxy_key.is_empty());
        assert!(server_visitor
            .proxy_keys_by_device
            .contains_key(expected_device_id));
    }

    #[test]
    fn svcgwsvrproxyvisit_accessors_and_mutators() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service = Service {
            service_id: 200,
            name: "svc200".to_string(),
            transport: Transport::TCP,
            host: "svchost1".to_string(),
            port: 4000,
        };

        let device100_id = "C:03e8:100";
        let device101_id = "C:a756:101";

        let server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: Arc::new(Mutex::new(MockSvcMgr::new())),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: sync::mpsc::channel().0,
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::new())),
            devices_by_proxy_addrs: HashMap::from([
                (
                    ("addr1".to_string(), "addr2".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr3".to_string(), "addr4".to_string()),
                    device101_id.to_string(),
                ),
                (
                    ("addr5".to_string(), "addr6".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr7".to_string(), "addr8".to_string()),
                    device101_id.to_string(),
                ),
            ]),
            proxy_addrs_by_proxy_key: HashMap::new(),
            proxy_keys_by_device: HashMap::from([
                (
                    device100_id.to_string(),
                    vec![
                        (
                            "key1".to_string(),
                            ("addr1".to_string(), "addr2".to_string()),
                        ),
                        (
                            "key2".to_string(),
                            ("addr5".to_string(), "addr6".to_string()),
                        ),
                    ],
                ),
                (
                    device101_id.to_string(),
                    vec![(
                        "key3".to_string(),
                        ("addr3".to_string(), "addr4".to_string()),
                    )],
                ),
            ]),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        assert_eq!(server_visitor.get_service(), service);
        assert!(server_visitor.get_proxy_host().is_some());
        assert_eq!(server_visitor.get_proxy_host().unwrap(), "gwhost1");
        assert_eq!(server_visitor.get_proxy_port(), 2000);

        let expected_proxy_keys = vec![
            (
                "key1".to_string(),
                ("addr1".to_string(), "addr2".to_string()),
            ),
            (
                "key2".to_string(),
                ("addr5".to_string(), "addr6".to_string()),
            ),
        ];
        let mut proxy_keys = server_visitor.get_proxy_keys_for_device(device100_id);
        proxy_keys.sort();
        assert_eq!(proxy_keys, expected_proxy_keys);
    }

    #[test]
    fn svcgwsvrproxyvisit_shutdown_connections_when_no_device_supplied() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();

        let device100_id = "C:03e8:100";
        let device101_id = "C:a756:101";

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: Arc::new(Mutex::new(MockSvcMgr::new())),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::from([
                ("key1".to_string(), 200),
                ("key2".to_string(), 200),
                ("key3".to_string(), 201),
            ]))),
            devices_by_proxy_addrs: HashMap::from([
                (
                    ("addr1".to_string(), "addr2".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr3".to_string(), "addr4".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr5".to_string(), "addr6".to_string()),
                    device101_id.to_string(),
                ),
            ]),
            proxy_addrs_by_proxy_key: HashMap::from([
                (
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string()),
                ),
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string()),
                ),
                (
                    "key3".to_string(),
                    ("addr5".to_string(), "addr6".to_string()),
                ),
            ]),
            proxy_keys_by_device: HashMap::from([
                (
                    device100_id.to_string(),
                    vec![
                        (
                            "key1".to_string(),
                            ("addr1".to_string(), "addr2".to_string()),
                        ),
                        (
                            "key2".to_string(),
                            ("addr3".to_string(), "addr4".to_string()),
                        ),
                    ],
                ),
                (
                    device101_id.to_string(),
                    vec![(
                        "key3".to_string(),
                        ("addr5".to_string(), "addr6".to_string()),
                    )],
                ),
            ]),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        if let Err(err) = server_visitor.shutdown_connections(&proxy_tasks_sender, None) {
            panic!("Unexpected result: err={:?}", &err);
        }

        for _ in 0..3 {
            match proxy_tasks_receiver.try_recv() {
                Ok(proxy_task) => match proxy_task {
                    ProxyExecutorEvent::Close(key) => {
                        assert!(key == "key1" || key == "key2" || key == "key3")
                    }
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
        }

        assert!(server_visitor.proxy_addrs_by_proxy_key.is_empty());
        assert!(server_visitor.devices_by_proxy_addrs.is_empty());
        assert!(server_visitor.proxy_keys_by_device.is_empty());
        assert!(server_visitor
            .services_by_proxy_key
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn svcgwsvrproxyvisit_shutdown_connections_when_device_supplied() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();

        let device100_id = "C:03e8:100";
        let device101_id = "C:a756:101";

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: Arc::new(Mutex::new(MockSvcMgr::new())),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::from([
                ("key1".to_string(), 200),
                ("key2".to_string(), 200),
                ("key3".to_string(), 201),
            ]))),
            devices_by_proxy_addrs: HashMap::from([
                (
                    ("addr1".to_string(), "addr2".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr3".to_string(), "addr4".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr5".to_string(), "addr6".to_string()),
                    device101_id.to_string(),
                ),
            ]),
            proxy_addrs_by_proxy_key: HashMap::from([
                (
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string()),
                ),
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string()),
                ),
                (
                    "key3".to_string(),
                    ("addr5".to_string(), "addr6".to_string()),
                ),
            ]),
            proxy_keys_by_device: HashMap::from([
                (
                    device100_id.to_string(),
                    vec![
                        (
                            "key1".to_string(),
                            ("addr1".to_string(), "addr2".to_string()),
                        ),
                        (
                            "key2".to_string(),
                            ("addr3".to_string(), "addr4".to_string()),
                        ),
                    ],
                ),
                (
                    device101_id.to_string(),
                    vec![(
                        "key3".to_string(),
                        ("addr5".to_string(), "addr6".to_string()),
                    )],
                ),
            ]),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        if let Err(err) =
            server_visitor.shutdown_connections(&proxy_tasks_sender, Some(device100_id.to_string()))
        {
            panic!("Unexpected result: err={:?}", &err);
        }

        for _ in 0..2 {
            match proxy_tasks_receiver.try_recv() {
                Ok(proxy_task) => match proxy_task {
                    ProxyExecutorEvent::Close(key) => assert!(key == "key1" || key == "key2"),
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
        }

        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 1);
        assert_eq!(
            server_visitor.proxy_addrs_by_proxy_key.get("key3"),
            Some(&("addr5".to_string(), "addr6".to_string()))
        );
        assert_eq!(server_visitor.devices_by_proxy_addrs.len(), 1);
        assert_eq!(
            server_visitor
                .devices_by_proxy_addrs
                .get(&("addr5".to_string(), "addr6".to_string())),
            Some(device101_id.to_string()).as_ref()
        );
        assert_eq!(server_visitor.proxy_keys_by_device.len(), 1);
        assert_eq!(
            server_visitor.proxy_keys_by_device.get(device101_id),
            Some(&vec![(
                "key3".to_string(),
                ("addr5".to_string(), "addr6".to_string())
            )])
        );
        assert_eq!(
            server_visitor.services_by_proxy_key.lock().unwrap().len(),
            1
        );
        assert_eq!(
            server_visitor
                .services_by_proxy_key
                .lock()
                .unwrap()
                .get("key3"),
            Some(&201)
        );
    }

    #[test]
    fn svcgwsvrproxyvisit_shutdown_connection_when_proxy_key_known() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();

        let device100_id = "C:03e8:100";
        let device101_id = "C:a756:101";

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: Arc::new(Mutex::new(MockSvcMgr::new())),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::from([
                ("key1".to_string(), 200),
                ("key2".to_string(), 200),
                ("key3".to_string(), 201),
            ]))),
            devices_by_proxy_addrs: HashMap::from([
                (
                    ("addr1".to_string(), "addr2".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr3".to_string(), "addr4".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr5".to_string(), "addr6".to_string()),
                    device101_id.to_string(),
                ),
            ]),
            proxy_addrs_by_proxy_key: HashMap::from([
                (
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string()),
                ),
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string()),
                ),
                (
                    "key3".to_string(),
                    ("addr5".to_string(), "addr6".to_string()),
                ),
            ]),
            proxy_keys_by_device: HashMap::from([
                (
                    device100_id.to_string(),
                    vec![
                        (
                            "key1".to_string(),
                            ("addr1".to_string(), "addr2".to_string()),
                        ),
                        (
                            "key2".to_string(),
                            ("addr3".to_string(), "addr4".to_string()),
                        ),
                    ],
                ),
                (
                    device101_id.to_string(),
                    vec![(
                        "key3".to_string(),
                        ("addr5".to_string(), "addr6".to_string()),
                    )],
                ),
            ]),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        if let Err(err) = server_visitor.shutdown_connection(&proxy_tasks_sender, "key3") {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key3"),
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

        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 2);
        assert_eq!(
            server_visitor.proxy_addrs_by_proxy_key.get("key1"),
            Some(&("addr1".to_string(), "addr2".to_string()))
        );
        assert_eq!(
            server_visitor.proxy_addrs_by_proxy_key.get("key2"),
            Some(&("addr3".to_string(), "addr4".to_string()))
        );
        assert_eq!(server_visitor.devices_by_proxy_addrs.len(), 2);
        assert_eq!(
            server_visitor
                .devices_by_proxy_addrs
                .get(&("addr1".to_string(), "addr2".to_string())),
            Some(device100_id.to_string()).as_ref()
        );
        assert_eq!(
            server_visitor
                .devices_by_proxy_addrs
                .get(&("addr3".to_string(), "addr4".to_string())),
            Some(device100_id.to_string()).as_ref()
        );
        assert_eq!(server_visitor.proxy_keys_by_device.len(), 1);
        assert_eq!(
            server_visitor.proxy_keys_by_device.get(device100_id),
            Some(&vec![
                (
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string())
                ),
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string())
                )
            ])
        );
        assert_eq!(
            server_visitor.services_by_proxy_key.lock().unwrap().len(),
            2
        );
        assert_eq!(
            server_visitor
                .services_by_proxy_key
                .lock()
                .unwrap()
                .get("key1"),
            Some(&200)
        );
        assert_eq!(
            server_visitor
                .services_by_proxy_key
                .lock()
                .unwrap()
                .get("key2"),
            Some(&200)
        );
    }

    #[test]
    fn svcgwsvrproxyvisit_shutdown_connection_when_proxy_key_unknown() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Client,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();

        let device100_id = "C:03e8:100";
        let device101_id = "C:a756:101";

        let mut server_visitor = ServiceGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: Arc::new(Mutex::new(MockSvcMgr::new())),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "svchost1".to_string(),
                port: 4000,
            },
            proxy_host: Some("gwhost1".to_string()),
            proxy_port: 2000,
            proxy_tasks_sender: proxy_tasks_sender.clone(),
            proxy_events_sender: sync::mpsc::channel().0,
            services_by_proxy_key: Arc::new(Mutex::new(HashMap::from([
                ("key1".to_string(), 200),
                ("key2".to_string(), 200),
                ("key3".to_string(), 201),
            ]))),
            devices_by_proxy_addrs: HashMap::from([
                (
                    ("addr1".to_string(), "addr2".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr3".to_string(), "addr4".to_string()),
                    device100_id.to_string(),
                ),
                (
                    ("addr5".to_string(), "addr6".to_string()),
                    device101_id.to_string(),
                ),
            ]),
            proxy_addrs_by_proxy_key: HashMap::from([
                (
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string()),
                ),
                (
                    "key2".to_string(),
                    ("addr3".to_string(), "addr4".to_string()),
                ),
                (
                    "key3".to_string(),
                    ("addr5".to_string(), "addr6".to_string()),
                ),
            ]),
            proxy_keys_by_device: HashMap::from([
                (
                    device100_id.to_string(),
                    vec![
                        (
                            "key1".to_string(),
                            ("addr1".to_string(), "addr2".to_string()),
                        ),
                        (
                            "key2".to_string(),
                            ("addr3".to_string(), "addr4".to_string()),
                        ),
                    ],
                ),
                (
                    device101_id.to_string(),
                    vec![(
                        "key3".to_string(),
                        ("addr5".to_string(), "addr6".to_string()),
                    )],
                ),
            ]),
            service_gateway_proxy_addrs: ProxyAddrs(2000, "host1".to_string(), 8888),
        };

        if let Err(err) = server_visitor.shutdown_connection(&proxy_tasks_sender, "key4") {
            panic!("Unexpected result: err={:?}", &err);
        }

        match proxy_tasks_receiver.try_recv() {
            Ok(proxy_task) => match proxy_task {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key4"),
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

        assert_eq!(server_visitor.proxy_addrs_by_proxy_key.len(), 3);
        assert_eq!(server_visitor.devices_by_proxy_addrs.len(), 3);
        assert_eq!(server_visitor.proxy_keys_by_device.len(), 2);
        assert_eq!(
            server_visitor.services_by_proxy_key.lock().unwrap().len(),
            3
        );
    }

    #[test]
    fn svrconnvisit_new() {
        let visitor = ServerConnVisitor::new();
        assert!(visitor.is_ok());
    }

    #[test]
    fn svrconnvisit_send_error_response() {
        use trust0_common::net::tls_server::conn_std::ConnectionVisitor;
        let mut visitor = ServerConnVisitor {};
        visitor.send_error_response(&AppError::StreamEOF);
    }

    #[test]
    fn cliconnvisit_new() {
        let visitor = ClientConnVisitor::new();
        assert!(visitor.is_ok());
    }

    #[test]
    fn cliconnvisit_send_error_response() {
        use trust0_common::net::tls_client::conn_std::ConnectionVisitor;
        let mut visitor = ClientConnVisitor {};
        visitor.send_error_response(&AppError::StreamEOF);
    }
}
