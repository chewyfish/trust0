use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

#[cfg(test)]
use ::time::macros::datetime;
use anyhow::Result;
use rustls::server::Accepted;
use rustls::ServerConfig;
use trust0_common::control::tls;
use trust0_common::control::tls::message::ConnectionAddrs;
use trust0_common::crypto::alpn;
#[cfg(test)]
use x509_parser::prelude::{ASN1Time, Validity};

use crate::client::connection::ClientConnVisitor;
#[cfg(test)]
use crate::client::device::Device;
use crate::config::AppConfig;
use crate::service::manager::ServiceMgr;
use crate::service::proxy::proxy_base::{GatewayServiceProxy, GatewayServiceProxyVisitor};
#[cfg(test)]
use trust0_common::crypto::ca::{CertAccessContext, EntityType};
use trust0_common::error::AppError;
use trust0_common::model::service::Service;
#[cfg(test)]
use trust0_common::model::user;
use trust0_common::net::stream_utils;
use trust0_common::net::tls_server::conn_std::TlsServerConnection;
use trust0_common::net::tls_server::{conn_std, server_std};
use trust0_common::proxy::event::ProxyEvent;
use trust0_common::proxy::executor::ProxyExecutorEvent;
use trust0_common::proxy::proxy_base::ProxyType;
use trust0_common::sync;

/// Gateway service proxy (TCP trust0 gateway <-> TCP service)
pub struct TcpGatewayProxy {
    /// TLS server (delegate) for given service proxy
    tls_server: server_std::Server,
}

impl TcpGatewayProxy {
    /// TcpGatewayProxy constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `server_visitor` - Server visitor pattern object
    /// * `proxy_port` - Port to use for binding server listener
    ///
    /// # Returns
    ///
    /// A newly constructed [`TcpGatewayProxy`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        server_visitor: Arc<Mutex<TcpGatewayProxyServerVisitor>>,
        proxy_port: u16,
    ) -> Self {
        Self {
            tls_server: server_std::Server::new(
                server_visitor,
                &app_config.server_host,
                proxy_port,
                false,
            ),
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
}

impl TcpGatewayProxyServerVisitor {
    #[allow(clippy::too_many_arguments)]
    /// TcpGatewayProxyServerVisitor constructor
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
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`TcpGatewayProxyServerVisitor`] object.
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
        })
    }

    /// Client connection authentication/authorization enforcement
    /// If valid auth, return tuple of: connection visitor; device ID; user ID; ALPN protocol
    ///
    /// # Arguments
    ///
    /// * `tls_conn` - TLS server connection object
    ///
    /// # Returns
    ///
    /// A [`Result`] containing tuple of: connection visitor; device ID; user ID; ALPN protocol
    ///
    #[cfg(not(test))]
    fn process_connection_authorization(
        &self,
        tls_conn: &TlsServerConnection,
    ) -> Result<(ClientConnVisitor, String, i64, alpn::Protocol), AppError> {
        let mut conn_visitor = ClientConnVisitor::new(&self.app_config, &self.service_mgr);
        let protocol =
            conn_visitor.process_authorization(tls_conn, Some(self.service.service_id))?;
        let device_id = conn_visitor.get_device().as_ref().unwrap().get_id();
        let user_id = conn_visitor.get_user().as_ref().unwrap().user_id;
        Ok((conn_visitor, device_id.to_string(), user_id, protocol))
    }
    #[cfg(test)]
    fn process_connection_authorization(
        &self,
        _tls_conn: &TlsServerConnection,
    ) -> Result<(ClientConnVisitor, String, i64, alpn::Protocol), AppError> {
        let mut conn_visitor = ClientConnVisitor::new(&self.app_config, &self.service_mgr);
        let device = Device {
            cert_subj: HashMap::new(),
            cert_alt_subj: HashMap::new(),
            cert_access_context: CertAccessContext {
                entity_type: EntityType::Client,
                platform: "plat1".to_string(),
                user_id: 100,
            },
            cert_serial_num: vec![0x03u8, 0xe8u8],
            cert_validity: Validity {
                not_before: ASN1Time::from(datetime!(2025-12-21 19:04:45.0 +00:00:00)),
                not_after: ASN1Time::from(datetime!(2100-01-01 0:00:00.0 +00:00:00)),
            },
        };
        let user = user::User::new(100, None, None, "name100", &user::Status::Active, &[]);
        conn_visitor.set_device(Some(device.clone()));
        conn_visitor.set_user(Some(user.clone()));
        conn_visitor.set_protocol(Some(alpn::Protocol::Service(200)));
        Ok((
            conn_visitor,
            device.get_id(),
            user.user_id,
            alpn::Protocol::Service(200),
        ))
    }
}

impl server_std::ServerVisitor for TcpGatewayProxyServerVisitor {
    fn create_client_conn(
        &mut self,
        tls_conn: TlsServerConnection,
        _client_msg: Option<tls::message::SessionMessage>,
    ) -> Result<conn_std::Connection, AppError> {
        let (conn_visitor, device_id, _user_id, alpn_protocol) =
            self.process_connection_authorization(&tls_conn)?;
        let conn_addrs = tls::message::Trust0Connection::create_connection_addrs(&tls_conn.sock);
        self.devices_by_proxy_addrs
            .insert(conn_addrs.clone(), device_id);
        conn_std::Connection::new(
            Box::new(conn_visitor),
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

    fn on_conn_accepted(&mut self, connection: conn_std::Connection) -> Result<(), AppError> {
        // Make connection to service

        let mut service_stream: Option<TcpStream> = None;
        let mut response_err = None;

        let resolved_host = self
            .app_config
            .dns_client
            .lookup_ip(self.service.host.as_str())
            .map_err(|err| {
                AppError::General(format!(
                    "Failed resolving host: host={}, err={:?}",
                    &self.service.host, &err
                ))
            })?;

        for host_addr in resolved_host.into_iter() {
            let service_addr = SocketAddr::new(host_addr, self.service.port);

            match TcpStream::connect(service_addr) {
                Ok(socket) => {
                    let tcp_socket_str = format!("{:?}", &socket);
                    stream_utils::set_std_tcp_stream_blocking_and_delay(
                        &socket,
                        false,
                        false,
                        Box::new(move || format!("socket={:?}", &tcp_socket_str)),
                    )?;
                    service_stream = Some(socket);
                    break;
                }
                Err(err) => {
                    response_err = Some(AppError::General(format!(
                        "Failed connect to service endpoint(s): addr={:?}, svc={:?}, err={:?}",
                        &service_addr, &self.service, &err
                    )));
                }
            }
        }

        if service_stream.is_none() {
            return match response_err {
                Some(err) => Err(err),
                None => Err(AppError::General(format!(
                    "No resolved service endpoints: svc={:?}",
                    &self.service
                ))),
            };
        }

        let service_stream = service_stream.unwrap();

        // Send request to proxy executor to startup new proxy

        let tcp_stream = connection.get_tcp_stream();
        let proxy_addrs = connection.get_session_addrs().clone();
        let proxy_key = ProxyEvent::key_value(
            &ProxyType::TcpAndTcp,
            &tcp_stream.peer_addr().ok(),
            &service_stream.peer_addr().ok(),
        );
        let client_stream = stream_utils::clone_std_tcp_stream(tcp_stream, "tcp-proxy-server")?;
        let service_stream_copy =
            stream_utils::clone_std_tcp_stream(&service_stream, "tcp-proxy-server-service")?;

        let open_proxy_request = ProxyExecutorEvent::OpenTcpAndTcpProxy(
            proxy_key.clone(),
            (
                client_stream,
                service_stream,
                Arc::new(Mutex::new(Box::<TlsServerConnection>::new(
                    connection.into(),
                ))),
                Arc::new(Mutex::new(Box::new(service_stream_copy))),
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
    fn tcpgwproxy_new() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));
        let server_visitor = Arc::new(Mutex::new(TcpGatewayProxyServerVisitor {
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
        }));

        let _ = TcpGatewayProxy::new(&app_config, server_visitor, 3000);
    }

    #[test]
    fn tcpsvrproxyvisit_new() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));

        let result = TcpGatewayProxyServerVisitor::new(
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
        );

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn tcpsvrproxyvisit_create_client_conn() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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

        let mut server_visitor = TcpGatewayProxyServerVisitor {
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
        };

        if let Err(err) = server_visitor.create_client_conn(
            StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(
                    proxy_base::tests::create_tls_server_config(vec![
                        alpn::Protocol::create_service_protocol(200).into_bytes(),
                    ])
                    .unwrap(),
                ))
                .unwrap(),
                stream_utils::clone_std_tcp_stream(
                    &connected_tcp_stream.server_stream.0,
                    "tcp-proxy-server",
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
    fn tcpsvrproxyvisit_on_server_msg_provider() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));

        let mut server_visitor = TcpGatewayProxyServerVisitor {
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
        };

        let server_msg_result = server_visitor.on_server_msg_provider(
            &rustls::ServerConnection::new(Arc::new(
                proxy_base::tests::create_tls_server_config(vec![
                    alpn::Protocol::create_service_protocol(200).into_bytes(),
                ])
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
    fn tcpsvrproxyvisit_on_conn_accepted_when_service_unresolvable() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
                Arc::new(Mutex::new(MockUserRepo::new())),
                Arc::new(Mutex::new(MockServiceRepo::new())),
                Arc::new(Mutex::new(MockRoleRepo::new())),
                Arc::new(Mutex::new(MockAccessRepo::new())),
            )
            .unwrap(),
        );
        let connected_tcp_stream = stream_utils::ConnectedTcpStream::new().unwrap();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));

        let mut server_visitor = TcpGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "invalid svc200 host".to_string(),
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
        };

        let client_conn = server_visitor
            .create_client_conn(
                StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(
                        proxy_base::tests::create_tls_server_config(vec![
                            alpn::Protocol::create_service_protocol(200).into_bytes(),
                        ])
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
                if !err.to_string().contains("resolving host")
                    && !err.to_string().contains("resolved service endpoint")
                {
                    panic!("Unexpected result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn tcpsvrproxyvisit_on_conn_accepted_when_successful() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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
        let server_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let service_port = server_listener.local_addr().unwrap().port();
        let service_mgr = Arc::new(Mutex::new(MockSvcMgr::new()));
        let expected_device_id = "C:03e8:100";
        let expected_proxy_addrs = (
            format!("{:?}", connected_tcp_peer_addr),
            format!("{:?}", connected_tcp_local_addr),
        );

        let mut server_visitor = TcpGatewayProxyServerVisitor {
            app_config: app_config.clone(),
            service_mgr: service_mgr.clone(),
            service: Service {
                service_id: 200,
                name: "svc200".to_string(),
                transport: Transport::TCP,
                host: "localhost".to_string(),
                port: service_port,
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
        };

        let client_conn = server_visitor
            .create_client_conn(
                StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(
                        proxy_base::tests::create_tls_server_config(vec![
                            alpn::Protocol::create_service_protocol(200).into_bytes(),
                        ])
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
    fn tcpsvrproxyvisit_accessors_and_mutators() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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

        let server_visitor = TcpGatewayProxyServerVisitor {
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
    fn tcpsvrproxyvisit_shutdown_connections_when_no_device_supplied() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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

        let mut server_visitor = TcpGatewayProxyServerVisitor {
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
    fn tcpsvrproxyvisit_shutdown_connections_when_device_supplied() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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

        let mut server_visitor = TcpGatewayProxyServerVisitor {
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
    fn tcpsvrproxyvisit_shutdown_connection_when_proxy_key_known() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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

        let mut server_visitor = TcpGatewayProxyServerVisitor {
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
    fn tcpsvrproxyvisit_shutdown_connection_when_proxy_key_unknown() {
        let app_config = Arc::new(
            config::tests::create_app_config_with_repos(
                config::GatewayType::Service,
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

        let mut server_visitor = TcpGatewayProxyServerVisitor {
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
}
