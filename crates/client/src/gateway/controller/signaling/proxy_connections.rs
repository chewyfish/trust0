use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::Value;
use serde_json::Value::Array;

use crate::gateway::controller::signaling::SignalingEventHandler;
use crate::service::manager::ServiceMgr;
use trust0_common::control::signaling::event::{EventType, SignalEvent};
use trust0_common::control::signaling::heartbeat::ProxyConnectionEvent;
use trust0_common::control::tls::message::ConnectionAddrs;
use trust0_common::error::AppError;
use trust0_common::error::AppError::General;
use trust0_common::logging::{error, warn};
use trust0_common::{control, target};

const LIVENESS_MAX_CONSECUTIVE_MISSING_CONNECTION_PROBES: u16 = 5;
const LIVENESS_MAX_CONSECUTIVE_MISSING_SIGNAL_PROBES: u16 = 5;

/// Process inbound proxy connections signaling message events
pub struct ProxyConnectionsProcessor {
    /// Service manager
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    /// Queued PDU responses to be sent to client
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Missing connection bind addresses
    /// key: (client bind address, gateway bind address)
    /// value: (missing count, service ID, proxy key)
    missing_connection_binds: HashMap<ConnectionAddrs, (u16, u64, String)>,
    /// Missing signal event probes
    missing_signal_probes: u16,
}

impl ProxyConnectionsProcessor {
    /// ProxyConnectionsProcessor constructor
    ///
    /// # Arguments
    ///
    /// * `service_mgr` - Service manager
    /// * `message_outbox` - Queued PDU responses to be sent to client
    ///
    /// # Returns
    ///
    /// A newly constructed [`ProxyConnectionsProcessor`] object.
    ///
    pub fn new(
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        message_outbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Self {
        Self {
            service_mgr: service_mgr.clone(),
            message_outbox: message_outbox.clone(),
            missing_connection_binds: HashMap::new(),
            missing_signal_probes: 0,
        }
    }

    /// Gather proxy keys/addresses for service proxy connections.
    ///
    /// # Returns
    ///
    /// A map of (`service ID`, (`service name`, Vec<(`proxy key`, `proxy addrs`)>)) corresponding to proxy connections.
    ///
    fn current_proxy_keys(&self) -> HashMap<u64, (String, Vec<(String, ConnectionAddrs)>)> {
        let service_proxies = self.service_mgr.lock().unwrap().get_service_proxies();
        service_proxies
            .iter()
            .map(|service_proxy| {
                let service_proxy = service_proxy.lock().unwrap();
                let service = service_proxy.get_service();
                (
                    service.service_id,
                    (service.name.clone(), service_proxy.get_proxy_keys().clone()),
                )
            })
            .collect::<HashMap<u64, (String, Vec<(String, ConnectionAddrs)>)>>()
    }

    /// Process inbound proxy connections signal event
    ///
    /// # Arguments
    ///
    /// * `service_mgr` - Service manager
    /// * `proxy_keys` - Current proxy keys and address binds
    /// * `signal_event` - Proxy connections signal event
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    #[allow(clippy::type_complexity)]
    fn process_inbound_event(
        &mut self,
        service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
        proxy_keys: &HashMap<u64, (String, Vec<(String, ConnectionAddrs)>)>,
        signal_event: &SignalEvent,
    ) -> Result<(), AppError> {
        let mut proxy_context_map = HashMap::new();
        let mut missing_conn_binds = HashMap::new();
        let mut shutdown_conn_binds = Vec::new();

        // Set up client/gateway connection address sets
        let client_conn_addrs: HashSet<ConnectionAddrs> = match &signal_event.data {
            None => HashSet::new(),
            Some(data) => HashSet::from_iter(
                ProxyConnectionEvent::from_serde_value(data)?
                    .iter()
                    .flat_map(|proxy_conn| proxy_conn.binds.clone())
                    .map(|proxy_addrs| {
                        (
                            #[allow(clippy::get_first)]
                            proxy_addrs.get(0).as_ref().unwrap().to_string(),
                            proxy_addrs.get(1).as_ref().unwrap().to_string(),
                        )
                    })
                    .collect::<HashSet<ConnectionAddrs>>(),
            ),
        };

        let mut gateway_conn_addrs: HashSet<ConnectionAddrs> = HashSet::new();
        for (service_id, (_, service_proxy_keys)) in proxy_keys {
            for service_proxy_key in service_proxy_keys {
                proxy_context_map.insert(
                    service_proxy_key.1.clone(),
                    (service_id, service_proxy_key.0.clone()),
                );
                gateway_conn_addrs.insert(service_proxy_key.1.clone());
            }
        }

        // Determine missing connections from client set
        for missing_conn_bind in gateway_conn_addrs.difference(&client_conn_addrs) {
            match self.missing_connection_binds.get(missing_conn_bind) {
                None => {
                    let (service_id, proxy_key) =
                        proxy_context_map.get(missing_conn_bind).unwrap().clone();
                    missing_conn_binds.insert(
                        missing_conn_bind.clone(),
                        (1, *service_id, proxy_key.clone()),
                    );
                }
                Some((count, service_id, proxy_key)) => {
                    let missing_count = count + 1;
                    if missing_count >= LIVENESS_MAX_CONSECUTIVE_MISSING_CONNECTION_PROBES {
                        shutdown_conn_binds.push((
                            *service_id,
                            proxy_key.clone(),
                            missing_conn_bind.clone(),
                        ));
                    } else {
                        missing_conn_binds.insert(
                            missing_conn_bind.clone(),
                            (missing_count, *service_id, proxy_key.clone()),
                        );
                    }
                }
            }
        }

        self.missing_connection_binds = missing_conn_binds;

        // Shutdown dead connections
        let mut errors: Vec<String> = vec![];

        for shutdown_conn_bind in &shutdown_conn_binds {
            warn(
                &target!(),
                &format!(
                    "Shutting down dead proxy connection: svc_id={}, proxy_addrs={:?}",
                    shutdown_conn_bind.0, shutdown_conn_bind.1
                ),
            );

            if let Err(err) = service_mgr
                .lock()
                .unwrap()
                .shutdown_connection(shutdown_conn_bind.0, &shutdown_conn_bind.1)
            {
                errors.push(format!("{:?}", &err));
            }
        }

        if !errors.is_empty() {
            Err(General(format!(
                "Error shutting down connection(s): errs={}",
                errors.join(", ")
            )))
        } else {
            Ok(())
        }
    }

    /// Process outbound proxy connections signal event
    ///
    /// # Arguments
    ///
    /// * `proxy_keys` - Current proxy keys and address binds
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    #[allow(clippy::type_complexity)]
    fn process_outbound_event(
        &mut self,
        proxy_keys: &HashMap<u64, (String, Vec<(String, ConnectionAddrs)>)>,
    ) -> Result<(), AppError> {
        let mut proxy_connections: Vec<Value> = Vec::new();

        for (service_name, service_proxy_keys) in proxy_keys.values() {
            proxy_connections.push(
                ProxyConnectionEvent::new(
                    service_name.as_str(),
                    &service_proxy_keys
                        .iter()
                        .map(|k| vec![k.1 .0.to_string(), k.1 .1.to_string()])
                        .collect::<Vec<Vec<String>>>(),
                )
                .try_into()
                .unwrap(),
            );
        }

        self.message_outbox.lock().unwrap().push_back(
            control::pdu::MessageFrame::new(
                control::pdu::ControlChannel::Signaling,
                control::pdu::CODE_OK,
                &None,
                &Some(serde_json::to_value(EventType::ProxyConnections).unwrap()),
                &Some(Array(proxy_connections)),
            )
            .build_pdu()?,
        );

        Ok(())
    }
}

unsafe impl Send for ProxyConnectionsProcessor {}

impl SignalingEventHandler for ProxyConnectionsProcessor {
    fn on_loop_cycle(&mut self, signal_events: VecDeque<SignalEvent>) -> Result<(), AppError> {
        let proxy_keys = self.current_proxy_keys();
        let service_mgr = self.service_mgr.clone();

        // Process inbound message(s)
        if !signal_events.is_empty() {
            self.missing_signal_probes = 0;

            for signal_event in signal_events {
                if let Err(err) =
                    self.process_inbound_event(&service_mgr, &proxy_keys, &signal_event)
                {
                    error(&target!(), &format!("{:?}", &err));
                }
            }
        }
        // Process missing signal event
        else {
            self.missing_signal_probes += 1;
            if self.missing_signal_probes >= LIVENESS_MAX_CONSECUTIVE_MISSING_SIGNAL_PROBES {
                return Err(AppError::General(
                    "Gateway not responsive, closing all connections".to_string(),
                ));
            }
        }

        // Process outbound message
        self.process_outbound_event(&proxy_keys)
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::service::manager::tests::MockSvcMgr;
    use crate::service::proxy::proxy_base::tests::MockCliSvcProxyVisitor;
    use mockall::predicate;
    use serde_json::json;
    use trust0_common::control::pdu;
    use trust0_common::control::pdu::ControlChannel;
    use trust0_common::model;

    // utils
    // =====

    fn create_processor(
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Result<ProxyConnectionsProcessor, AppError> {
        Ok(ProxyConnectionsProcessor {
            service_mgr,
            message_outbox,
            missing_connection_binds: HashMap::new(),
            missing_signal_probes: 0,
        })
    }

    // tests
    // =====

    #[test]
    fn proxyconnproc_new() {
        let service_mgr: Arc<Mutex<dyn ServiceMgr>> = Arc::new(Mutex::new(MockSvcMgr::new()));
        let processor =
            ProxyConnectionsProcessor::new(&service_mgr, &Arc::new(Mutex::new(VecDeque::new())));

        assert!(processor.missing_connection_binds.is_empty());
        assert_eq!(processor.missing_signal_probes, 0);
    }

    #[test]
    fn proxyconnproc_current_proxy_keys() {
        let mut service_mgr = MockSvcMgr::new();
        let mut service_proxy = MockCliSvcProxyVisitor::new();
        service_proxy
            .expect_get_service()
            .times(1)
            .return_once(|| model::service::Service {
                service_id: 200,
                name: "Service200".to_string(),
                transport: model::service::Transport::TCP,
                host: "localhost".to_string(),
                port: 8200,
            });
        service_proxy
            .expect_get_proxy_keys()
            .times(1)
            .return_once(move || {
                vec![(
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string()),
                )]
            });
        service_mgr
            .expect_get_service_proxies()
            .times(1)
            .return_once(move || vec![Arc::new(Mutex::new(service_proxy))]);

        let processor = create_processor(
            Arc::new(Mutex::new(service_mgr)),
            Arc::new(Mutex::new(VecDeque::new())),
        );

        let proxy_keys = processor.unwrap().current_proxy_keys();

        assert!(proxy_keys.contains_key(&200));
        assert_eq!(
            *proxy_keys.get(&200).unwrap(),
            (
                "Service200".to_string(),
                vec![(
                    "key1".to_string(),
                    ("addr1".to_string(), "addr2".to_string())
                )]
            )
        );
    }

    #[test]
    fn proxyconnproc_on_loop_cycle_when_1_found_and_1_missing_and_1_dead() {
        let mut service_mgr = MockSvcMgr::new();
        let mut service_proxy = MockCliSvcProxyVisitor::new();
        service_proxy
            .expect_get_service()
            .times(1)
            .return_once(|| model::service::Service {
                service_id: 200,
                name: "Service200".to_string(),
                transport: model::service::Transport::TCP,
                host: "localhost".to_string(),
                port: 8200,
            });
        service_proxy
            .expect_get_proxy_keys()
            .times(1)
            .return_once(move || {
                vec![
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
                ]
            });
        service_mgr
            .expect_get_service_proxies()
            .times(1)
            .return_once(move || vec![Arc::new(Mutex::new(service_proxy))]);
        service_mgr
            .expect_shutdown_connection()
            .with(predicate::eq(200), predicate::eq("key3".to_string()))
            .times(1)
            .return_once(|_, _| Ok(()));

        let mut processor = create_processor(
            Arc::new(Mutex::new(service_mgr)),
            Arc::new(Mutex::new(VecDeque::new())),
        )
        .unwrap();
        processor.missing_signal_probes = 1;
        processor.missing_connection_binds.insert(
            ("addr5".to_string(), "addr6".to_string()),
            (
                LIVENESS_MAX_CONSECUTIVE_MISSING_CONNECTION_PROBES - 1,
                200,
                "key3".to_string(),
            ),
        );

        let result = processor.on_loop_cycle(VecDeque::from(vec![SignalEvent::new(
            control::pdu::CODE_OK,
            &None,
            &EventType::ProxyConnections,
            &Some(json!([
                {
                    "serviceName": "Service200",
                    "binds": [["addr1","addr2"]]
                },
            ])),
        )]));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(processor.missing_signal_probes, 0);
        assert_eq!(processor.missing_connection_binds.len(), 1);
        assert!(processor
            .missing_connection_binds
            .get(&("addr3".to_string(), "addr4".to_string()))
            .is_some());
        assert_eq!(
            *processor
                .missing_connection_binds
                .get(&("addr3".to_string(), "addr4".to_string()))
                .unwrap(),
            (1, 200, "key2".to_string())
        );
        assert_eq!(processor.message_outbox.lock().unwrap().len(), 1);

        let mut message = VecDeque::from(
            processor
                .message_outbox
                .lock()
                .unwrap()
                .get(0)
                .unwrap()
                .clone(),
        );
        let message_result = pdu::MessageFrame::consume_next_pdu(&mut message);
        assert!(message_result.is_ok());
        let message_frame = message_result.unwrap();
        assert!(message_frame.is_some());
        assert_eq!(
            message_frame.unwrap(),
            pdu::MessageFrame::new(
                ControlChannel::Signaling,
                pdu::CODE_OK,
                &None,
                &Some(serde_json::to_value(EventType::ProxyConnections).unwrap()),
                &Some(json!([
                    {
                        "serviceName": "Service200",
                        "binds": [
                            ["addr1", "addr2"],
                            ["addr3", "addr4"],
                            ["addr5", "addr6"],
                        ],
                    },
                ])),
            ),
        );
    }

    #[test]
    fn proxyconnproc_on_loop_cycle_when_client_dead() {
        let mut service_mgr = MockSvcMgr::new();
        let mut service_proxy = MockCliSvcProxyVisitor::new();
        service_proxy
            .expect_get_service()
            .times(1)
            .return_once(|| model::service::Service {
                service_id: 200,
                name: "Service200".to_string(),
                transport: model::service::Transport::TCP,
                host: "localhost".to_string(),
                port: 8200,
            });
        service_proxy
            .expect_get_proxy_keys()
            .times(1)
            .return_once(move || {
                vec![
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
                ]
            });
        service_mgr
            .expect_get_service_proxies()
            .times(1)
            .return_once(move || vec![Arc::new(Mutex::new(service_proxy))]);
        service_mgr.expect_shutdown_connection().never();

        let mut processor = create_processor(
            Arc::new(Mutex::new(service_mgr)),
            Arc::new(Mutex::new(VecDeque::new())),
        )
        .unwrap();
        processor.missing_signal_probes = LIVENESS_MAX_CONSECUTIVE_MISSING_SIGNAL_PROBES - 1;

        let result = processor.on_loop_cycle(VecDeque::new());

        if let Ok(()) = result {
            panic!("Unexpected successful result");
        }

        assert_eq!(
            processor.missing_signal_probes,
            LIVENESS_MAX_CONSECUTIVE_MISSING_SIGNAL_PROBES
        );
        assert_eq!(processor.missing_connection_binds.len(), 0);
        assert!(processor.message_outbox.lock().unwrap().is_empty());
    }
}
