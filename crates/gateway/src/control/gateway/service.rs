use anyhow::Result;
use std::sync::{Arc, Mutex};
use trust0_common::client::service::ProxyAddrs;
use trust0_common::client::service::{ClientControlServiceMgr, ClientControlServiceProxyVisitor};
use trust0_common::control::tls::message::ConnectionAddrs;
use trust0_common::error::AppError;
use trust0_common::model::service::Service;

use crate::service::manager::ServiceMgr;

/// Service proxy visitor used by the client controller to the service-gateway
pub struct ControlServiceProxyVisitor {
    pub service: Service,
    pub proxy_keys: Vec<(String, ConnectionAddrs)>,
}

impl ClientControlServiceProxyVisitor for ControlServiceProxyVisitor {
    fn get_service(&self) -> Service {
        self.service.clone()
    }

    fn get_proxy_keys(&self) -> Vec<(String, ConnectionAddrs)> {
        self.proxy_keys.clone()
    }
}

/// Service manager (wrapper) used for client controller to the service-gateway
pub struct ControllerServiceMgr {
    pub service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    pub device_id: String,
}

impl ClientControlServiceMgr for ControllerServiceMgr {
    fn get_proxy_addrs_for_service(&self, _service_id: i64) -> Option<ProxyAddrs> {
        unimplemented!();
    }

    fn get_service_proxies(&self) -> Vec<Arc<Mutex<dyn ClientControlServiceProxyVisitor>>> {
        let mut proxies: Vec<Arc<Mutex<dyn ClientControlServiceProxyVisitor>>> = vec![];
        for proxy in self.service_mgr.lock().unwrap().get_service_proxies() {
            let locked_proxy = proxy.lock().unwrap();
            proxies.push(Arc::new(Mutex::new(ControlServiceProxyVisitor {
                service: locked_proxy.get_service(),
                proxy_keys: locked_proxy.get_proxy_keys_for_device(self.device_id.as_str()),
            })));
        }
        proxies
    }

    fn startup(
        &mut self,
        service: &Service,
        proxy_addrs: &ProxyAddrs,
    ) -> Result<ProxyAddrs, AppError> {
        let (service_host, service_port) = self.service_mgr.lock().unwrap().startup(
            self.service_mgr.clone(),
            service,
            &Some(proxy_addrs.clone()),
        )?;
        Ok(ProxyAddrs(
            proxy_addrs.0,
            service_host.unwrap_or(proxy_addrs.1.clone()),
            service_port,
        ))
    }

    fn shutdown(&mut self, service_id: Option<i64>) -> Result<(), AppError> {
        self.service_mgr
            .lock()
            .unwrap()
            .shutdown_connections(None, service_id)
    }

    fn shutdown_connection(&mut self, service_id: i64, proxy_key: &str) -> Result<(), AppError> {
        self.service_mgr
            .lock()
            .unwrap()
            .shutdown_connection(service_id, proxy_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::manager::tests::MockSvcMgr;
    use crate::service::proxy::proxy_base::tests::MockGwSvcProxyVisitor;
    use mockall::predicate;
    use trust0_common::model::service::Transport;

    // tests
    // =====

    #[test]
    fn ctlsvcproxyvis_construction() {
        let service = Service::new(200, "svc200", &Transport::TCP, "host1", 3000);
        let proxy_keys = vec![(
            "key1".to_string(),
            ("cliaddr1".to_string(), "svraddr1".to_string()),
        )];

        let visitor = ControlServiceProxyVisitor {
            service: service.clone(),
            proxy_keys: proxy_keys.clone(),
        };

        assert_eq!(visitor.service, service);
        assert_eq!(visitor.proxy_keys, proxy_keys);
    }

    #[test]
    #[should_panic]
    fn ctlsvcmgr_get_proxy_addrs_for_svc() {
        let mut service_mgr = MockSvcMgr::new();
        service_mgr.expect_get_service_id_by_proxy_key().never();
        service_mgr.expect_get_service_proxies().never();
        service_mgr.expect_get_service_proxy().never();
        service_mgr.expect_has_control_plane_for_device().never();
        service_mgr.expect_add_control_plane().never();
        service_mgr.expect_clone_proxy_tasks_sender().never();
        service_mgr.expect_startup().never();
        service_mgr
            .expect_has_proxy_for_device_and_service()
            .never();
        service_mgr.expect_shutdown_connections().never();
        service_mgr.expect_shutdown_connection().never();
        service_mgr.expect_on_closed_proxy().never();

        let ctl_service_mgr = ControllerServiceMgr {
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            device_id: String::from("dev300"),
        };

        let _ = ctl_service_mgr.get_proxy_addrs_for_service(200);
    }

    #[test]
    fn ctlsvcmgr_get_svc_proxies() {
        let device_id = String::from("dev300");
        let service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::UDP,
            host: "localhost".to_string(),
            port: 8200,
        };
        let service_copy = service.clone();
        let proxy_keys = vec![(
            "key1".to_string(),
            ("cliaddr1".to_string(), "svraddr1".to_string()),
        )];
        let proxy_keys_copy = proxy_keys.clone();

        let mut gwsvc_proxy_visitor = MockGwSvcProxyVisitor::new();
        gwsvc_proxy_visitor
            .expect_get_service()
            .times(1)
            .return_once(move || service_copy);
        gwsvc_proxy_visitor
            .expect_get_proxy_keys_for_device()
            .with(predicate::eq(device_id.clone()))
            .times(1)
            .return_once(|_| proxy_keys_copy);

        let mut service_mgr = MockSvcMgr::new();
        service_mgr
            .expect_get_service_proxies()
            .times(1)
            .return_once(move || vec![Arc::new(Mutex::new(gwsvc_proxy_visitor))]);
        service_mgr.expect_get_service_id_by_proxy_key().never();
        service_mgr.expect_get_service_proxy().never();
        service_mgr.expect_has_control_plane_for_device().never();
        service_mgr.expect_add_control_plane().never();
        service_mgr.expect_clone_proxy_tasks_sender().never();
        service_mgr.expect_startup().never();
        service_mgr
            .expect_has_proxy_for_device_and_service()
            .never();
        service_mgr.expect_shutdown_connections().never();
        service_mgr.expect_shutdown_connection().never();
        service_mgr.expect_on_closed_proxy().never();

        let ctl_service_mgr = ControllerServiceMgr {
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            device_id,
        };

        let result_proxies = ctl_service_mgr.get_service_proxies();

        assert_eq!(result_proxies.len(), 1);

        let result_proxy = result_proxies[0].lock().unwrap();
        assert_eq!(result_proxy.get_service(), service);
        assert_eq!(result_proxy.get_proxy_keys(), proxy_keys);
    }

    #[test]
    fn ctlsvcmgr_startup() {
        let device_id = String::from("dev300");
        let proxy_addrs = ProxyAddrs(3000, "gwhost1".to_string(), 8000);
        let gw_service_host = String::from("gwhost2");
        let gw_service_host_copy = gw_service_host.clone();
        let gw_service_port = 9000;
        let service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::UDP,
            host: "localhost".to_string(),
            port: 8200,
        };

        let mut service_mgr = MockSvcMgr::new();
        service_mgr
            .expect_startup()
            .with(
                predicate::always(),
                predicate::eq(service.clone()),
                predicate::eq(Some(proxy_addrs.clone())),
            )
            .times(1)
            .return_once(move |_, _, _| Ok((Some(gw_service_host_copy), gw_service_port)));
        service_mgr.expect_get_service_id_by_proxy_key().never();
        service_mgr.expect_get_service_proxies().never();
        service_mgr.expect_get_service_proxy().never();
        service_mgr.expect_has_control_plane_for_device().never();
        service_mgr.expect_add_control_plane().never();
        service_mgr.expect_clone_proxy_tasks_sender().never();
        service_mgr
            .expect_has_proxy_for_device_and_service()
            .never();
        service_mgr.expect_shutdown_connections().never();
        service_mgr.expect_shutdown_connection().never();
        service_mgr.expect_on_closed_proxy().never();

        let mut ctl_service_mgr = ControllerServiceMgr {
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            device_id,
        };

        let result = ctl_service_mgr.startup(&service, &proxy_addrs);
        assert!(result.is_ok());

        let res_proxy_addrs = result.unwrap();
        assert_eq!(res_proxy_addrs.0, proxy_addrs.0);
        assert_eq!(res_proxy_addrs.1, gw_service_host);
        assert_eq!(res_proxy_addrs.2, gw_service_port);
    }

    #[test]
    fn ctlsvcmgr_shutdown() {
        let mut service_mgr = MockSvcMgr::new();
        service_mgr
            .expect_shutdown_connections()
            .with(predicate::eq(None), predicate::eq(Some(200)))
            .times(1)
            .return_once(|_, _| Ok(()));
        service_mgr.expect_get_service_id_by_proxy_key().never();
        service_mgr.expect_get_service_proxies().never();
        service_mgr.expect_get_service_proxy().never();
        service_mgr.expect_has_control_plane_for_device().never();
        service_mgr.expect_add_control_plane().never();
        service_mgr.expect_clone_proxy_tasks_sender().never();
        service_mgr.expect_startup().never();
        service_mgr
            .expect_has_proxy_for_device_and_service()
            .never();
        service_mgr.expect_shutdown_connection().never();
        service_mgr.expect_on_closed_proxy().never();

        let mut ctl_service_mgr = ControllerServiceMgr {
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            device_id: String::from("dev300"),
        };

        let result = ctl_service_mgr.shutdown(Some(200));
        assert!(result.is_ok());
    }

    #[test]
    fn ctlsvcmgr_shutdown_conn() {
        let mut service_mgr = MockSvcMgr::new();
        service_mgr
            .expect_shutdown_connection()
            .with(predicate::eq(200), predicate::eq("key1".to_string()))
            .return_once(|_, _| Ok(()));
        service_mgr.expect_get_service_id_by_proxy_key().never();
        service_mgr.expect_get_service_proxies().never();
        service_mgr.expect_get_service_proxy().never();
        service_mgr.expect_has_control_plane_for_device().never();
        service_mgr.expect_add_control_plane().never();
        service_mgr.expect_clone_proxy_tasks_sender().never();
        service_mgr.expect_startup().never();
        service_mgr
            .expect_has_proxy_for_device_and_service()
            .never();
        service_mgr.expect_shutdown_connections().never();
        service_mgr.expect_on_closed_proxy().never();

        let mut ctl_service_mgr = ControllerServiceMgr {
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            device_id: String::from("dev300"),
        };

        let result = ctl_service_mgr.shutdown_connection(200, "key1");
        assert!(result.is_ok());
    }
}
