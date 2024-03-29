pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod gateway;
pub(crate) mod repository;
pub(crate) mod service;

#[cfg(test)]
pub(crate) mod testutils;

pub mod api {
    use std::sync::{self, Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use anyhow::Result;

    use super::*;
    use crate::service::manager::ServiceMgr;
    pub use config::AppConfig;
    use trust0_common::error::AppError;
    use trust0_common::proxy::executor::ProxyExecutor;

    /// Component lifecycle methods
    pub trait ComponentLifecycle {
        /// Component start
        fn start(&mut self) -> Result<(), AppError>;

        /// Component stop
        fn stop(&mut self) -> Result<(), AppError>;
    }

    pub struct MainProcessor {
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
        _proxy_executor_handle: thread::JoinHandle<Result<(), AppError>>,
        _proxy_events_processor_handle: thread::JoinHandle<Result<(), AppError>>,
        gateway: Option<gateway::Gateway>,
        gateway_visitor: Arc<Mutex<gateway::ServerVisitor>>,
    }

    impl MainProcessor {
        /// MainProcessor constructor
        pub fn new(app_config: AppConfig) -> Self {
            let app_config = Arc::new(app_config);

            // Setup service manager/proxy executor
            let mut proxy_executor = ProxyExecutor::new();
            let proxy_tasks_sender = proxy_executor.clone_proxy_tasks_sender();

            let proxy_executor_handle = thread::spawn(move || proxy_executor.poll_new_tasks());

            let (proxy_events_sender, proxy_events_receiver) = sync::mpsc::channel();

            let service_mgr = Arc::new(Mutex::new(service::manager::GatewayServiceMgr::new(
                &app_config,
                &proxy_tasks_sender,
                &proxy_events_sender,
            )));

            let service_mgr_copy = service_mgr.clone();
            let proxy_events_processor_handle = thread::spawn(move || {
                service::manager::GatewayServiceMgr::poll_proxy_events(
                    service_mgr_copy,
                    &proxy_events_receiver,
                )
            });

            // Construct processor object
            Self {
                app_config: app_config.clone(),
                service_mgr: service_mgr.clone(),
                _proxy_executor_handle: proxy_executor_handle,
                _proxy_events_processor_handle: proxy_events_processor_handle,
                gateway: None,
                gateway_visitor: Arc::new(Mutex::new(gateway::ServerVisitor::new(
                    &app_config,
                    service_mgr,
                ))),
            }
        }

        /// Get a function to (initiate) gateway shutdown
        pub fn get_shutdown_function(&self) -> impl Fn() {
            let server_visitor = self.gateway_visitor.clone();
            move || {
                server_visitor.lock().unwrap().set_shutdown_requested(true);
            }
        }
    }

    impl ComponentLifecycle for MainProcessor {
        /// Component start: start trust gateway
        fn start(&mut self) -> Result<(), AppError> {
            let trust_gateway =
                gateway::Gateway::new(&self.app_config, self.gateway_visitor.clone());
            self.gateway = Some(trust_gateway);
            self.gateway.as_mut().unwrap().bind_listener()?;
            self.gateway.as_mut().unwrap().poll_new_connections()?;
            self.stop()
        }

        /// Component stop: stop trust gateway
        fn stop(&mut self) -> Result<(), AppError> {
            // Shutdown gateway listener (may already be shut down)
            self.gateway_visitor
                .lock()
                .unwrap()
                .set_shutdown_requested(true);

            // Shutdown service proxies
            self.service_mgr
                .lock()
                .unwrap()
                .shutdown_connections(None, None)?;

            thread::sleep(Duration::from_millis(2000));

            Ok(())
        }
    }
}
