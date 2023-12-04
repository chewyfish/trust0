pub(crate) mod client;
pub(crate) mod console;
pub(crate) mod config;
pub(crate) mod gateway;
pub(crate) mod service;

pub mod api {
    use std::sync;
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use async_trait::async_trait;
    use tokio::task::JoinHandle;

    use trust0_common::error::AppError;
    use trust0_common::logging::error;
    use trust0_common::proxy::executor::ProxyExecutor;
    use trust0_common::target;
    use super::*;
    pub use crate::config::AppConfig;
    pub use crate::console::write_shell_prompt;

    /// Component lifecycle methods
    #[async_trait]
    pub trait ComponentLifecycle {

        /// Component start
        async fn start(&mut self) -> Result<(), AppError>;

        /// Component stop
        async fn stop(&mut self) -> Result<(), AppError>;
    }

    pub struct MainProcessor {
        _app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<service::manager::ServiceMgr>>,
        _proxy_executor_handle: JoinHandle<Result<(), AppError>>,
        _proxy_events_processor_handle: JoinHandle<Result<(), AppError>>,
        client: client::Client,
    }

    impl MainProcessor {

        /// MainProcessor constructor
        pub fn new(app_config: AppConfig) -> Self {

            let app_config = Arc::new(app_config);

            // Setup service manager/proxy executor
            let mut proxy_executor = ProxyExecutor::new();
            let proxy_tasks_sender = proxy_executor.clone_proxy_tasks_sender();

            let proxy_executor_handle = tokio::task::spawn_blocking(move || {
                proxy_executor.poll_new_tasks()
            });

            let (proxy_events_sender, proxy_events_receiver) = sync::mpsc::channel();

            let service_mgr = Arc::new(Mutex::new(
                service::manager::ServiceMgr::new(app_config.clone(), proxy_tasks_sender, proxy_events_sender)));

            let service_mgr_copy = service_mgr.clone();
            let proxy_events_processor_handle = tokio::task::spawn_blocking(move || {
                service::manager::ServiceMgr::poll_proxy_events(service_mgr_copy, proxy_events_receiver)
            });

            // Construct processor object

            Self {
                _app_config: app_config.clone(),
                service_mgr: service_mgr.clone(),
                _proxy_executor_handle: proxy_executor_handle,
                _proxy_events_processor_handle: proxy_events_processor_handle,
                client: client::Client::new(app_config, service_mgr)
            }
        }

        /// Get a function to shutdown proces
        pub fn get_shutdown_function(&self) -> impl Fn() {
            let service_mgr = self.service_mgr.clone();
            move || {
                if let Err(err) = service_mgr.lock().unwrap().shutdown() {
                    error(&target!(), &format!("{:?}", err));
                }
            }
        }
    }

    #[async_trait]
    impl ComponentLifecycle for MainProcessor {

        /// Component start: start trust client
        async fn start(&mut self) -> Result<(), AppError> {

            self.client.connect()?;
            self.client.poll_connection()?;
            self.stop().await
        }

        /// Component stop: stop trust client
        async fn stop(&mut self) -> Result<(), AppError> {

            self.service_mgr.lock().unwrap().shutdown()
        }
    }
}