pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod console;
pub(crate) mod gateway;
pub(crate) mod service;

pub mod api {

    use std::sync;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use anyhow::Result;

    use super::*;
    pub use crate::config::AppConfig;
    pub use crate::console::write_shell_prompt;
    use trust0_common::error::AppError;
    use trust0_common::logging::error;
    use trust0_common::proxy::executor::ProxyExecutor;
    use trust0_common::target;

    /// Component lifecycle methods
    pub trait ComponentLifecycle {
        /// Component start
        fn start(&mut self) -> Result<(), AppError>;

        /// Component stop
        fn stop(&mut self) -> Result<(), AppError>;
    }

    pub struct MainProcessor {
        _app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn service::manager::ServiceMgr>>,
        _proxy_executor_handle: thread::JoinHandle<Result<(), AppError>>,
        _proxy_events_processor_handle: thread::JoinHandle<Result<(), AppError>>,
        client: client::Client,
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

            let service_mgr = Arc::new(Mutex::new(service::manager::ClientServiceMgr::new(
                app_config.clone(),
                proxy_tasks_sender,
                proxy_events_sender,
            )));

            let service_mgr_copy = service_mgr.clone();
            let proxy_events_processor_handle = thread::spawn(move || {
                service::manager::ClientServiceMgr::poll_proxy_events(
                    service_mgr_copy,
                    proxy_events_receiver,
                )
            });

            // Construct processor object

            Self {
                _app_config: app_config.clone(),
                service_mgr: service_mgr.clone(),
                _proxy_executor_handle: proxy_executor_handle,
                _proxy_events_processor_handle: proxy_events_processor_handle,
                client: client::Client::new(app_config, service_mgr),
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

    impl ComponentLifecycle for MainProcessor {
        /// Component start: start trust client
        fn start(&mut self) -> Result<(), AppError> {
            self.client.connect()?;
            self.client.poll_connection()?;
            self.stop()
        }

        /// Component stop: stop trust client
        fn stop(&mut self) -> Result<(), AppError> {
            self.service_mgr.lock().unwrap().shutdown()
        }
    }
}
