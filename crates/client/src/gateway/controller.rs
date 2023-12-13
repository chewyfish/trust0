use std::borrow::Borrow;
use std::io;
use std::io::Write;
use std::sync::{Arc, Mutex};
use anyhow::Result;

use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use crate::service::manager::{self, ServiceMgr};

/// Process control plane commands (validate requests, parse gateway control plane responses).
pub struct ControlPlane {
    processor: request::RequestProcessor,
}

impl ControlPlane {

    /// ControlPlane constructor
    pub fn new() -> Self {

        Self {
            processor: request::RequestProcessor::new(),
        }
    }

    /// Process 'proxies' response
    fn process_response_proxies(&self,
                                service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
                                gateway_response: &mut response::Response)
        -> Result<(), AppError> {

        let mut proxies = response::Proxy::from_serde_value(gateway_response.data.as_ref().unwrap())?;

        for proxy in &mut proxies {
            if let Some(proxy_addrs) = service_mgr.lock().unwrap().get_proxy_addrs_for_service(proxy.service.id) {
                proxy.client_port = Some(proxy_addrs.get_client_port());
            }
        }

        gateway_response.data = Some(serde_json::to_value(proxies).map_err(|err|
            AppError::GenWithMsgAndErr("Failed converting Proxies vector to serde Value::Array".to_string(), Box::new(err)))?);

        Ok(())
    }

    /// Process 'start' response
    fn process_response_start(&self,
                              service_mgr: &Arc<Mutex<dyn ServiceMgr>>,
                              gateway_response: &mut response::Response)
        -> Result<(), AppError> {

        let proxy_container = response::Proxy::from_serde_value(gateway_response.data.as_ref().unwrap())?;
        let proxy = proxy_container.get(0).unwrap();

        let _ = service_mgr.lock().unwrap().startup(
            &proxy.service.clone().into(),
            &manager::ProxyAddrs(proxy.client_port.unwrap(), proxy.gateway_host.as_ref().unwrap().to_string(), proxy.gateway_port))?;

        Ok(())
    }

    /// Process 'quit' response
    fn process_response_quit(&self, service_mgr: &Arc<Mutex<dyn ServiceMgr>>) -> Result<(), AppError> {

        service_mgr.lock().unwrap().shutdown()
    }
}

impl RequestProcessor for ControlPlane {
    /// Validate given command request, prior to being sent to the gateway control plane
    fn validate_request(&mut self, command_line: &str)
                        -> Result<request::Request, AppError> {
        let result: Result<request::Request, AppError>;

        let processed_request = self.processor.parse(command_line);

        match processed_request {
            Ok(request::Request::None) => {
                result = Ok(request::Request::None);
            }
            Err(err) => {
                result = Err(err)
            }
            _ => result = Ok(processed_request.unwrap().clone())
        }

        return result;
    }
    /// Process gateway response data
    fn process_response(&mut self, service_mgr: &Arc<Mutex<dyn ServiceMgr>>, response_line: &str)
                        -> Result<response::Response, AppError> {

        // Process response based on request context
        let mut gateway_response = response::Response::parse(&response_line)?;

        if gateway_response.code == response::CODE_OK {
            match &gateway_response.request.borrow() {
                &request::Request::Proxies => {
                    self.process_response_proxies(service_mgr, &mut gateway_response)?;
                }
                &request::Request::Start { service_name: _, local_port: _ } => {
                    self.process_response_start(service_mgr, &mut gateway_response)?;
                }
                &request::Request::Quit => {
                    self.process_response_quit(service_mgr)?;
                }
                _ => {}
            }
        }

        // Write response to REPL shell
        let repl_shell_response = format!("{}\n",
                                          serde_json::to_string_pretty(&gateway_response).map_err(|err|
                                              AppError::GenWithMsgAndErr("Error serializing response".to_ascii_lowercase(), Box::new(err)))?);

        io::stdout().write_all(&repl_shell_response.as_bytes()).map_err(|err|
            AppError::GenWithMsgAndErr("Error writing response to STDOUT".to_string(), Box::new(err)))?;

        Ok(gateway_response)
    }
}

pub trait RequestProcessor {

    /// Validate given command request, prior to being sent to the gateway control plane
    fn validate_request(&mut self, command_line: &str)
                        -> Result<request::Request, AppError>;
    /// Process gateway response data
    fn process_response(&mut self, service_mgr: &Arc<Mutex<dyn ServiceMgr>>, response_line: &str)
                        -> Result<response::Response, AppError>;
}

/// Unit tests
#[cfg(test)]
mod tests {

    use mockall::mock;
    use super::*;

    // mocks
    // =====

    mock! {
    pub GwReqProcessor {}
        impl RequestProcessor for GwReqProcessor {
            fn validate_request(&mut self, command_line: &str)
                            -> Result<request::Request, AppError>;
            fn process_response(&mut self, service_mgr: &Arc<Mutex<dyn ServiceMgr>>, response_line: &str)
                            -> Result<response::Response, AppError>;
        }
    }
}

