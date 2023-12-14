use std::borrow::Borrow;
use std::io::Write;
use std::sync::{Arc, Mutex};
use anyhow::Result;

use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use crate::config::AppConfig;
use crate::console::ShellOutputWriter;
use crate::service::manager::{self, ServiceMgr};

/// Process control plane commands (validate requests, parse gateway control plane responses).
pub struct ControlPlane {
    processor: request::RequestProcessor,
    console_shell_output: Arc<Mutex<ShellOutputWriter>>
}

impl ControlPlane {

    /// ControlPlane constructor
    pub fn new(app_config: Arc<AppConfig>) -> Self {

        Self {
            processor: request::RequestProcessor::new(),
            console_shell_output: app_config.console_shell_output.clone()
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

        self.console_shell_output.lock().unwrap().write_all(&repl_shell_response.as_bytes()).map_err(|err|
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
pub mod tests {

    use std::sync::mpsc;
    use mockall::{mock, predicate};
    use serde_json::json;
    use trust0_common::control::request::Request;
    use trust0_common::model::service::Transport;
    use trust0_common::{model, testutils};
    use trust0_common::testutils::ChannelWriter;
    use crate::config;
    use crate::service::manager::ProxyAddrs;
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

    // tests
    // =====

    #[test]
    fn ctlplane_validate_request_when_invalid_request() {

        let app_config = config::tests::create_app_config(None).unwrap();
        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let result = control_plane.validate_request("INVALID");
        match result {
            Ok(request) => {
                panic!("Unexpected validate request: req={:?}" ,request);
            }
            Err(err) => {
                assert!(err.get_code().is_some());
                assert_eq!(err.get_code().unwrap(), 400);
            }
        }
    }

    #[test]
    fn ctlplane_validate_request_when_valid_ping_request() {

        let app_config = config::tests::create_app_config(None).unwrap();
        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let result = control_plane.validate_request("ping");
        match result {
            Ok(request) => {
                if request != Request::Ping {
                    panic!("Unexpected validate request: req={:?}", request);
                }
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}" ,err);
            }
        }
    }

    #[test]
    fn ctlplane_process_response_when_invalid_json_response() {

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter { channel_sender: output_channel.0 })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let result = control_plane.process_response(&service_mgr, "INVALID");
        if let Ok(response) = &result {
            panic!("Unexpected process response: resp={:?}", response);
        }

        let expected_data = "".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_proxies_response_for_no_proxies() {

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter { channel_sender: output_channel.0 })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let result = control_plane.process_response(&service_mgr, "{\"code\":200,\"message\":null,\"request\":\"Proxies\",\"data\":[]}");
        match &result {
            Ok(response) => {
                assert_eq!(response.code, 200, "Unexpected process response code: resp={:?}", response);
                assert_eq!(response.message, None, "Unexpected process response msg: resp={:?}", response);
                assert_eq!(response.request, Request::Proxies, "Unexpected process response request: resp={:?}", response);
                assert_eq!(response.data, Some(json!([])), "Unexpected process response data: resp={:?}", response);
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": []\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_proxies_response_for_2_proxies() {

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter { channel_sender: output_channel.0 })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr.expect_get_proxy_addrs_for_service().with(predicate::eq(203)).times(1).return_once(|_|
            Some(ProxyAddrs(8501, "gwhost1".to_string(), 8400)));
        service_mgr.expect_get_proxy_addrs_for_service().with(predicate::eq(204)).times(1).return_once(|_|
            Some(ProxyAddrs(8601, "gwhost1".to_string(), 8400)));
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let response_data_str = "[
                {
                  \"client_port\": 8601,
                  \"gateway_host\": \"gwhost1\",
                  \"gateway_port\": 8400,
                  \"service\": {
                    \"address\": \"echohost1:8600\",
                    \"id\": 204,
                    \"name\": \"echo-udp\",
                    \"transport\": \"UDP\"
                  }
                },
                {
                  \"client_port\": 8501,
                  \"gateway_host\": \"gwhost1\",
                  \"gateway_port\": 8400,
                  \"service\": {
                    \"address\": \"chathost1:8500\",
                    \"id\": 203,
                    \"name\": \"chat-tcp\",
                    \"transport\": \"TCP\"
                  }
                }]";
        let response_str = format!("{{\"code\":200,\"message\":null,\"request\":\"Proxies\",\"data\":{}}}", response_data_str);
        let response_data_json = serde_json::from_str(&response_data_str).unwrap();

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(response.code, 200, "Unexpected process response code: resp={:?}", response);
                assert_eq!(response.message, None, "Unexpected process response msg: resp={:?}", response);
                assert_eq!(response.request, Request::Proxies, "Unexpected process response request: resp={:?}", response);
                assert_eq!(response.data, Some(response_data_json), "Unexpected process response data: resp={:?}", response);
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Proxies\",\n  \"data\": [\n    {\n      \"client_port\": 8601,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 8400,\n      \"service\": {\n        \"address\": \"echohost1:8600\",\n        \"id\": 204,\n        \"name\": \"echo-udp\",\n        \"transport\": \"UDP\"\n      }\n    },\n    {\n      \"client_port\": 8501,\n      \"gateway_host\": \"gwhost1\",\n      \"gateway_port\": 8400,\n      \"service\": {\n        \"address\": \"chathost1:8500\",\n        \"id\": 203,\n        \"name\": \"chat-tcp\",\n        \"transport\": \"TCP\"\n      }\n    }\n  ]\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_start_response() {

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter { channel_sender: output_channel.0 })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr.expect_startup().with(
            predicate::eq(model::service::Service::new(203, "chat-tcp", &Transport::TCP, "chathost1", 8500)),
            predicate::eq(ProxyAddrs(8501, "gwhost1".to_string(), 8400)))
            .times(1).return_once(|_, addrs| { Ok(addrs.clone()) });
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let response_str = "{
              \"code\": 200,
              \"message\": null,
              \"request\": {
                \"Start\": {
                  \"service_name\": \"chat-tcp\",
                  \"local_port\": 8501
                }
              },
              \"data\": {
                \"client_port\": 8501,
                \"gateway_host\": \"gwhost1\",
                \"gateway_port\": 8400,
                \"service\": {
                  \"address\": \"chathost1:8500\",
                  \"id\": 203,
                  \"name\": \"chat-tcp\",
                  \"transport\": \"TCP\"
                }
              }
            }";

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(response.code, 200, "Unexpected process response code: resp={:?}", response);
                assert_eq!(response.message, None, "Unexpected process response msg: resp={:?}", response);
                assert_eq!(response.request, Request::Start { service_name: "chat-tcp".to_string(), local_port: 8501 },
                           "Unexpected process response request: resp={:?}", response);
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }

        let expected_data ="{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": {\n    \"Start\": {\n      \"service_name\": \"chat-tcp\",\n      \"local_port\": 8501\n    }\n  },\n  \"data\": {\n    \"client_port\": 8501,\n    \"gateway_host\": \"gwhost1\",\n    \"gateway_port\": 8400,\n    \"service\": {\n      \"address\": \"chathost1:8500\",\n      \"id\": 203,\n      \"name\": \"chat-tcp\",\n      \"transport\": \"TCP\"\n    }\n  }\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_quit_response() {

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter { channel_sender: output_channel.0 })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();

        let mut service_mgr = manager::tests::MockSvcMgr::new();
        service_mgr.expect_shutdown().times(1).return_once(|| { Ok(()) });
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(service_mgr));

        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let response_str = "{\"code\":200,\"message\":null,\"request\":\"Quit\",\"data\":null}";

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(response.code, 200, "Unexpected process response code: resp={:?}", response);
                assert_eq!(response.message, None, "Unexpected process response msg: resp={:?}", response);
                assert_eq!(response.request, Request::Quit, "Unexpected process response request: resp={:?}", response);
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 200,\n  \"message\": null,\n  \"request\": \"Quit\",\n  \"data\": null\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn ctlplane_process_response_when_valid_non200_response() {

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter { channel_sender: output_channel.0 })));
        let app_config = config::tests::create_app_config(Some(output_writer)).unwrap();
        let service_mgr: Arc<Mutex<dyn ServiceMgr + 'static>> = Arc::new(Mutex::new(manager::tests::MockSvcMgr::new()));
        let mut control_plane = ControlPlane::new(Arc::new(app_config));

        let response_str = "{\"code\":500,\"message\":\"System error encountered\",\"request\":\"Ping\",\"data\":null}";

        let result = control_plane.process_response(&service_mgr, &response_str);

        match &result {
            Ok(response) => {
                assert_eq!(response.code, 500, "Unexpected process response code: resp={:?}", response);
                assert_eq!(response.message, Some("System error encountered".to_string()), "Unexpected process response msg: resp={:?}", response);
                assert_eq!(response.request, Request::Ping, "Unexpected process response request: resp={:?}", response);
            }
            Err(err) => {
                panic!("Unexpected validate result: err={:?}", err);
            }
        }

        let expected_data = "{\n  \"code\": 500,\n  \"message\": \"System error encountered\",\n  \"request\": \"Ping\",\n  \"data\": null\n}\n".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }
}
