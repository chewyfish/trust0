use std::io::Write;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::config::AppConfig;
use crate::console::{InputTextStreamConnector, ShellInputReader, ShellOutputWriter};
use crate::gateway::controller::{ControlPlane, RequestProcessor};
use crate::service::manager::ServiceMgr;
use trust0_common::control::{request, response};
use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::net::tls_client::conn_std;
use trust0_common::target;

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {
    _app_config: Arc<AppConfig>,
    stdin_connector: Box<dyn InputTextStreamConnector>,
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    request_processor: Box<dyn RequestProcessor>,
    console_shell_output: Arc<Mutex<ShellOutputWriter>>,
}

impl ServerConnVisitor {
    /// ServerConnVisitor constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<dyn ServiceMgr>>,
    ) -> Result<Self, AppError> {
        let stdin_connector = ShellInputReader::new();
        let control_plane =
            ControlPlane::new(app_config.clone(), stdin_connector.clone_disable_tty_echo());
        Ok(Self {
            _app_config: app_config.clone(),
            stdin_connector: Box::new(stdin_connector),
            event_channel_sender: None,
            service_mgr,
            request_processor: Box::new(control_plane),
            console_shell_output: app_config.console_shell_output.clone(),
        })
    }
}

impl conn_std::ConnectionVisitor for ServerConnVisitor {
    fn on_connected(&mut self) -> Result<(), AppError> {
        self.console_shell_output
            .lock()
            .unwrap()
            .write_shell_prompt(true)?;
        self.stdin_connector.spawn_line_reader();
        Ok(())
    }

    fn set_event_channel_sender(
        &mut self,
        event_channel_sender: Sender<conn_std::ConnectionEvent>,
    ) {
        self.event_channel_sender = Some(event_channel_sender.clone());
        self.request_processor
            .set_event_channel_sender(event_channel_sender);
    }

    fn on_connection_read(&mut self, data: &[u8]) -> Result<(), AppError> {
        let text_data = String::from_utf8(data.to_vec()).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting gateway response data as UTF8".to_string(),
                Box::new(err),
            )
        })?;

        let mut response = response::Response::default();
        for line in text_data.lines() {
            response = self
                .request_processor
                .process_response(&self.service_mgr, line)?;
        }

        if request::Request::Ignore != response.request {
            self.console_shell_output
                .lock()
                .unwrap()
                .write_shell_prompt(false)?;
        }

        Ok(())
    }

    fn on_polling_cycle(&mut self) -> Result<(), AppError> {
        let line = self.stdin_connector.next_line()?;
        if line.is_none() {
            return Ok(());
        }
        let line = line.unwrap();

        // validate command
        let validated_request = self.request_processor.validate_request(&line);

        match validated_request {
            Ok(request::Request::None) => {
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_shell_prompt(false)?;
                return Ok(());
            }
            Ok(request::Request::Ignore) => {
                return Ok(());
            }
            Err(err) => {
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_all(format!("{}\n", err).as_bytes())
                    .map_err(|err| {
                        AppError::GenWithMsgAndErr(
                            "Error writing invalid command response to STDOUT".to_string(),
                            Box::new(err),
                        )
                    })?;
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_shell_prompt(false)?;
                return Ok(());
            }
            _ => {}
        }

        // valid command, send to gateway control plane
        let event_sender = self.event_channel_sender.as_ref().unwrap();

        if let Err(err) = event_sender
            .send(conn_std::ConnectionEvent::Write(line.into_bytes()))
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error sending write event".to_string(), Box::new(err))
            })
        {
            let _ = event_sender.send(conn_std::ConnectionEvent::Closing);

            return Err(err);
        }

        Ok(())
    }

    fn send_error_response(&mut self, err: &AppError) {
        error(&target!(), &format!("{:?}", err));
    }
}

unsafe impl Send for ServerConnVisitor {}

/// Unit tests
#[cfg(test)]
mod tests {

    use super::*;
    use crate::gateway::controller;
    use crate::{config, console, service};
    use serde_json::Value;
    use std::sync::mpsc;
    use trust0_common::control::request::Request;
    use trust0_common::control::response::Response;
    use trust0_common::net::tls_client::conn_std::{ConnectionEvent, ConnectionVisitor};
    use trust0_common::testutils::{self, ChannelWriter};

    #[test]
    fn srvconnvis_on_connection_read_when_simple_ping_response() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let response_str =
            "{\"code\":200,\"message\":null,\"request\":\"ping\",\"data\":\"pong\"}".to_string();

        let response_str_copy = response_str.clone();
        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor
            .expect_process_response()
            .times(1)
            .returning(move |_, line| {
                if line != &response_str_copy {
                    Err(AppError::General(format!(
                        "Unexpected process response line: line={}",
                        &line
                    )))
                } else {
                    Ok(Response {
                        code: 200,
                        message: None,
                        request: Request::Ping,
                        data: Some(Value::String(response_str_copy.clone())),
                    })
                }
            });

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(console::tests::MockInpTxtStreamConnector::new()),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        match server_conn_visitor.on_connection_read(&response_str.as_bytes()) {
            Ok(()) => {}
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn srvconnvis_on_connection_read_when_login_data_response() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let response_str =
            "{\"code\":200,\"message\":null,\"request\":\"loginData\",\"data\":{\"authnType\":\"Insecure\",\"message\":null}}".to_string();

        let response_str_copy = response_str.clone();
        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor
            .expect_process_response()
            .times(1)
            .returning(move |_, line| {
                if line != &response_str_copy {
                    Err(AppError::General(format!(
                        "Unexpected process response line: line={}",
                        &line
                    )))
                } else {
                    Ok(Response {
                        code: 200,
                        message: None,
                        request: Request::Ignore,
                        data: None,
                    })
                }
            });

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(console::tests::MockInpTxtStreamConnector::new()),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        match server_conn_visitor.on_connection_read(&response_str.as_bytes()) {
            Ok(()) => {}
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }

    #[test]
    fn srvconnvis_on_polling_cycle_when_no_pending_line() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor.expect_validate_request().never();

        let mut input_reader = console::tests::MockInpTxtStreamConnector::new();
        input_reader
            .expect_next_line()
            .times(1)
            .return_once(|| Ok(None));

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(input_reader),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
    #[test]
    fn srvconnvis_on_polling_cycle_when_void_request() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let request_str = "".to_string();

        let request_str_copy = request_str.clone();
        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor
            .expect_validate_request()
            .times(1)
            .return_once(move |req| {
                if !request_str_copy.eq(req) {
                    panic!("Unexpected request validation: req={}", req);
                }
                Ok(Request::None)
            });

        let request_str_copy = request_str.clone();
        let mut input_reader = console::tests::MockInpTxtStreamConnector::new();
        input_reader
            .expect_next_line()
            .times(1)
            .return_once(|| Ok(Some(request_str_copy)));

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(input_reader),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_data = "> ".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(output_data.len(), expected_data.len());
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn srvconnvis_on_polling_cycle_when_invalid_request() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let request_str = "".to_string();

        let request_str_copy = request_str.clone();
        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor
            .expect_validate_request()
            .times(1)
            .return_once(move |req| {
                if !request_str_copy.eq(req) {
                    panic!("Unexpected request validation: req={}", req);
                }
                Err(AppError::General("Expected validate error".to_string()))
            });

        let request_str_copy = request_str.clone();
        let mut input_reader = console::tests::MockInpTxtStreamConnector::new();
        input_reader
            .expect_next_line()
            .times(1)
            .return_once(|| Ok(Some(request_str_copy)));

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(input_reader),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_data = "Expected validate error\n> ".to_string();
        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);

        assert_eq!(output_data.len(), expected_data.len());
        assert_eq!(String::from_utf8(output_data).unwrap(), expected_data);
    }

    #[test]
    fn srvconnvis_on_polling_cycle_when_valid_ping_request() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let request_str = request::PROTOCOL_REQUEST_PING.to_string();

        let request_str_copy = request_str.clone();
        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor
            .expect_validate_request()
            .times(1)
            .return_once(move |req| {
                if !request_str_copy.eq(req) {
                    panic!("Unexpected request validation: req={}", req);
                }
                Ok(Request::Ping)
            });

        let request_str_copy = request_str.clone();
        let mut input_reader = console::tests::MockInpTxtStreamConnector::new();
        input_reader
            .expect_next_line()
            .times(1)
            .return_once(|| Ok(Some(request_str_copy)));

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(input_reader),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }

        let connevt_data = testutils::gather_rcvd_connection_channel_data(&event_channel.1);
        assert_eq!(connevt_data.len(), 1);

        match connevt_data.get(0).unwrap() {
            ConnectionEvent::Closing => panic!("Unexpected connection event: evt=Closing"),
            ConnectionEvent::Closed => panic!("Unexpected connection event: evt=Closing"),
            ConnectionEvent::Write(evt_data) => {
                let expected_data = "ping".to_string();
                assert_eq!(evt_data.len(), expected_data.len());
                assert_eq!(String::from_utf8(evt_data.to_vec()).unwrap(), expected_data);
            }
        }
    }

    #[test]
    fn srvconnvis_on_polling_cycle_when_valid_login_request() {
        let app_config = config::tests::create_app_config(None).unwrap();
        let service_mgr = service::manager::tests::MockSvcMgr::new();
        let event_channel = mpsc::channel();

        let request_str = request::PROTOCOL_REQUEST_LOGIN.to_string();

        let request_str_copy = request_str.clone();
        let mut req_processor = controller::tests::MockGwReqProcessor::new();
        req_processor
            .expect_validate_request()
            .times(1)
            .return_once(move |req| {
                if !request_str_copy.eq(req) {
                    panic!("Unexpected request validation: req={}", req);
                }
                Ok(Request::Ignore)
            });

        let request_str_copy = request_str.clone();
        let mut input_reader = console::tests::MockInpTxtStreamConnector::new();
        input_reader
            .expect_next_line()
            .times(1)
            .return_once(|| Ok(Some(request_str_copy)));

        let output_channel = mpsc::channel();
        let output_writer = ChannelWriter {
            channel_sender: output_channel.0,
        };

        let mut server_conn_visitor = ServerConnVisitor {
            _app_config: Arc::new(app_config),
            stdin_connector: Box::new(input_reader),
            service_mgr: Arc::new(Mutex::new(service_mgr)),
            event_channel_sender: Some(event_channel.0),
            request_processor: Box::new(req_processor),
            console_shell_output: Arc::new(Mutex::new(ShellOutputWriter::new(Some(Box::new(
                output_writer,
            ))))),
        };

        if let Err(err) = server_conn_visitor.on_polling_cycle() {
            panic!("Unexpected result: err={:?}", &err);
        }

        let connevt_data = testutils::gather_rcvd_connection_channel_data(&event_channel.1);
        assert_eq!(connevt_data.len(), 0);
    }
}
