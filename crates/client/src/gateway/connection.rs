use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;

use anyhow::Result;
use trust0_common::control::request;

use trust0_common::error::AppError;
use trust0_common::logging::error;
use trust0_common::net::tls_client::conn_std;
use trust0_common::target;
use crate::config::AppConfig;
use crate::console::{self, ThreadedStdin};
use crate::gateway::controller::{ControlPlane, RequestProcessor};
use crate::service::manager::ServiceMgr;

/// tls_client::std_conn::Connection strategy visitor pattern implementation
pub struct ServerConnVisitor {
    _app_config: Arc<AppConfig>,
    stdin: Option<ThreadedStdin>,
    event_channel_sender: Option<Sender<conn_std::ConnectionEvent>>,
    service_mgr: Arc<Mutex<ServiceMgr>>,
    request_processor: Box<dyn RequestProcessor>
}

impl ServerConnVisitor {

    /// ServerConnVisitor constructor
    pub fn new(
        app_config: Arc<AppConfig>,
        service_mgr: Arc<Mutex<ServiceMgr>>
    ) -> Result<Self, AppError> {

        Ok(Self {
            _app_config: app_config,
            stdin: None,
            event_channel_sender: None,
            service_mgr,
            request_processor: Box::new(ControlPlane::new())
        })
    }
}

impl conn_std::ConnectionVisitor for ServerConnVisitor {

    fn on_connected(&mut self) -> Result<(), AppError> {

        console::write_shell_prompt(true)?;
        let stdin = ThreadedStdin::new();
        ThreadedStdin::spawn_line_reader(stdin.clone_channel_sender());
        self.stdin = Some(stdin);
        Ok(())
    }

    fn set_event_channel_sender(&mut self, event_channel_sender: Sender<conn_std::ConnectionEvent>) {
        self.event_channel_sender = Some(event_channel_sender);
    }

    fn on_connection_read(&mut self, data: &Vec<u8>) -> Result<(), AppError> {

        let text_data = String::from_utf8(data.to_vec()).map_err(|err|
            AppError::GenWithMsgAndErr("Error converting gateway response data as UTF8".to_string(), Box::new(err)))?;

        for line in text_data.lines() {
            let _ = self.request_processor.process_response(&self.service_mgr, &line)?;
        }

        console::write_shell_prompt(false)
    }

    fn on_polling_cycle(&mut self) -> Result<(), AppError> {

        let line = self.stdin.as_mut().unwrap().next_line()?;
        if line == None { return Ok(()); }
        let line = line.unwrap();

        // validate command
        let validated_request = self.request_processor.validate_request(&line);

        match validated_request {

            Ok(request::Request::None) => {
                console::write_shell_prompt(false)?;
                return Ok(());
            }
            Err(err) => {
                io::stdout().write_all(format!("{}\n", err.to_string()).as_bytes()).map_err(|err|
                    AppError::GenWithMsgAndErr("Error writing invalid command response to STDOUT".to_string(), Box::new(err)))?;
                console::write_shell_prompt(false)?;
                return Ok(());
            }
            _ => {}
        }

        // valid command, send to gateway control plane
        let event_sender = self.event_channel_sender.as_ref().unwrap();

        if let Err(err) = event_sender.send(conn_std::ConnectionEvent::Write(line.into_bytes())).map_err(|err|
            AppError::GenWithMsgAndErr("Error sending write event".to_string(), Box::new(err))) {
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
