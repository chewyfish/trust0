use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::console;
use crate::console::ShellOutputWriter;
use crate::gateway::controller::signaling::SignalingEventHandler;
use trust0_common::control::signaling::event::SignalEvent;
use trust0_common::control::signaling::security::CertificateReissueEvent;
use trust0_common::distro::AppInstallFile;
use trust0_common::error::AppError;
use trust0_common::logging::warn;
use trust0_common::target;

/// Process inbound certificate/key pair CA re-issuance events
pub struct CertReissuanceProcessor {
    /// Console output writer
    console_shell_output: Arc<Mutex<ShellOutputWriter>>,
}

impl CertReissuanceProcessor {
    /// CertReissuanceProcessor constructor
    ///
    /// # Arguments
    ///
    /// * `console_shell_output` - Console output writer
    ///
    /// # Returns
    ///
    /// A newly constructed [`CertReissuanceProcessor`] object.
    ///
    pub fn new(console_shell_output: &Arc<Mutex<ShellOutputWriter>>) -> Self {
        Self {
            console_shell_output: console_shell_output.clone(),
        }
    }

    /// Process inbound certificate/key pair re-issuance signal event
    ///
    /// # Arguments
    ///
    /// * `signal_event` - Certificate reissue signal event
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_inbound_event(&mut self, signal_event: SignalEvent) -> Result<(), AppError> {
        if signal_event.data.is_none() {
            warn(
                &target!(),
                &format!(
                    "Missing CertificateReissueEvent object: evt={:?}",
                    &signal_event
                ),
            );
            return Ok(());
        }

        // Deserialize event
        let cert_reissue: CertificateReissueEvent =
            CertificateReissueEvent::from_serde_value(signal_event.data.as_ref().unwrap())?;

        _ = self
            .write_console_line("Received new client certificate, key pair PEMs from gateway CA");

        // Backup current PKI resource files
        let cert_install_file = AppInstallFile::ClientCertificate;
        let key_install_file = AppInstallFile::ClientKey;

        if let Some((_, backed_up_file_path)) = cert_install_file.backup()? {
            _ = self.write_console_line(&format!(
                "Backed up certificate file: path={:?}",
                &backed_up_file_path
            ));
        }
        if let Some((_, backed_up_file_path)) = key_install_file.backup()? {
            _ = self.write_console_line(&format!(
                "Backed up key file: path={:?}",
                &backed_up_file_path
            ));
        }

        // Write new PKI resource files
        _ = cert_install_file.create(cert_reissue.certificate_pem.as_bytes())?;
        _ = self.write_console_line(&format!(
            "Created new certificate file: path={:?}",
            &cert_install_file.pathspec()
        ));
        _ = key_install_file.create(cert_reissue.key_pair_pem.as_bytes())?;
        _ = self.write_console_line(&format!(
            "Created new key pair file: path={:?}",
            &key_install_file.pathspec()
        ));

        _ = self.write_console_line("New certificate will be used upon client restart");

        Ok(())
    }

    /// Write text line to management console shell
    ///
    /// # Arguments
    ///
    /// * `output_text` - Text to write to console (STDOUT). Line ending will be appended.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of write operation.
    ///
    fn write_console_line(&self, output_text: &str) -> Result<(), AppError> {
        self.console_shell_output
            .lock()
            .unwrap()
            .write_all(format!("{}{}", output_text, console::LINE_ENDING).as_bytes())
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error writing to STDOUT".to_string(), Box::new(err))
            })?;
        self.console_shell_output
            .lock()
            .unwrap()
            .flush()
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error flushing STDOUT".to_string(), Box::new(err))
            })
    }
}

unsafe impl Send for CertReissuanceProcessor {}

impl SignalingEventHandler for CertReissuanceProcessor {
    fn on_loop_cycle(&mut self, signal_events: VecDeque<SignalEvent>) -> Result<(), AppError> {
        if !signal_events.is_empty() {
            for signal_event in signal_events {
                self.process_inbound_event(signal_event)?;
                self.console_shell_output
                    .lock()
                    .unwrap()
                    .write_shell_prompt(false)?;
            }
        }

        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{config, console};
    use regex::Regex;
    use serde_json::json;
    use std::fs;
    use std::fs::File;
    use std::sync::mpsc;
    use trust0_common::control;
    use trust0_common::control::signaling::event::EventType;
    use trust0_common::distro::AppInstallDir;
    use trust0_common::testutils::{self, ChannelWriter};

    #[test]
    fn certreissueproc_new() {
        _ = CertReissuanceProcessor::new(&Arc::new(Mutex::new(ShellOutputWriter::new(Some(
            Box::new(ChannelWriter {
                channel_sender: mpsc::channel().0,
            }),
        )))));
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_no_events() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let mut processor = CertReissuanceProcessor::new(&Arc::new(Mutex::new(output_writer)));

        let result = processor.on_loop_cycle(VecDeque::new());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert!(output_data.is_empty());
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_wrong_event() {
        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let mut processor = CertReissuanceProcessor::new(&Arc::new(Mutex::new(output_writer)));

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

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let output_data = testutils::gather_rcvd_bytearr_channel_data(&output_channel.1);
        assert!(output_data.is_empty());
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_cert_reissue_event_and_no_existing_files() {
        let mutex = config::tests::TEST_MUTEX.clone();
        let _lock = mutex.lock().unwrap();
        testutils::setup_xdg_vars().unwrap();
        let cert_install_file = AppInstallFile::ClientCertificate;
        let key_install_file = AppInstallFile::ClientKey;

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let mut processor = CertReissuanceProcessor::new(&Arc::new(Mutex::new(output_writer)));

        let cert_install_file_path = cert_install_file.pathspec();
        let key_install_file_path = key_install_file.pathspec();
        fs::create_dir_all(cert_install_file_path.parent().unwrap()).unwrap();
        fs::create_dir_all(key_install_file_path.parent().unwrap()).unwrap();

        if cert_install_file_path.exists() {
            fs::remove_file(&cert_install_file_path).unwrap();
        }
        if key_install_file_path.exists() {
            fs::remove_file(&key_install_file_path).unwrap();
        }

        let result = processor.on_loop_cycle(VecDeque::from(vec![SignalEvent::new(
            control::pdu::CODE_OK,
            &None,
            &EventType::CertificateReissue,
            &Some(json!({
                "keyAlgorithm": "ed25519",
                "keyPairPem": "KEY PAIR PEM",
                "certificatePem": "CERTIFICATE PEM"
            })),
        )]));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_output_data = format!(
            "\
            Received new client certificate, key pair PEMs from gateway CA{}\
            Created new certificate file: path=\"{}\"{}\
            Created new key pair file: path=\"{}\"{}\
            New certificate will be used upon client restart{}\
            {}",
            console::LINE_ENDING,
            cert_install_file_path.to_str().unwrap(),
            console::LINE_ENDING,
            key_install_file_path.to_str().unwrap(),
            console::LINE_ENDING,
            console::LINE_ENDING,
            console::SHELL_PROMPT,
        )
        .replace("\\", "");

        let output_data = String::from_utf8(testutils::gather_rcvd_bytearr_channel_data(
            &output_channel.1,
        ))
        .unwrap()
        .replace("\\", "");

        assert_eq!(output_data, expected_output_data);

        let cert_file_contents = fs::read_to_string(&cert_install_file_path).unwrap();
        assert_eq!(
            cert_file_contents.replace(&['\r', '\n'], "<NL>"),
            "CERTIFICATE PEM".to_string()
        );

        let key_file_contents = fs::read_to_string(&key_install_file_path).unwrap();
        assert_eq!(
            key_file_contents.replace(&['\r', '\n'], "<NL>"),
            "KEY PAIR PEM".to_string()
        );
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_cert_reissue_event_and_existing_files() {
        let mutex = config::tests::TEST_MUTEX.clone();
        let _lock = mutex.lock().unwrap();
        testutils::setup_xdg_vars().unwrap();
        let cert_install_file = AppInstallFile::ClientCertificate;
        let key_install_file = AppInstallFile::ClientKey;
        let mut backup_cert_install_file_relpath = cert_install_file.relative_path().clone();
        backup_cert_install_file_relpath.set_extension("pem.9876543210");
        let mut backup_key_install_file_relpath = key_install_file.relative_path().clone();
        backup_key_install_file_relpath.set_extension("pem.9876543210");
        let backup_cert_install_file = AppInstallFile::Custom(
            AppInstallDir::Backup,
            backup_cert_install_file_relpath,
            cert_install_file.permissions(),
        );
        let backup_key_install_file = AppInstallFile::Custom(
            AppInstallDir::Backup,
            backup_key_install_file_relpath,
            key_install_file.permissions(),
        );

        let output_channel = mpsc::channel();
        let output_writer = ShellOutputWriter::new(Some(Box::new(ChannelWriter {
            channel_sender: output_channel.0,
        })));
        let mut processor = CertReissuanceProcessor::new(&Arc::new(Mutex::new(output_writer)));

        let backup_cert_install_file_path = backup_cert_install_file.pathspec();
        let backup_key_install_file_path = backup_key_install_file.pathspec();
        let cert_install_file_path = cert_install_file.pathspec();
        let key_install_file_path = key_install_file.pathspec();

        fs::create_dir_all(backup_cert_install_file_path.parent().unwrap()).unwrap();
        fs::create_dir_all(backup_key_install_file_path.parent().unwrap()).unwrap();
        fs::create_dir_all(cert_install_file_path.parent().unwrap()).unwrap();
        fs::create_dir_all(key_install_file_path.parent().unwrap()).unwrap();

        if cert_install_file_path.exists() {
            fs::remove_file(&cert_install_file_path).unwrap();
        }
        let mut cert_install_file = File::create(cert_install_file_path.clone()).unwrap();
        cert_install_file
            .write_all("OLD CERTIFICATE PEM".as_bytes())
            .unwrap();

        if key_install_file_path.exists() {
            fs::remove_file(&key_install_file_path).unwrap();
        }
        let mut key_install_file = File::create(key_install_file_path.clone()).unwrap();
        key_install_file
            .write_all("OLD KEY PAIR PEM".as_bytes())
            .unwrap();

        let result = processor.on_loop_cycle(VecDeque::from(vec![SignalEvent::new(
            control::pdu::CODE_OK,
            &None,
            &EventType::CertificateReissue,
            &Some(json!({
                "keyAlgorithm": "ed25519",
                "keyPairPem": "KEY PAIR PEM",
                "certificatePem": "CERTIFICATE PEM"
            })),
        )]));

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let expected_output_data = format!(
            "\
            Received new client certificate, key pair PEMs from gateway CA{}\
            Backed up certificate file: path=\"{}\"{}\
            Backed up key file: path=\"{}\"{}\
            Created new certificate file: path=\"{}\"{}\
            Created new key pair file: path=\"{}\"{}\
            New certificate will be used upon client restart{}\
            {}",
            console::LINE_ENDING,
            backup_cert_install_file_path.to_str().unwrap(),
            console::LINE_ENDING,
            backup_key_install_file_path.to_str().unwrap(),
            console::LINE_ENDING,
            cert_install_file_path.to_str().unwrap(),
            console::LINE_ENDING,
            key_install_file_path.to_str().unwrap(),
            console::LINE_ENDING,
            console::LINE_ENDING,
            console::SHELL_PROMPT,
        )
        .replace("\\", "");

        let large_num_re = Regex::new(r"\d{10,}").unwrap();
        let output_data = String::from_utf8(testutils::gather_rcvd_bytearr_channel_data(
            &output_channel.1,
        ))
        .unwrap()
        .replace("\\", "");
        let output_data = large_num_re.replace_all(&output_data, "9876543210");
        assert_eq!(output_data, expected_output_data);

        let cert_file_contents = fs::read_to_string(&cert_install_file_path).unwrap();
        assert_eq!(
            cert_file_contents.replace(&['\r', '\n'], "<NL>"),
            "CERTIFICATE PEM".to_string()
        );

        let key_file_contents = fs::read_to_string(&key_install_file_path).unwrap();
        assert_eq!(
            key_file_contents.replace(&['\r', '\n'], "<NL>"),
            "KEY PAIR PEM".to_string()
        );
    }
}
