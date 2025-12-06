use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rand::random;
#[cfg(test)]
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use crate::client::controller::signaling;
use crate::client::controller::signaling::SignalingEventHandler;
use crate::client::device;
use crate::client::device::Device;
use crate::config::AppConfig;
use trust0_common::control::signaling::event::{EventType, SignalEvent};
use trust0_common::control::signaling::security::CertificateReissueEvent;
use trust0_common::crypto::ca;
use trust0_common::crypto::ca::{Certificate, KeyAlgorithm};
use trust0_common::error::AppError;
use trust0_common::logging::info;
use trust0_common::{control, file, target};

const PROCESSING_RECHECK_DURATION_SECS: u64 = 3_600;

/// Generate/send new certificate/key pair PEM resources to client when necessary
pub struct CertReissuanceProcessor {
    /// Application configuration object
    app_config: Arc<AppConfig>,
    /// Queued PDU responses to be sent to client
    message_outbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Certificate device context
    device: Device,
    /// Certificate reissue datetime (based on certificate expiry minus configured delta)
    cert_reissue_datetime: OffsetDateTime,
    /// Cycle iterations between processing
    recheck_cycle_iterations: u64,
    /// Current cycle iteration
    curr_cycle_iteration: u64,
    /// Certificate reissued state
    reissued: bool,
}

impl CertReissuanceProcessor {
    /// CertReissuanceProcessor constructor
    ///
    /// # Arguments
    ///
    /// * `app_config` - Application configuration object
    /// * `message_outbox` - Queued PDU responses to be sent to client
    /// * `device` - Certificate device context
    ///
    /// # Returns
    ///
    /// A newly constructed [`CertReissuanceProcessor`] object.
    ///
    pub fn new(
        app_config: &Arc<AppConfig>,
        message_outbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
        device: &Device,
    ) -> Self {
        let recheck_cycle_iterations =
            PROCESSING_RECHECK_DURATION_SECS / (signaling::EVENT_LOOP_CYCLE_DELAY_MSECS / 1000);
        Self {
            app_config: app_config.clone(),
            message_outbox: message_outbox.clone(),
            device: device.clone(),
            cert_reissue_datetime: device
                .get_cert_validity()
                .not_after
                .to_datetime()
                .checked_sub(Duration::days(
                    app_config.ca_reissuance_threshold_days as i64,
                ))
                .unwrap(),
            recheck_cycle_iterations,
            curr_cycle_iteration: recheck_cycle_iterations - 1,
            reissued: false,
        }
    }

    /// Process potential outbound [`CertificateReissueEvent`] messages for client
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the processing operation.
    ///
    fn process_outbound_event(&mut self) -> Result<(), AppError> {
        let now_datetime = Self::get_now_utc();
        if now_datetime > self.cert_reissue_datetime {
            // Create new certificate/key pair objects

            let key_algorithm = self.app_config.ca_key_algorithm.into();
            let validity_not_before = now_datetime;
            let validity_not_after = now_datetime
                .checked_add(Duration::days(
                    self.app_config.ca_validity_period_days as i64,
                ))
                .unwrap();
            let subj_common_name = self
                .device
                .cert_subj
                .get(device::CERT_OID_COMMON_NAME)
                .unwrap()
                .first()
                .unwrap();
            let subj_organization = self
                .device
                .cert_subj
                .get(device::CERT_OID_ORGANIZATION)
                .and_then(|vals| vals.first());
            let subj_country = self
                .device
                .cert_subj
                .get(device::CERT_OID_COUNTRY)
                .and_then(|vals| vals.first());

            let serial_num = random::<[u8; 20]>();
            let mut builder = ca::Certificate::client_certificate_builder();
            builder
                .key_algorithm(&key_algorithm)
                .serial_number(serial_num.as_ref())
                .validity_not_after(&validity_not_after)
                .validity_not_before(&validity_not_before)
                .dn_common_name(subj_common_name.as_str())
                .san_uri_user_id(self.device.cert_access_context.user_id)
                .san_uri_platform(self.device.cert_access_context.platform.as_str());
            if let Some(subj_organization) = subj_organization {
                builder.dn_organization(subj_organization.as_str());
            }
            if let Some(subj_country) = subj_country {
                builder.dn_country(subj_country.as_str());
            }
            let certificate = builder.build()?;

            // Create certificate/key pair PEM strings

            let signer_cert = Self::load_existing_rootca_certificate(
                self.app_config.ca_signer_cert_file.as_str(),
                self.app_config
                    .ca_signer_key_file
                    .as_ref()
                    .unwrap()
                    .as_str(),
                &key_algorithm,
            )?;
            let signer_cert_der = signer_cert.generate_certificate(None)?;

            let key_pem = certificate.serialize_private_key();
            let cert_pem = certificate
                .serialize_certificate(Some((&signer_cert_der, signer_cert.key_pair())))?;

            // Queue client-bound certificate reissue message

            let message_frame: control::pdu::MessageFrame = SignalEvent::new(
                control::pdu::CODE_OK,
                &None,
                &EventType::CertificateReissue,
                &Some(
                    serde_json::to_value(CertificateReissueEvent::new(
                        &key_algorithm,
                        &key_pem,
                        &cert_pem,
                    ))
                    .unwrap(),
                ),
            )
            .try_into()
            .unwrap();

            self.message_outbox
                .lock()
                .unwrap()
                .push_back(message_frame.build_pdu()?);

            self.reissued = true;

            info(
                &target!(),
                &format!(
                    "Client certificate/key pair reissued: uid={}, plat={}, ser={:?}, expiry={:?}",
                    self.device.cert_access_context.user_id,
                    self.device.cert_access_context.platform,
                    hex::encode(serial_num),
                    &validity_not_after,
                ),
            );
        }

        Ok(())
    }

    /// Get current datetime (UTC)
    ///
    /// # Returns
    ///
    /// The [`OffsetDateTime`] representing current datetime UTC
    ///
    #[cfg(not(test))]
    fn get_now_utc() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
    #[cfg(test)]
    fn get_now_utc() -> OffsetDateTime {
        datetime!(2024-12-21 0:57:52.0 +00:00:00)
    }

    /// Create root CA [`Certificate`] based on existing root CA certificate/key pem files and corresponding key algorithm
    ///
    /// # Arguments
    ///
    /// * `rootca_cert_file` - Root CA certificate file path
    /// * `rootca_key_file` - Root CA key pait file path
    /// * `key_algorithm` - Private key algorithm corresponding to stored key
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructured [`Certificate`] based on existing key and algorithm.
    ///
    fn load_existing_rootca_certificate(
        rootca_cert_file: &str,
        rootca_key_file: &str,
        key_algorithm: &KeyAlgorithm,
    ) -> Result<Certificate, AppError> {
        let rootca_key_pem = file::load_text_data(rootca_key_file)?;
        let rootca_cert_pem = file::load_text_data(rootca_cert_file)?;
        Certificate::root_ca_certificate_builder()
            .key_algorithm(key_algorithm)
            .key_pair_pem(&rootca_key_pem)
            .certificate_pem(&rootca_cert_pem)
            .build()
    }
}

unsafe impl Send for CertReissuanceProcessor {}

impl SignalingEventHandler for CertReissuanceProcessor {
    fn on_loop_cycle(
        &mut self,
        _signal_events: VecDeque<SignalEvent>,
        is_authenticated: bool,
    ) -> Result<(), AppError> {
        if self.reissued || !is_authenticated {
            return Ok(());
        }

        self.curr_cycle_iteration += 1;
        if self
            .curr_cycle_iteration
            .is_multiple_of(self.recheck_cycle_iterations)
        {
            self.curr_cycle_iteration = 0;
            self.process_outbound_event()?;
        }

        Ok(())
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use std::path::PathBuf;
    use time::macros::datetime;
    use trust0_common::crypto::file::load_certificates;

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "root-ca.crt.pem"];
    const KEYFILE_ROOTCA_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "root-ca.key.pem"];
    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];

    #[test]
    fn certreissueproc_new() {
        let mut app_config = config::tests::create_app_config_with_repos(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_reissuance_threshold_days = 20;
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        let device = Device::new(certs).unwrap();

        let processor = CertReissuanceProcessor::new(
            &Arc::new(app_config),
            &Arc::new(Mutex::new(VecDeque::new())),
            &device,
        );

        assert_eq!(
            processor.cert_reissue_datetime,
            datetime!(2024-12-26 0:57:52.0 +00:00:00)
        );
        assert_eq!(processor.recheck_cycle_iterations, 600);
        assert_eq!(processor.curr_cycle_iteration, 599);
        assert!(!processor.reissued);
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_authed_and_mid_cycle() {
        let rootca_certs_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_file: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let mut app_config = config::tests::create_app_config_with_repos(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_reissuance_threshold_days = 20;
        app_config.ca_signer_cert_file = rootca_certs_file.to_str().unwrap().to_string();
        app_config.ca_signer_key_file = Some(rootca_key_file.to_str().unwrap().to_string());
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        let device = Device::new(certs).unwrap();

        let mut processor = CertReissuanceProcessor::new(
            &Arc::new(app_config),
            &Arc::new(Mutex::new(VecDeque::new())),
            &device,
        );
        processor.curr_cycle_iteration = processor.recheck_cycle_iterations - 2;

        let result = processor.on_loop_cycle(VecDeque::new(), true);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(processor.message_outbox.lock().unwrap().is_empty());
        assert_eq!(
            processor.curr_cycle_iteration,
            processor.recheck_cycle_iterations - 1
        );
        assert!(!processor.reissued);
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_authed_and_cycle_end_and_no_reissue_needed() {
        let rootca_certs_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_file: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let mut app_config = config::tests::create_app_config_with_repos(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_reissuance_threshold_days = 20;
        app_config.ca_signer_cert_file = rootca_certs_file.to_str().unwrap().to_string();
        app_config.ca_signer_key_file = Some(rootca_key_file.to_str().unwrap().to_string());
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        let device = Device::new(certs).unwrap();

        let mut processor = CertReissuanceProcessor::new(
            &Arc::new(app_config),
            &Arc::new(Mutex::new(VecDeque::new())),
            &device,
        );
        processor.curr_cycle_iteration = processor.recheck_cycle_iterations - 1;

        let result = processor.on_loop_cycle(VecDeque::new(), true);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(processor.message_outbox.lock().unwrap().is_empty());
        assert_eq!(processor.curr_cycle_iteration, 0);
        assert!(!processor.reissued);
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_authed_and_cycle_end_and_reissued() {
        let rootca_certs_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_file: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let mut app_config = config::tests::create_app_config_with_repos(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_reissuance_threshold_days = 30;
        app_config.ca_validity_period_days = 360;
        app_config.ca_key_algorithm = config::KeyAlgorithm::EcdsaP384;
        app_config.ca_signer_cert_file = rootca_certs_file.to_str().unwrap().to_string();
        app_config.ca_signer_key_file = Some(rootca_key_file.to_str().unwrap().to_string());
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        let device = Device::new(certs).unwrap();

        let mut processor = CertReissuanceProcessor::new(
            &Arc::new(app_config),
            &Arc::new(Mutex::new(VecDeque::new())),
            &device,
        );
        processor.curr_cycle_iteration = processor.recheck_cycle_iterations - 1;

        let result = processor.on_loop_cycle(VecDeque::new(), true);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(processor.curr_cycle_iteration, 0);
        assert!(processor.reissued);
        assert_eq!(processor.message_outbox.lock().unwrap().len(), 1);
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_authed_and_previously_reissued() {
        let rootca_certs_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_file: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let mut app_config = config::tests::create_app_config_with_repos(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_reissuance_threshold_days = 30;
        app_config.ca_validity_period_days = 360;
        app_config.ca_key_algorithm = config::KeyAlgorithm::EcdsaP384;
        app_config.ca_signer_cert_file = rootca_certs_file.to_str().unwrap().to_string();
        app_config.ca_signer_key_file = Some(rootca_key_file.to_str().unwrap().to_string());
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        let device = Device::new(certs).unwrap();

        let mut processor = CertReissuanceProcessor::new(
            &Arc::new(app_config),
            &Arc::new(Mutex::new(VecDeque::new())),
            &device,
        );
        processor.curr_cycle_iteration = processor.recheck_cycle_iterations - 1;
        processor.reissued = true;

        let result = processor.on_loop_cycle(VecDeque::new(), true);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(
            processor.curr_cycle_iteration,
            processor.recheck_cycle_iterations - 1
        );
        assert!(processor.reissued);
        assert!(processor.message_outbox.lock().unwrap().is_empty());
    }

    #[test]
    fn certreissueproc_on_loop_cycle_when_not_authed_and_not_previously_reissued() {
        let rootca_certs_file: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_file: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let mut app_config = config::tests::create_app_config_with_repos(
            Arc::new(Mutex::new(MockUserRepo::new())),
            Arc::new(Mutex::new(MockServiceRepo::new())),
            Arc::new(Mutex::new(MockRoleRepo::new())),
            Arc::new(Mutex::new(MockAccessRepo::new())),
        )
        .unwrap();
        app_config.ca_reissuance_threshold_days = 30;
        app_config.ca_validity_period_days = 360;
        app_config.ca_key_algorithm = config::KeyAlgorithm::EcdsaP384;
        app_config.ca_signer_cert_file = rootca_certs_file.to_str().unwrap().to_string();
        app_config.ca_signer_key_file = Some(rootca_key_file.to_str().unwrap().to_string());
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap()).unwrap();
        let device = Device::new(certs).unwrap();

        let mut processor = CertReissuanceProcessor::new(
            &Arc::new(app_config),
            &Arc::new(Mutex::new(VecDeque::new())),
            &device,
        );
        processor.curr_cycle_iteration = processor.recheck_cycle_iterations - 1;

        let result = processor.on_loop_cycle(VecDeque::new(), false);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(
            processor.curr_cycle_iteration,
            processor.recheck_cycle_iterations - 1
        );
        assert!(!processor.reissued);
        assert!(processor.message_outbox.lock().unwrap().is_empty());
    }
}
