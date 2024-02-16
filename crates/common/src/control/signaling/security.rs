use std::borrow::Borrow;

use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::ca;
use crate::error::AppError;

/// Used by CA to send new certificate and public/private key pair to client
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CertificateReissueEvent {
    /// Public key algorithm
    pub key_algorithm: ca::KeyAlgorithm,
    /// Public/private key pair PEM string
    pub key_pair_pem: String,
    /// Certificate PEM string
    pub certificate_pem: String,
}

impl CertificateReissueEvent {
    /// CertificateReissueEvent constructor
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - Public key algorithm
    /// * `key_pair_pem` - Public/private key pair PEM string
    /// * `certificate_pem` - Certificate PEM string
    ///
    /// # Returns
    ///
    /// A newly constructed [`CertificateReissueEvent`] object.
    ///
    pub fn new(
        key_algorithm: &ca::KeyAlgorithm,
        key_pair_pem: &str,
        certificate_pem: &str,
    ) -> Self {
        Self {
            key_algorithm: key_algorithm.clone(),
            key_pair_pem: key_pair_pem.to_string(),
            certificate_pem: certificate_pem.to_string(),
        }
    }

    /// Construct certificate reissue event from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing a [`CertificateReissueEvent`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a [`CertificateReissueEvent`] object.
    ///
    pub fn from_serde_value(value: &Value) -> Result<CertificateReissueEvent, AppError> {
        serde_json::from_value(value.clone()).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting serde Value to CertificateReissueEvent".to_string(),
                Box::new(err),
            )
        })
    }
}

unsafe impl Send for CertificateReissueEvent {}

impl TryInto<Value> for CertificateReissueEvent {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &CertificateReissueEvent {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        serde_json::to_value(self).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting Connection to serde Value".to_string(),
                Box::new(err),
            )
        })
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn certreissueevt_new() {
        let cert_reissue = CertificateReissueEvent::new(
            &ca::KeyAlgorithm::Ed25519,
            "KEY PAIR PEM",
            "CERTIFICATE PEM",
        );

        assert_eq!(cert_reissue.key_algorithm, ca::KeyAlgorithm::Ed25519);
        assert_eq!(cert_reissue.key_pair_pem, "KEY PAIR PEM");
        assert_eq!(cert_reissue.certificate_pem, "CERTIFICATE PEM");
    }
    #[test]
    fn certreissueevt_from_serde_value_when_invalid() {
        let cert_reissue_json = json!({"keyAlgorithm": "Invalid", "keyPairPem": "KEY PAIR PEM", "certificatePem": "CERTIFICATE PEM"});

        match CertificateReissueEvent::from_serde_value(&cert_reissue_json) {
            Ok(cert_reissue) => panic!(
                "Unexpected successful result: cert_reissue={:?}",
                &cert_reissue
            ),
            _ => {}
        }
    }

    #[test]
    fn certreissueevt_from_serde_value_when_valid() {
        let cert_reissue_json = json!({"keyAlgorithm": "ecdsaP256", "keyPairPem": "KEY PAIR PEM", "certificatePem": "CERTIFICATE PEM"});

        match CertificateReissueEvent::from_serde_value(&cert_reissue_json) {
            Ok(cert_reissue) => {
                assert_eq!(cert_reissue.key_algorithm, ca::KeyAlgorithm::EcdsaP256);
                assert_eq!(cert_reissue.key_pair_pem, "KEY PAIR PEM");
                assert_eq!(cert_reissue.certificate_pem, "CERTIFICATE PEM");
            }
            _ => {}
        }
    }

    #[test]
    fn certreissueevt_try_into_value() {
        let cert_reissue = CertificateReissueEvent::new(
            &ca::KeyAlgorithm::Ed25519,
            "KEY PAIR PEM",
            "CERTIFICATE PEM",
        );

        let result: Result<Value, AppError> = cert_reissue.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"keyAlgorithm": "ed25519", "keyPairPem": "KEY PAIR PEM", "certificatePem": "CERTIFICATE PEM"})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }
}
