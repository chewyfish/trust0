use std::collections::HashMap;

use ::time::OffsetDateTime;
use anyhow::Result;
use iter_group::IntoGroup;
use pki_types::CertificateDer;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

use trust0_common::crypto::asn;
use trust0_common::crypto::ca::CertAccessContext;
use trust0_common::error::AppError;

pub const CERT_OID_COMMON_NAME: &str = "2.5.4.3";
pub const CERT_OID_ORGANIZATION: &str = "2.5.4.10";
#[allow(dead_code)]
pub const CERT_OID_DEPARTMENT: &str = "2.5.4.11";
#[allow(dead_code)]
pub const CERT_OID_LOCALITY: &str = "2.5.4.7";
#[allow(dead_code)]
pub const CERT_OID_STATE: &str = "2.5.4.8";
pub const CERT_OID_COUNTRY: &str = "2.5.4.6";

/// Represents client device
#[derive(Clone, Debug)]
pub struct Device {
    /// Certificate subject attributes
    pub cert_subj: HashMap<String, Vec<String>>,

    /// Certificate alternate subject name attributes
    pub cert_alt_subj: HashMap<String, Vec<String>>,

    /// Device certificate info
    pub cert_access_context: CertAccessContext,

    /// Certificate serial number
    pub cert_serial_num: Vec<u8>,

    /// Certificate validity period
    pub cert_validity: Validity,
}

impl Device {
    /// Device constructor
    ///
    /// # Arguments
    ///
    /// * `device_cert_chain` - [`CertificateDer`] chain
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`Device`] object.
    ///
    pub fn new(device_cert_chain: Vec<CertificateDer<'static>>) -> Result<Self, AppError> {
        let x509_cert = Device::device_cert(&device_cert_chain)?;

        let cert_subj = x509_cert
            .subject
            .iter()
            .flat_map(|dn| dn.iter())
            .map(|attr| match asn::stringify_asn_value(attr.attr_value()) {
                Ok(attr_value) => Ok((attr.attr_type().to_string(), attr_value)),
                Err(err) => Err(err),
            })
            .group::<Result<HashMap<_, Vec<_>>, AppError>>()?;

        let mut cert_alt_subj = HashMap::new();
        let mut cert_access_context = CertAccessContext::default();

        if let Some(cert_alt_subj_ext) = x509_cert.subject_alternative_name().map_err(|err| {
            AppError::General(format!(
                "Failed to parse subject alternative name: err={:?}",
                &err
            ))
        })? {
            cert_alt_subj = cert_alt_subj_ext
                .value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::URI(val) => Some(("URI".to_string(), val.to_string())),
                    _ => None,
                })
                .group::<HashMap<_, Vec<_>>>();

            if let Some(uri_value) = cert_alt_subj.get("URI") {
                cert_access_context = serde_json::from_str(uri_value.first().unwrap().as_str())
                    .map_err(|err| {
                        AppError::General(format!(
                            "Invalid Certificate Context JSON: err={:?}",
                            &err
                        ))
                    })?;
            }
        }

        Ok(Self {
            cert_subj,
            cert_alt_subj,
            cert_access_context,
            cert_serial_num: x509_cert.raw_serial().to_vec(),
            cert_validity: x509_cert.validity.clone(),
        })
    }

    /// Certificate subject attributes
    ///
    /// # Returns
    ///
    /// Reference to the map containing the certificate subject entries.
    ///
    pub fn get_cert_subj(&self) -> &HashMap<String, Vec<String>> {
        &self.cert_subj
    }

    /// Certificate alternate subject name attributes
    ///
    /// # Returns
    ///
    /// Reference to the map containing the subject alternative name entries.
    ///
    pub fn get_cert_alt_subj(&self) -> &HashMap<String, Vec<String>> {
        &self.cert_alt_subj
    }

    /// Certificate access context accessor
    ///
    /// # Returns
    ///
    /// The [`CertAccessContext`] for the certificate.
    ///
    pub fn get_cert_access_context(&self) -> CertAccessContext {
        self.cert_access_context.clone()
    }

    /// Certificate serial number
    ///
    /// # Returns
    ///
    /// Reference to the certificate serial number
    ///
    pub fn get_cert_serial_num(&self) -> &Vec<u8> {
        &self.cert_serial_num
    }

    /// Certificate validity period accessor
    ///
    /// # Returns
    ///
    /// Reference to the certificate validity period.
    ///
    pub fn get_cert_validity(&self) -> &Validity {
        &self.cert_validity
    }

    /// Retrieve the end-entity (aka device) certificate, must be the first one.
    ///
    /// # Returns
    ///
    /// The first certificate in the [`CertificateDer`] chain.
    ///
    fn device_cert<'a>(
        cert_chain: &'a [CertificateDer<'a>],
    ) -> Result<X509Certificate<'a>, AppError> {
        match cert_chain.first() {
            Some(cert) => Ok(parse_x509_certificate(cert.as_bytes())
                .map_err(|err| {
                    AppError::General(format!(
                        "Failed to parse client certificate: err={:?}",
                        &err
                    ))
                })?
                .1),
            None => Err(AppError::General(
                "Empty client certificate chain (1)".to_string(),
            )),
        }
    }
}

impl Default for Device {
    fn default() -> Self {
        Self {
            cert_subj: HashMap::new(),
            cert_alt_subj: HashMap::new(),
            cert_access_context: CertAccessContext::default(),
            cert_serial_num: Vec::new(),
            cert_validity: Validity {
                not_before: ASN1Time::from(OffsetDateTime::UNIX_EPOCH),
                not_after: ASN1Time::from(OffsetDateTime::UNIX_EPOCH),
            },
        }
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use ::time::macros::datetime;
    use std::path::PathBuf;
    use trust0_common::crypto::ca::EntityType;
    use trust0_common::crypto::file::load_certificates;

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];
    const CERTFILE_NON_CLIENT_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "non-client.crt.pem"];
    const CERTFILE_GATEWAY_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "gateway.crt.pem"];

    #[test]
    fn device_new_fn_when_valid_client_cert() -> Result<(), AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap())?;

        let device_result = Device::new(certs);

        if let Ok(device) = &device_result {
            assert_eq!(device.cert_serial_num, vec![3u8, 232u8]);
            assert_eq!(device.cert_access_context.entity_type, EntityType::Client);
            assert_eq!(device.cert_access_context.user_id, 100);
            assert_eq!(device.cert_access_context.platform, "Linux");
            return Ok(());
        }

        panic!("Unexpected result: val={:?}", &device_result);
    }

    #[test]
    fn device_new_fn_when_invalid_client_cert() -> Result<(), AppError> {
        let certs_file: PathBuf = CERTFILE_NON_CLIENT_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap())?;

        let device_result = Device::new(certs);

        if let Ok(device) = &device_result {
            let default_device = Device::default();
            assert_eq!(
                device.cert_serial_num,
                vec![
                    94u8, 51u8, 9u8, 59u8, 79u8, 225u8, 97u8, 148u8, 183u8, 195u8, 188u8, 141u8,
                    4u8, 157u8, 253u8, 51u8, 209u8, 33u8, 97u8, 146u8
                ]
            );
            assert_eq!(
                device.cert_access_context.user_id,
                default_device.cert_access_context.user_id
            );
            assert_eq!(
                device.cert_access_context.platform,
                default_device.cert_access_context.platform
            );
            return Ok(());
        }

        panic!("Unexpected result: val={:?}", &device_result);
    }

    #[test]
    fn device_new_fn_when_valid_gateway_cert() -> Result<(), AppError> {
        let certs_file: PathBuf = CERTFILE_GATEWAY_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap())?;

        let device_result = Device::new(certs);

        if let Ok(device) = &device_result {
            assert_eq!(device.cert_serial_num, vec![3u8, 231u8]);
            assert_eq!(device.cert_access_context.entity_type, EntityType::Gateway);
            assert_eq!(device.cert_access_context.user_id, 0);
            assert_eq!(device.cert_access_context.platform, "");
            return Ok(());
        }

        panic!("Unexpected result: val={:?}", &device_result);
    }

    #[test]
    fn device_new_fn_when_no_certificates() -> Result<(), AppError> {
        let device_result = Device::new(vec![]);

        if device_result.is_err() {
            return Ok(());
        }

        panic!("Unexpected result: val={:?}", &device_result);
    }

    #[test]
    fn device_accessors() -> Result<(), AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().as_ref().unwrap())?;

        let device = Device::new(certs)?;

        assert_eq!(
            device.get_cert_subj(),
            &HashMap::from([
                (
                    CERT_OID_COMMON_NAME.to_string(),
                    vec!["example-client.local".to_string()]
                ),
                (
                    CERT_OID_ORGANIZATION.to_string(),
                    vec!["Example1".to_string()]
                ),
                (CERT_OID_COUNTRY.to_string(), vec!["US".to_string()]),
            ])
        );
        assert_eq!(
            device.get_cert_alt_subj(),
            &HashMap::from([(
                "URI".to_string(),
                vec![r#"{"entityType":"client","platform":"Linux","userId":100}"#.to_string()]
            ),])
        );
        assert_eq!(
            device.get_cert_access_context(),
            CertAccessContext {
                entity_type: EntityType::Client,
                user_id: 100,
                platform: "Linux".to_string()
            }
        );
        assert_eq!(device.cert_serial_num, vec![3u8, 232u8]);
        assert_eq!(
            device.get_cert_validity(),
            &Validity {
                not_before: ASN1Time::from(datetime!(2025-12-21 19:04:45.0 +00:00:00)),
                not_after: ASN1Time::from(datetime!(2100-01-01 0:00:00.0 +00:00:00)),
            }
        );

        Ok(())
    }
}
