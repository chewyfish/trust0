use std::collections::HashMap;

use anyhow::Result;
use iter_group::IntoGroup;
use pki_types::CertificateDer;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

use trust0_common::crypto::asn;
use trust0_common::crypto::ca::CertAccessContext;
use trust0_common::error::AppError;

/// Represents client device
#[derive(Clone, Default, Debug)]
pub struct Device {
    /// Certificate subject attributes
    pub cert_subj: HashMap<String, Vec<String>>,

    /// Certificate alternate subject name attributes
    pub cert_alt_subj: HashMap<String, Vec<String>>,

    /// Device certificate info
    pub cert_access_context: CertAccessContext,
}

impl Device {
    /// Device constructor
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
            AppError::GenWithMsgAndErr(
                "Failed to parse subject alternative name".to_string(),
                Box::new(err),
            )
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
                        AppError::GenWithMsgAndErr(
                            "Invalid Certificate Context JSON".to_string(),
                            Box::new(err),
                        )
                    })?;
            }
        }

        Ok(Self {
            cert_subj,
            cert_alt_subj,
            cert_access_context,
        })
    }

    /// Certificate subject attributes
    pub fn get_cert_subj(&self) -> &HashMap<String, Vec<String>> {
        &self.cert_subj
    }

    /// Certificate alternate subject name attributes
    pub fn get_cert_alt_subj(&self) -> &HashMap<String, Vec<String>> {
        &self.cert_alt_subj
    }

    /// Certificate access context accessor
    pub fn get_cert_access_context(&self) -> CertAccessContext {
        self.cert_access_context.clone()
    }

    /// Retrieve the end-entity (aka device) certificate, must be the first one.
    fn device_cert<'a>(
        cert_chain: &'a [CertificateDer<'a>],
    ) -> Result<X509Certificate<'a>, AppError> {
        match cert_chain.first() {
            Some(cert) => Ok(parse_x509_certificate(cert.as_bytes())
                .map_err(|err| {
                    AppError::GenWithMsgAndErr(
                        "Failed to parse client certificate".to_string(),
                        Box::new(err),
                    )
                })?
                .1),
            None => Err(AppError::General(
                "Empty client certificate chain (1)".to_string(),
            )),
        }
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use trust0_common::crypto::file::load_certificates;

    const CERTFILE_CLIENT_UID100_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client-uid100.crt.pem",
    ];
    const CERTFILE_NON_CLIENT_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "non-client.crt.pem"];

    #[test]
    fn device_new_fn_when_valid_client_cert() -> Result<(), AppError> {
        let certs_file: PathBuf = CERTFILE_CLIENT_UID100_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().unwrap().to_string())?;

        let device_result = Device::new(certs);

        if let Ok(device) = &device_result {
            assert_eq!(device.cert_access_context.user_id, 100);
            assert_eq!(device.cert_access_context.platform, "Linux");
            return Ok(());
        }

        panic!("Unexpected result: val={:?}", &device_result);
    }

    #[test]
    fn device_new_fn_when_invalid_client_cert() -> Result<(), AppError> {
        let certs_file: PathBuf = CERTFILE_NON_CLIENT_PATHPARTS.iter().collect();
        let certs = load_certificates(certs_file.to_str().unwrap().to_string())?;

        let device_result = Device::new(certs);

        if let Ok(device) = &device_result {
            let default_device = Device::default();
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
    fn device_new_fn_when_no_certificates() -> Result<(), AppError> {
        let device_result = Device::new(vec![]);

        if let Err(_) = &device_result {
            return Ok(());
        }

        panic!("Unexpected result: val={:?}", &device_result);
    }
}
