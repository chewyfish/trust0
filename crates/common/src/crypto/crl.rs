use crate::crypto::ca;
use crate::error::AppError;
use crate::{crypto, file};
use pki_types::{pem::PemObject, CertificateRevocationListDer};
use rcgen::{
    CertificateRevocationList, CertificateRevocationListParams, CrlIssuingDistributionPoint,
    KeyIdMethod, RevocationReason, RevokedCertParams, SerialNumber,
};
use std::ops::DerefMut;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

const VALIDATION_MSG_CERTIFICATE_SERIAL_NUMBER_REQUIRED: &str =
    "Certificate Serial Number required";
const VALIDATION_MSG_CERTIFICATE_REVOCATION_DATETIME_REQUIRED: &str =
    "Certificate Revocation Datetime required";
const VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED: &str = "Serial Number may not exceed 20 octets";
const VALIDATION_MSG_CRL_NUMBER_REQUIRED: &str = "CRL Number required";
const VALIDATION_MSG_CRL_NUMBER_LIMIT_EXCEEDED: &str = "CRL Number may not exceed 20 octets";
const VALIDATION_MSG_UPDATE_DATETIME_REQUIRED: &str = "Update Datetime required";
const VALIDATION_MSG_NEXT_UPDATE_DATETIME_REQUIRED: &str = "Next Update Datetime required";
const VALIDATION_MSG_SIGNATURE_ALGORITHM_REQUIRED: &str = "Signature Algorithm required";
const VALIDATION_MSG_KEY_IDENTIFIER_METHOD_REQUIRED: &str = "Key Identifier Method required";

/// Builder for a revoked certificate (to be added to a CRL)
pub struct RevokedCertificateBuilder {
    /// Unique for each certificate issued by a given CA
    serial_number: Option<Vec<u8>>,
    /// Datetime at which the CA processed the revocation.
    revocation_datetime: Option<OffsetDateTime>,
    /// (Optional) Reason for the certificate revocation
    reason_code: Option<RevocationReason>,
    /// (Optional) Datetime on which key was compromised or that the certificate otherwise became invalid
    invalidity_datetime: Option<OffsetDateTime>,
}

impl RevokedCertificateBuilder {
    /// Returns a new builder, which can create a [`RevokedCertParams`] object
    ///
    /// # Returns
    ///
    /// A [`RevokedCertificateBuilder`] object.
    ///
    pub fn new() -> Self {
        Self {
            serial_number: None,
            revocation_datetime: None,
            reason_code: None,
            invalidity_datetime: None,
        }
    }

    /// Sets the serial number
    ///
    /// # Arguments
    ///
    /// * `serial_number` - Serial number (to uniquely identify certificate, up to 20 octets)
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn serial_number(&mut self, serial_number: &[u8]) -> &mut Self {
        self.serial_number = Some(serial_number.to_vec());
        self
    }

    /// Sets the revocation datetime
    ///
    /// # Arguments
    ///
    /// * `revocation_datetime` - Datetime at which the CA processed the revocation
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn revocation_datetime(&mut self, revocation_datetime: &OffsetDateTime) -> &mut Self {
        self.revocation_datetime = Some(*revocation_datetime);
        self
    }

    /// Sets the revocation reason code
    ///
    /// # Arguments
    ///
    /// * `reason_code` - Reason for the certificate revocation
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn reason_code(&mut self, reason_code: &RevocationReason) -> &mut Self {
        self.reason_code = Some(*reason_code);
        self
    }

    /// Sets the invalidity datetime
    ///
    /// # Arguments
    ///
    /// * `invalidity_datetime` - Datetime on which key was compromised or that the certificate otherwise became invalid
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn invalidity_datetime(&mut self, invalidity_datetime: &OffsetDateTime) -> &mut Self {
        self.invalidity_datetime = Some(*invalidity_datetime);
        self
    }

    /// Invoke the build for the supplied data.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing (if valid) a newly constructed [`RevokedCertParams`] object.
    ///
    pub fn build(&self) -> Result<RevokedCertParams, AppError> {
        // Validation
        let mut errors = Vec::new();

        if self.serial_number.is_none() {
            errors.push(VALIDATION_MSG_CERTIFICATE_SERIAL_NUMBER_REQUIRED.to_string());
        } else if self.serial_number.as_ref().unwrap().len() > ca::SERIAL_NUMBER_MAX_OCTETS {
            errors.push(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED.to_string());
        }
        if self.revocation_datetime.is_none() {
            errors.push(VALIDATION_MSG_CERTIFICATE_REVOCATION_DATETIME_REQUIRED.to_string());
        }
        if self.serial_number.is_some()
            && (self.serial_number.as_ref().unwrap().len() > ca::SERIAL_NUMBER_MAX_OCTETS)
        {
            errors.push(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED.to_string());
        }

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error building revoked certificate: errs={}",
                errors.join(", ")
            )));
        }

        // Valid, set up attributes

        Ok(RevokedCertParams {
            serial_number: SerialNumber::from_slice(
                self.serial_number.as_ref().unwrap().as_slice(),
            ),
            revocation_time: *self.revocation_datetime.as_ref().unwrap(),
            reason_code: self.reason_code,
            invalidity_date: self.invalidity_datetime,
        })
    }
}

impl Default for RevokedCertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for a certificate revocation list (CRL)
pub struct CertificateRevocationListBuilder {
    /// CRL extension that conveys a monotonically increasing sequence number for a given CRL scope and CRL issuer
    crl_number: Option<Vec<u8>>,
    /// Issue datetime of this CRL
    update_datetime: Option<OffsetDateTime>,
    /// Datetime by which the next CRL will be issued
    next_update_datetime: Option<OffsetDateTime>,
    /// (Optional) CRL extension that identifies the CRL distribution point and scope for a particular CRL
    issuing_distribution: Option<CrlIssuingDistributionPoint>,
    /// Algorithm used by the CRL issuer to sign the certificate list
    signature_algorithm: Option<ca::KeyAlgorithm>,
    /// Means of identifying the public key corresponding to the private key used to sign a CRL
    key_ident_method: Option<KeyIdMethod>,
}

impl CertificateRevocationListBuilder {
    /// Returns a new builder, which can create a [`CertificateRevocationList`] object
    ///
    /// # Returns
    ///
    /// A [`CertificateRevocationListBuilder`] object.
    ///
    pub fn new() -> Self {
        Self {
            crl_number: None,
            update_datetime: None,
            next_update_datetime: None,
            issuing_distribution: None,
            signature_algorithm: None,
            key_ident_method: None,
        }
    }

    /// Sets the CRL number
    ///
    /// # Arguments
    ///
    /// * `crl_number` - CRL extension that conveys a monotonically increasing sequence number for a given CRL scope and CRL issuer
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn crl_number(&mut self, crl_number: &[u8]) -> &mut Self {
        self.crl_number = Some(crl_number.to_vec());
        self
    }

    /// Sets the CRL issue datetime
    ///
    /// # Arguments
    ///
    /// * `update_datetime` - Issue datetime of this CRL
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn update_datetime(&mut self, update_datetime: &OffsetDateTime) -> &mut Self {
        self.update_datetime = Some(*update_datetime);
        self
    }

    /// Sets the next CRL issue datetime
    ///
    /// # Arguments
    ///
    /// * `next_update_datetime` - Datetime by which the next CRL will be issued
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn next_update_datetime(&mut self, next_update_datetime: &OffsetDateTime) -> &mut Self {
        self.next_update_datetime = Some(*next_update_datetime);
        self
    }

    /// Sets the issuing distribution point
    ///
    /// # Arguments
    ///
    /// * `issuing_distribution` - CRL extension that identifies the CRL distribution point and scope for a particular CRL
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn issuing_distribution(
        &mut self,
        issuing_distribution: CrlIssuingDistributionPoint,
    ) -> &mut Self {
        self.issuing_distribution = Some(issuing_distribution);
        self
    }

    /// Sets the signature algorithm
    ///
    /// # Arguments
    ///
    /// * `signature_algorithm` - Algorithm used by the CRL issuer to sign the certificate list
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn signature_algorithm(&mut self, signature_algorithm: &ca::KeyAlgorithm) -> &mut Self {
        self.signature_algorithm = Some(signature_algorithm.clone());
        self
    }

    /// Sets the key identifier method
    ///
    /// # Arguments
    ///
    /// * `key_ident_method` - Means of identifying the public key corresponding to the private key used to sign a CRL
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn key_ident_method(&mut self, key_ident_method: KeyIdMethod) -> &mut Self {
        self.key_ident_method = Some(key_ident_method);
        self
    }

    /// Invoke the build for the supplied data.
    ///
    /// # Arguments
    ///
    /// * `revoked_certificates` - List of revoked certificates (possibly empty)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`CertificateRevocationList`] object.
    ///
    pub fn build(
        &mut self,
        revoked_certificates: Vec<RevokedCertParams>,
    ) -> Result<CertificateRevocationList, AppError> {
        // Validation
        let mut errors = Vec::new();

        if self.crl_number.is_none() {
            errors.push(VALIDATION_MSG_CRL_NUMBER_REQUIRED.to_string());
        } else if self.crl_number.as_ref().unwrap().len() > ca::SERIAL_NUMBER_MAX_OCTETS {
            errors.push(VALIDATION_MSG_CRL_NUMBER_LIMIT_EXCEEDED.to_string());
        }
        if self.update_datetime.is_none() {
            errors.push(VALIDATION_MSG_UPDATE_DATETIME_REQUIRED.to_string());
        }
        if self.next_update_datetime.is_none() {
            errors.push(VALIDATION_MSG_NEXT_UPDATE_DATETIME_REQUIRED.to_string());
        }
        if self.signature_algorithm.is_none() {
            errors.push(VALIDATION_MSG_SIGNATURE_ALGORITHM_REQUIRED.to_string());
        }
        if self.key_ident_method.is_none() {
            errors.push(VALIDATION_MSG_KEY_IDENTIFIER_METHOD_REQUIRED.to_string());
        }

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error building certificate revocation list: errs={}",
                errors.join(", ")
            )));
        }

        // Valid, set up attributes

        let crl_params = CertificateRevocationListParams {
            this_update: self.update_datetime.unwrap(),
            next_update: self.next_update_datetime.unwrap(),
            crl_number: SerialNumber::from_slice(self.crl_number.as_ref().unwrap().as_slice()),
            issuing_distribution_point: self.issuing_distribution.take(),
            revoked_certs: revoked_certificates,
            alg: self
                .signature_algorithm
                .as_ref()
                .unwrap()
                .signature_algorithm(),
            key_identifier_method: self.key_ident_method.as_ref().unwrap().clone(),
        };

        CertificateRevocationList::from_params(crl_params).map_err(|err| {
            AppError::General(format!(
                "Error creating certificate revocation list: num={:?}, err={:?}",
                self.crl_number.as_ref().unwrap(),
                &err
            ))
        })
    }
}

impl Default for CertificateRevocationListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a certificate revocation list (CRL) file.
/// Exposes the ability to re-parse entries when file has changed.
pub struct CRLFile {
    /// Path to CRL file
    path: PathBuf,
    /// Last modified file time (used to determine reloading)
    last_mtime: SystemTime,
    /// Last loaded CRL object list
    crl_list: Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>>,
    /// Controls whether reloading loop is active
    reloading: Arc<Mutex<bool>>,
}

impl CRLFile {
    /// CRLFile constructor
    ///
    /// # Arguments
    ///
    /// * `filepath_str` - CRL file pathspec
    /// * `crl_list` - CRL objects list (potentially updated on changes)
    /// * `reloading` - Controls whether reloading loop is active
    ///
    /// # Returns
    ///
    /// A [`anyhow::Result`] containing the new constructed [`CRLFile`] object.
    /// If the file path is not valid, will return an error.
    ///
    pub fn new(
        filepath_str: &str,
        crl_list: &Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>>,
        reloading: &Arc<Mutex<bool>>,
    ) -> anyhow::Result<Self, AppError> {
        let filepath = PathBuf::from_str(filepath_str).map_err(|err| {
            AppError::General(format!(
                "Error converting string to file path: file={}, err={:?}",
                filepath_str, &err
            ))
        })?;
        Ok(CRLFile {
            path: filepath,
            last_mtime: UNIX_EPOCH,
            crl_list: crl_list.clone(),
            reloading: reloading.clone(),
        })
    }

    /// CRL list accessor
    ///
    /// # Returns
    ///
    /// The CRL objects list
    ///
    pub fn crl_list(&mut self) -> Arc<Mutex<Vec<CertificateRevocationListDer<'static>>>> {
        self.crl_list.clone()
    }
}

impl file::ReloadableFile for CRLFile {
    fn filepath(&self) -> &PathBuf {
        &self.path
    }

    fn last_file_mtime(&mut self) -> &mut SystemTime {
        &mut self.last_mtime
    }

    fn on_reload_data(&mut self) -> anyhow::Result<(), AppError> {
        match crypto::file::load_crl_list(self.path.to_str().unwrap()) {
            Ok(list) => {
                *self.crl_list.lock().unwrap().deref_mut() = CertificateRevocationListDer::pem_slice_iter(
                    list.as_slice(),
                )
                .map(|result| {
                    result.map_err(|err| {
                        AppError::General(format!(
                            "Error reading CRL entries: file={:?}, err={:?}",
                            &self.path, &err
                        ))
                    })
                })
                .collect::<anyhow::Result<Vec<CertificateRevocationListDer<'static>>, AppError>>(
                )?;
                Ok(())
            }
            Err(err) => Err(AppError::General(format!(
                "Error loading CRL file: file={:?}, err={:?}",
                &self.path, &err
            ))),
        }
    }

    fn on_critical_error(&mut self, err: &AppError) {
        panic!("Error during CRL reload, exiting: err={:?}", &err);
    }

    fn reloading(&self) -> &Arc<Mutex<bool>> {
        &self.reloading
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::crypto::ca::SERIAL_NUMBER_MAX_OCTETS;
    use crate::crypto::crl::CRLFile;
    use crate::file::ReloadableFile;
    use rcgen::{CrlDistributionPoint, CrlScope};
    use std::path::PathBuf;
    use time::macros::datetime;

    const _CERTFILE_CLIENT0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.crt.pem",
    ];
    pub const CRLFILE_REVOKED_CERTS_0_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "revoked-crts-0.crl.pem",
    ];
    pub const CRLFILE_REVOKED_CERTS_0_1_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "revoked-crts-0-1.crl.pem",
    ];
    pub const CRLFILE_INVALID_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "invalid.crl.pem"];
    pub const CRLFILE_MISSING_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    #[test]
    fn revokecert_default_and_thus_new() {
        let builder = RevokedCertificateBuilder::default();
        assert!(builder.serial_number.is_none());
        assert!(builder.revocation_datetime.is_none());
        assert!(builder.reason_code.is_none());
        assert!(builder.invalidity_datetime.is_none());
    }

    #[test]
    fn revokecert_build_when_missing_all_required_data() {
        let builder = RevokedCertificateBuilder {
            serial_number: None,
            revocation_datetime: None,
            reason_code: None,
            invalidity_datetime: None,
        };

        let result = builder.build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_CERTIFICATE_SERIAL_NUMBER_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_CERTIFICATE_REVOCATION_DATETIME_REQUIRED));
    }

    #[test]
    fn revokecert_build_when_invalid_serial_number() {
        let mut builder = RevokedCertificateBuilder {
            serial_number: None,
            revocation_datetime: Some(OffsetDateTime::now_utc()),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_datetime: Some(OffsetDateTime::now_utc()),
        };

        builder.serial_number(&[0u8; SERIAL_NUMBER_MAX_OCTETS + 1].to_vec());

        let result = builder.build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED));
    }

    #[test]
    fn revokecert_build_when_all_valid() {
        let mut builder = RevokedCertificateBuilder {
            serial_number: None,
            revocation_datetime: None,
            reason_code: None,
            invalidity_datetime: None,
        };

        let result = builder
            .serial_number(&[0u8, 1u8])
            .revocation_datetime(&datetime!(2024-01-01 0:00 UTC))
            .reason_code(&RevocationReason::KeyCompromise)
            .invalidity_datetime(&datetime!(2024-02-01 0:00 UTC))
            .build();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let revoked_cert = result.unwrap();

        assert_eq!(
            &revoked_cert.serial_number,
            &SerialNumber::from_slice(&[0u8, 1u8])
        );
        assert_eq!(
            &revoked_cert.revocation_time,
            &datetime!(2024-01-01 0:00 UTC)
        );
        assert!(revoked_cert.reason_code.is_some());
        assert_eq!(
            revoked_cert.reason_code.as_ref().unwrap(),
            &RevocationReason::KeyCompromise
        );
        assert!(revoked_cert.invalidity_date.is_some());
        assert_eq!(
            revoked_cert.invalidity_date.as_ref().unwrap(),
            &datetime!(2024-02-01 0:00 UTC)
        );
    }

    #[test]
    fn certrevokelist_default_and_thus_new() {
        let builder = CertificateRevocationListBuilder::default();
        assert!(builder.crl_number.is_none());
        assert!(builder.update_datetime.is_none());
        assert!(builder.next_update_datetime.is_none());
        assert!(builder.issuing_distribution.is_none());
        assert!(builder.signature_algorithm.is_none());
        assert!(builder.key_ident_method.is_none());
    }

    #[test]
    fn certrevokelist_build_when_missing_all_required_data() {
        let mut builder = CertificateRevocationListBuilder {
            crl_number: None,
            update_datetime: None,
            next_update_datetime: None,
            issuing_distribution: None,
            signature_algorithm: None,
            key_ident_method: None,
        };

        let result = builder.build(vec![]);

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_CRL_NUMBER_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_UPDATE_DATETIME_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_NEXT_UPDATE_DATETIME_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_SIGNATURE_ALGORITHM_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_KEY_IDENTIFIER_METHOD_REQUIRED));
    }

    #[test]
    fn certrevokelist_build_when_invalid_serial_number() {
        let mut builder = CertificateRevocationListBuilder {
            crl_number: None,
            update_datetime: Some(OffsetDateTime::now_utc()),
            next_update_datetime: Some(OffsetDateTime::now_utc()),
            issuing_distribution: None,
            signature_algorithm: Some(ca::KeyAlgorithm::EcdsaP256),
            key_ident_method: Some(KeyIdMethod::Sha256),
        };

        builder.crl_number(&[0u8; SERIAL_NUMBER_MAX_OCTETS + 1].to_vec());

        let result = builder.build(vec![]);

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_CRL_NUMBER_LIMIT_EXCEEDED));
    }

    #[test]
    fn certrevokelist_build_when_all_valid() {
        let dist_pt_uris = vec!["https://example.com/crl".to_string()];
        let mut builder = CertificateRevocationListBuilder {
            crl_number: None,
            update_datetime: None,
            next_update_datetime: None,
            issuing_distribution: None,
            signature_algorithm: None,
            key_ident_method: None,
        };

        let result = builder
            .crl_number(&[0u8, 1u8])
            .update_datetime(&datetime!(2024-01-01 0:00 UTC))
            .next_update_datetime(&datetime!(2024-02-01 0:00 UTC))
            .issuing_distribution(CrlIssuingDistributionPoint {
                distribution_point: CrlDistributionPoint {
                    uris: dist_pt_uris.clone(),
                },
                scope: Some(CrlScope::UserCertsOnly),
            })
            .signature_algorithm(&ca::KeyAlgorithm::EcdsaP256)
            .key_ident_method(KeyIdMethod::Sha256)
            .build(vec![RevokedCertificateBuilder::new()
                .serial_number(&[2u8, 3u8])
                .revocation_datetime(&datetime!(2024-01-10 0:00 UTC))
                .reason_code(&RevocationReason::KeyCompromise)
                .invalidity_datetime(&datetime!(2024-02-10 0:00 UTC))
                .build()
                .unwrap()]);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let crl = result.unwrap();

        assert_eq!(
            &crl.get_params().crl_number,
            &SerialNumber::from_slice(&[0u8, 1u8])
        );
        assert_eq!(
            &crl.get_params().this_update,
            &datetime!(2024-01-01 0:00 UTC)
        );
        assert_eq!(
            &crl.get_params().next_update,
            &datetime!(2024-02-01 0:00 UTC)
        );
        assert_eq!(crl.get_params().alg, &rcgen::PKCS_ECDSA_P256_SHA256);
        assert_eq!(crl.get_params().key_identifier_method, KeyIdMethod::Sha256);

        assert!(crl.get_params().issuing_distribution_point.is_some());
        let issue_dist_pt = crl
            .get_params()
            .issuing_distribution_point
            .as_ref()
            .unwrap();
        assert_eq!(issue_dist_pt.distribution_point.uris, dist_pt_uris);
        assert!(issue_dist_pt.scope.is_some());
        assert_eq!(
            issue_dist_pt.scope.as_ref().unwrap(),
            &CrlScope::UserCertsOnly
        );

        assert_eq!(crl.get_params().revoked_certs.len(), 1);
        let revoked_cert = crl.get_params().revoked_certs.get(0).unwrap();
        assert_eq!(
            &revoked_cert.serial_number,
            &SerialNumber::from_slice(&[2u8, 3u8])
        );
        assert_eq!(
            &revoked_cert.revocation_time,
            &datetime!(2024-01-10 0:00 UTC)
        );
        assert!(revoked_cert.reason_code.is_some());
        assert_eq!(
            revoked_cert.reason_code.as_ref().unwrap(),
            &RevocationReason::KeyCompromise
        );
        assert!(revoked_cert.invalidity_date.is_some());
        assert_eq!(
            revoked_cert.invalidity_date.as_ref().unwrap(),
            &datetime!(2024-02-10 0:00 UTC)
        );
    }

    #[test]
    fn crlfile_new() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        assert_eq!(
            crl_file.path.to_str().unwrap().to_string(),
            crl_filepath_str.to_string()
        );
        assert!(crl_file.crl_list.lock().unwrap().is_empty());
        assert_eq!(*crl_file.reloading.lock().unwrap(), false);
    }

    #[test]
    fn crlfile_accessors() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = file::file_mtime(crl_filepath.as_path()).unwrap();

        let mut crl_file = CRLFile {
            path: crl_filepath.clone(),
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        assert_eq!(*crl_file.filepath(), crl_filepath);
        assert_eq!(*crl_file.last_file_mtime(), last_mtime);
        assert!(*crl_file.reloading().lock().unwrap());
    }

    #[test]
    fn crlfile_crl_list_when_invalid_filepath() {
        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Ok(()) = reload_result {
            panic!("Unexpected successful reload result");
        }

        let crl_list = crl_file.crl_list();

        assert!(crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_crl_list_when_invalid_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Ok(()) = reload_result {
            panic!("Unexpected successful reload result:");
        }

        let crl_list = crl_file.crl_list();

        assert!(crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_crl_list_when_valid_1_entry_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Err(err) = reload_result {
            panic!("Unexpected reload result: err={:?}", &err);
        }

        let crl_list = crl_file.crl_list();

        assert!(!crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_crl_list_when_valid_2_entry_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_1_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let reloading = Arc::new(Mutex::new(false));

        let mut crl_file = CRLFile::new(crl_filepath_str, &crl_list, &reloading).unwrap();

        let reload_result = crl_file.on_reload_data();
        if let Err(err) = reload_result {
            panic!("Unexpected reload result: err={:?}", &err);
        }

        let crl_list = crl_file.crl_list();

        assert!(!crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_process_reload_when_file_unchanged() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap().to_string();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = file::file_mtime(crl_filepath.as_path()).unwrap();
        let saved_last_mtime = last_mtime.clone();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = crl_file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed CRL list reload result: path={}, err={:?}",
                &crl_filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, false);
        assert_eq!(crl_file.last_mtime, saved_last_mtime);
        assert!(crl_list.lock().unwrap().is_empty());
    }

    #[test]
    fn crlfile_process_reload_when_file_changed() {
        let crl_filepath: PathBuf = CRLFILE_REVOKED_CERTS_0_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap().to_string();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = SystemTime::now();
        let saved_last_mtime = last_mtime.clone();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = crl_file.process_reload();
        if let Err(err) = result {
            panic!(
                "Unexpected processed CRL list reload result: path={}, err={:?}",
                &crl_filepath_str, &err
            );
        }
        let was_reloaded = result.unwrap();

        assert_eq!(was_reloaded, true);
        assert_ne!(crl_file.last_mtime, saved_last_mtime);
        assert!(!crl_list.lock().unwrap().is_empty());
    }

    #[test]
    #[should_panic]
    fn crlfile_process_reload_when_invalid_filepath() {
        let crl_filepath: PathBuf = CRLFILE_MISSING_PATHPARTS.iter().collect();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = SystemTime::now();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let _ = crl_file.process_reload();
    }

    #[test]
    fn crlfile_process_reload_when_invalid_crlfile() {
        let crl_filepath: PathBuf = CRLFILE_INVALID_PATHPARTS.iter().collect();
        let crl_filepath_str = crl_filepath.to_str().unwrap().to_string();
        let crl_list = Arc::new(Mutex::new(vec![]));
        let last_mtime = SystemTime::now();

        let mut crl_file = CRLFile {
            path: crl_filepath,
            last_mtime,
            crl_list: crl_list.clone(),
            reloading: Arc::new(Mutex::new(true)),
        };

        let result = crl_file.process_reload();
        if let Ok(was_reloaded) = result {
            panic!(
                "Unexpected processed CRL list reload result: path={}, reloaded={}",
                &crl_filepath_str, &was_reloaded
            );
        }

        assert!(crl_list.lock().unwrap().is_empty());
    }
}
