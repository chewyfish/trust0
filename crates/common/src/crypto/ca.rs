use pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::SerialNumber;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use serde_derive::{Deserialize, Serialize};
use time::OffsetDateTime;
use x509_parser::nom::AsBytes;

use crate::error::AppError;

const DEFAULT_DISTINGUISHED_NAME_COUNTRY_NAME: &str = "NA";
const DEFAULT_DISTINGUISHED_NAME_ORGANIZATION_NAME: &str = "NA";

pub const SERIAL_NUMBER_MAX_OCTETS: usize = 20;

const VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED: &str = "Serial number may not exceed 20 octets";
const VALIDATION_MSG_KEY_ALGORITHM_REQUIRED: &str = "Key Algorithm required";
const VALIDATION_MSG_KEY_PAIR_PEM_REQUIRED: &str = "Key Pair PEM required";
const VALIDATION_MSG_INVALID_KEY_PAIR_PEM_CONTENTS: &str = "Invalid Key Pair PEM contents";
const VALIDATION_MSG_CERTIFICATE_PEM_REQUIRED: &str = "Certificate PEM required";
const VALIDATION_MSG_INVALID_CERTIFICATE_PEM_CONTENTS: &str = "Invalid Certificate PEM contents";
const VALIDATION_MSG_VALIDITY_NOT_BEFORE_REQUIRED: &str = "Validity Not-Before required";
const VALIDATION_MSG_VALIDITIY_NOT_AFTER_REQUIRED: &str = "Validity Not-After required";
const VALIDATION_MSG_VALIDITY_ORDER_CONSTRAINT_ERROR: &str =
    "Validity Not-Before must be less than Not-After";
const VALIDATION_MSG_DN_COMMON_NAME_REQUIRED: &str = "DN Common Name required";
const VALIDATION_MSG_SAN_URI_USER_ID_REQUIRED: &str = "SAN URI User ID is required";
const VALIDATION_MSG_SAN_URI_PLATFORM_REQUIRED: &str = "SAN URI Platform is required";

/// Trust0 entity utiliing PKI resources
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub enum EntityType {
    /// Root CA, used to sign gateway/client certs
    #[serde(rename = "rootca")]
    RootCa,
    /// Trust0 gateway
    #[serde(rename = "gateway")]
    Gateway,
    /// Trust0 client
    #[serde(rename = "client")]
    #[default]
    Client,
}

/// User/device access context, stored as JSON in client certificate's SAN URI entry
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertAccessContext {
    /// Trust0 entity type
    #[serde(default)]
    pub entity_type: EntityType,
    /// Machine architecture platform hosting certificate
    pub platform: String,
    /// DB User ID for user (for client certs)
    pub user_id: i64,
}

/// Supported public key algorithms
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyAlgorithm {
    /// Elliptic curve P-256
    EcdsaP256,
    /// Elliptic curve P-384
    EcdsaP384,
    /// Edwards curve DSA Ed25519
    #[default]
    Ed25519,
}

impl KeyAlgorithm {
    /// Corresponding [`rcgen::SignatureAlgorithm`] for [`KeyAlgorithm`]
    ///
    /// # Returns
    ///
    /// [`rcgen::SignatureAlgorithm`] object for [`Self`]
    ///
    pub fn signature_algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            KeyAlgorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            KeyAlgorithm::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            KeyAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
        }
    }

    /// Create new key pair ([`rcgen::KeyPair`]) according to key algorithm
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly created [`rcgen::KeyPair`] object.
    ///
    fn create_key_pair(&self) -> Result<rcgen::KeyPair, AppError> {
        let rand = ring::rand::SystemRandom::new();
        let sig_alg;
        let pkcs8;
        match self {
            KeyAlgorithm::EcdsaP256 => {
                sig_alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rand);
            }
            KeyAlgorithm::EcdsaP384 => {
                sig_alg = &rcgen::PKCS_ECDSA_P384_SHA384;
                pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rand);
            }
            KeyAlgorithm::Ed25519 => {
                sig_alg = &rcgen::PKCS_ED25519;
                pkcs8 = Ed25519KeyPair::generate_pkcs8(&rand);
            }
        }

        let pkcs8 = pkcs8.map_err(|err| {
            AppError::General(format!("Error generating PKCS8 key pair: err={:?}", &err))
        })?;
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pkcs8.as_ref()));

        rcgen::KeyPair::from_der_and_sign_algo(&private_key, sig_alg).map_err(|err| {
            AppError::General(format!(
                "Error preparing key pair for signature: err={:?}",
                &err
            ))
        })
    }
}

/// Certificate source representation
pub enum CertificateSource {
    /// DER object
    DER(Vec<u8>),
    /// Build parameters
    Params(Box<rcgen::CertificateParams>),
}

/// Represents the core PKI (certificate, key pair) for a given entity type
pub struct Certificate {
    /// Type of Trust0 entity
    entity_type: EntityType,
    /// Public key algorithm
    _key_algorithm: KeyAlgorithm,
    /// certificate source object
    cert_source: CertificateSource,
    /// [`rcgen::KeyPair`] object
    key_pair: rcgen::KeyPair,
}

impl Certificate {
    /// Certiticate entity type accessor
    ///
    /// # Returns
    ///
    /// A [`EntityType`] object.
    ///
    pub fn entity_type(&self) -> &EntityType {
        &self.entity_type
    }

    /// Certificate public key algorithm type accessor
    ///
    /// # Returns
    ///
    /// A [`KeyAlgorithm`] object.
    ///
    pub fn key_algorithm(&self) -> &KeyAlgorithm {
        &self._key_algorithm
    }

    /// Certificate source accessor
    ///
    /// # Returns
    ///
    /// A [`CertificateSource`] object.
    ///
    pub fn cert_source(&self) -> &CertificateSource {
        &self.cert_source
    }

    /// Certificate public key pair accessor
    ///
    /// # Returns
    ///
    /// A [`rcgen::KeyPair`] object.
    ///
    pub fn key_pair(&self) -> &rcgen::KeyPair {
        &self.key_pair
    }

    /// Returns a builder, which can create a [`Certificate`] for a Trust0 root CA
    ///
    /// # Returns
    ///
    /// A [`RootCaCertificateBuilder`] object.
    ///
    pub fn root_ca_certificate_builder() -> RootCaCertificateBuilder {
        RootCaCertificateBuilder {
            common_builder: CommonCertificateBuilder::default(),
        }
    }

    /// Returns a builder, which can create a [`Certificate`] for a Trust0 gateway
    ///
    /// # Returns
    ///
    /// A [`GatewayCertificateBuilder`] object.
    ///
    pub fn gateway_certificate_builder() -> GatewayCertificateBuilder {
        GatewayCertificateBuilder {
            common_builder: CommonCertificateBuilder::default(),
            san_dns_names: Vec::new(),
        }
    }

    /// Returns a builder, which can create a [`Certificate`] for a Trust0 client
    ///
    /// # Returns
    ///
    /// A [`ClientCertificateBuilder`] object.
    ///
    pub fn client_certificate_builder() -> ClientCertificateBuilder {
        ClientCertificateBuilder {
            common_builder: CommonCertificateBuilder::default(),
            san_uri_user_id: None,
            san_uri_platform: None,
        }
    }

    /// Build and return the corresponding [`rcgen::Issuer`] for this certificate (only valid for [`EntityType::RootCa`] certs)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the corresponding [`rcgen::Issuer`] object
    ///
    pub fn build_issuer(&self) -> Result<rcgen::Issuer<'_, &rcgen::KeyPair>, AppError> {
        if self.entity_type != EntityType::RootCa {
            return Err(AppError::General(format!(
                "Only root CA certificates can be certificate issuers: val={:?}",
                &self.entity_type
            )));
        }

        match &self.cert_source() {
            CertificateSource::DER(cert_der) => rcgen::Issuer::from_ca_cert_der(
                &CertificateDer::from_slice(cert_der.as_slice()),
                self.key_pair(),
            ),
            CertificateSource::Params(cert_params) => {
                Ok(rcgen::Issuer::from_params(cert_params, self.key_pair()))
            }
        }
        .map_err(|err| {
            AppError::General(format!(
                "Error building issuer from certificate: err={:?}",
                &err
            ))
        })
    }

    /// Create a ['rcgen::Certificate'] pertaining to the certificate. Pass in a CA [`rcgen::Certificate`]
    /// and [`rcgen::KeyPair`] to use in signing the generated certificate DER object.
    ///
    /// # Arguments
    ///
    /// * `signer` - An optional [`rcgen::Issuer`] used to sign certificates
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the generated [`rcgen::Certificate`] DER object.
    ///
    pub fn generate_certificate<S: rcgen::SigningKey>(
        &self,
        signer: Option<&rcgen::Issuer<'_, S>>,
    ) -> Result<rcgen::Certificate, AppError> {
        let CertificateSource::Params(cert_params) = &self.cert_source else {
            return Err(AppError::General(
                "Certificate parameters required to build certificate".to_string(),
            ));
        };

        match signer {
            Some(issuer) => cert_params
                .clone()
                .signed_by(&self.key_pair, issuer)
                .map_err(|err| {
                    AppError::General(format!(
                        "Error building signed certificate: type={:?}, err={:?}",
                        &self.entity_type, &err
                    ))
                }),
            None => cert_params
                .clone()
                .self_signed(&self.key_pair)
                .map_err(|err| {
                    AppError::General(format!(
                        "Error building self-signed certificate: type={:?}, err={:?}",
                        &self.entity_type, &err
                    ))
                }),
        }
    }

    /// Create a PEM string pertaining to the certificate. Pass in a CA [`rcgen::Certificate`]
    /// and [`rcgen::KeyPair`] to use in signing the generated certificate PEM.
    ///
    /// # Arguments
    ///
    /// * `signer` - An optional [`rcgen::Issuer`] used to sign certificates
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the generated certificate PEM string.
    ///
    pub fn serialize_certificate<S: rcgen::SigningKey>(
        &self,
        signer: Option<&rcgen::Issuer<'_, S>>,
    ) -> Result<String, AppError> {
        self.generate_certificate(signer)
            .map(|cert| rcgen::Certificate::pem(&cert))
    }

    /// Create a PEM string pertaining to the certificate's key pair
    ///
    /// # Returns
    ///
    /// The generated key pair PEM string.
    ///
    pub fn serialize_private_key(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Create a PEM string pertaining to the signed certificate revocation list (CRL) object
    ///
    /// # Arguments
    ///
    /// * `crl_params` - A [`rcgen::CertificateRevocationListParams`] object to use in generating
    ///   and serializing CRL PEM string
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the generated CRL PEM string.
    ///
    pub fn serialize_certificate_revocation_list(
        &self,
        crl_params: rcgen::CertificateRevocationListParams,
    ) -> Result<String, AppError> {
        let signer = match &self.cert_source() {
            CertificateSource::DER(cert_der) => rcgen::Issuer::from_ca_cert_der(
                &CertificateDer::from_slice(cert_der.as_slice()),
                self.key_pair(),
            ),
            CertificateSource::Params(cert_params) => {
                Ok(rcgen::Issuer::from_params(cert_params, self.key_pair()))
            }
        }
        .map_err(|err| {
            AppError::General(format!(
                "Error building issuer from certificate: err={:?}",
                &err
            ))
        })?;

        let crl = crl_params.signed_by(&signer).map_err(|err| {
            AppError::General(format!(
                "Error signing certificate revocation list: err={:?}",
                &err
            ))
        })?;
        crl.pem().map_err(|err| {
            AppError::General(format!(
                "Error serializing certificate revocation list: err={:?}",
                &err
            ))
        })
    }
}

/// A common builder struct used by the other certificate builders
struct CommonCertificateBuilder {
    /// Serial number (to uniquely identify certificate, up to 20 octets)
    serial_number: Option<Vec<u8>>,
    /// Public key algorithm
    key_algorithm: Option<KeyAlgorithm>,
    /// Key pair PEM string (used for existing key pair)
    key_pair_pem: Option<String>,
    /// Certificate PEM string (used for existing certificate)
    certificate_pem: Option<String>,
    /// Validity not-after datetime
    validity_not_after: Option<OffsetDateTime>,
    /// Validity not-before datetime
    validity_not_before: Option<OffsetDateTime>,
    /// Distinguished name: common name
    dn_common_name: Option<String>,
    /// Distinguished name: country
    dn_country: String,
    /// Distinguished name: organization
    dn_organization: String,
}

impl CommonCertificateBuilder {
    /// Sets the serial number
    ///
    /// # Arguments
    ///
    /// * `serial_number` - Serial number (to uniquely identify certificate, up to 20 octets)
    ///
    fn serial_number(&mut self, serial_number: &[u8]) {
        self.serial_number = Some(serial_number.to_vec());
    }

    /// Sets the key algorithm
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - Public key algorithm
    ///
    fn key_algorithm(&mut self, key_algorithm: &KeyAlgorithm) {
        self.key_algorithm = Some(key_algorithm.clone());
    }

    /// Sets the key pair PEM string
    ///
    /// # Arguments
    ///
    /// * `key_pair_pem` - key pair PEM string
    ///
    fn key_pair_pem(&mut self, key_pair_pem: &str) {
        self.key_pair_pem = Some(key_pair_pem.to_string());
    }

    /// Sets the certificate PEM string
    ///
    /// # Arguments
    ///
    /// * `certificate_pem` - certificate PEM string
    ///
    fn certificate_pem(&mut self, certificate_pem: &str) {
        self.certificate_pem = Some(certificate_pem.to_string());
    }

    /// Sets the validity not-after datetime
    ///
    /// # Arguments
    ///
    /// * `not_after` - Validity not-after datetime
    ///
    fn validity_not_after(&mut self, not_after: &OffsetDateTime) {
        self.validity_not_after = Some(*not_after);
    }

    /// Sets the validity not-before datetime
    ///
    /// # Arguments
    ///
    /// * `not_before` - Validity not-before datetime
    ///
    fn validity_not_before(&mut self, not_before: &OffsetDateTime) {
        self.validity_not_before = Some(*not_before);
    }

    /// Sets the distinguished name - common name
    ///
    /// # Arguments
    ///
    /// * `common_name` - Distinguished name - common name
    ///
    fn dn_common_name(&mut self, common_name: &str) {
        self.dn_common_name = Some(common_name.to_string());
    }

    /// Sets the distinguished name - country name
    ///
    /// # Arguments
    ///
    /// * `country_name` - Distinguished name - country name
    ///
    fn dn_country(&mut self, country_name: &str) {
        self.dn_country = country_name.to_string();
    }

    /// Sets the distinguished name - organization name
    ///
    /// # Arguments
    ///
    /// * `organization_name` - Distinguished name - organization name
    ///
    fn dn_organization(&mut self, organization_name: &str) {
        self.dn_organization = organization_name.to_string();
    }

    /// Invoke the build for the supplied data.
    /// Either it will build from existing PKI resources or for a new certificate.
    ///
    /// # Arguments
    ///
    /// * `errors` - A mutable vector, which can be used add any validation error strings
    ///
    /// # Returns
    ///
    /// If valid, a tuple of the [`KeyAlgorithm`], [`CertificateSource`] and optional
    /// [`rcgen::KeyPair`]
    ///
    fn build(
        &self,
        errors: &mut Vec<String>,
    ) -> Option<(KeyAlgorithm, CertificateSource, Option<rcgen::KeyPair>)> {
        let mut cert_der = None;
        let mut cert_params = None;
        let mut key_pair = None;

        // Validation

        if self.key_algorithm.is_none() {
            errors.push(VALIDATION_MSG_KEY_ALGORITHM_REQUIRED.to_string());
        }

        if self.key_pair_pem.is_some() || self.certificate_pem.is_some() {
            if self.key_pair_pem.is_none() {
                errors.push(VALIDATION_MSG_KEY_PAIR_PEM_REQUIRED.to_string());
            } else {
                match rcgen::KeyPair::from_pem(self.key_pair_pem.as_ref().unwrap()) {
                    Ok(kp) => key_pair = Some(kp),
                    Err(_) => errors.push(VALIDATION_MSG_INVALID_KEY_PAIR_PEM_CONTENTS.to_string()),
                }
            }

            if self.certificate_pem.is_none() {
                errors.push(VALIDATION_MSG_CERTIFICATE_PEM_REQUIRED.to_string());
            } else if key_pair.is_some() {
                let certificate_result = pki_types::CertificateDer::from_pem_slice(
                    self.certificate_pem.as_ref().unwrap().as_bytes(),
                );
                match certificate_result {
                    Ok(cert) => cert_der = Some(cert.as_bytes().to_vec()),
                    Err(_) => {
                        errors.push(VALIDATION_MSG_INVALID_CERTIFICATE_PEM_CONTENTS.to_string())
                    }
                }
            }
        } else {
            if self.serial_number.is_some()
                && (self.serial_number.as_ref().unwrap().len() > SERIAL_NUMBER_MAX_OCTETS)
            {
                errors.push(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED.to_string());
            }
            if self.validity_not_before.is_none() {
                errors.push(VALIDATION_MSG_VALIDITY_NOT_BEFORE_REQUIRED.to_string());
            }
            if self.validity_not_after.is_none() {
                errors.push(VALIDATION_MSG_VALIDITIY_NOT_AFTER_REQUIRED.to_string());
            }
            if self.validity_not_before.is_some()
                && self.validity_not_after.is_some()
                && self
                    .validity_not_before
                    .as_ref()
                    .unwrap()
                    .ge(self.validity_not_after.as_ref().unwrap())
            {
                errors.push(VALIDATION_MSG_VALIDITY_ORDER_CONSTRAINT_ERROR.to_string());
            }
            if self.dn_common_name.is_none() {
                errors.push(VALIDATION_MSG_DN_COMMON_NAME_REQUIRED.to_string());
            }
        }

        if !errors.is_empty() {
            return None;
        }

        // Valid, set up attributes

        if cert_der.is_none() {
            let mut new_cert_params = rcgen::CertificateParams::default();

            if let Some(serial_number) = self.serial_number.as_ref() {
                new_cert_params.serial_number =
                    Some(SerialNumber::from_slice(serial_number.as_slice()));
            }
            new_cert_params.not_before = *self.validity_not_before.as_ref().unwrap();
            new_cert_params.not_after = *self.validity_not_after.as_ref().unwrap();

            let mut dn = rcgen::DistinguishedName::new();
            if let Some(dn_common_name) = self.dn_common_name.as_ref() {
                dn.push(
                    rcgen::DnType::CommonName,
                    rcgen::DnValue::PrintableString(dn_common_name.as_str().try_into().unwrap()),
                );
            }
            dn.push(
                rcgen::DnType::CountryName,
                rcgen::DnValue::PrintableString(self.dn_country.as_str().try_into().unwrap()),
            );
            dn.push(
                rcgen::DnType::OrganizationName,
                rcgen::DnValue::PrintableString(self.dn_organization.as_str().try_into().unwrap()),
            );
            new_cert_params.distinguished_name = dn;

            cert_params = Some(new_cert_params);
        }

        Some((
            self.key_algorithm.as_ref().unwrap().clone(),
            cert_der.map_or_else(
                || CertificateSource::Params(Box::new(cert_params.unwrap())),
                CertificateSource::DER,
            ),
            key_pair,
        ))
    }
}

impl Default for CommonCertificateBuilder {
    fn default() -> Self {
        Self {
            serial_number: None,
            key_algorithm: None,
            key_pair_pem: None,
            certificate_pem: None,
            validity_not_after: None,
            validity_not_before: None,
            dn_common_name: None,
            dn_country: DEFAULT_DISTINGUISHED_NAME_COUNTRY_NAME.to_string(),
            dn_organization: DEFAULT_DISTINGUISHED_NAME_ORGANIZATION_NAME.to_string(),
        }
    }
}

/// A root CA certificate builder
pub struct RootCaCertificateBuilder {
    /// Common certificate builder delegate object
    common_builder: CommonCertificateBuilder,
}

impl RootCaCertificateBuilder {
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
        self.common_builder.serial_number(serial_number);
        self
    }

    /// Sets the key algorithm
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - Public key algorithm
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn key_algorithm(&mut self, key_algorithm: &KeyAlgorithm) -> &mut Self {
        self.common_builder.key_algorithm(key_algorithm);
        self
    }

    /// Sets the key pair PEM string
    ///
    /// # Arguments
    ///
    /// * `key_pair_pem` - key pair PEM string
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn key_pair_pem(&mut self, key_pair_pem: &str) -> &mut Self {
        self.common_builder.key_pair_pem(key_pair_pem);
        self
    }

    /// Sets the certificate PEM string
    ///
    /// # Arguments
    ///
    /// * `certificate_pem` - certificate PEM string
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn certificate_pem(&mut self, certificate_pem: &str) -> &mut Self {
        self.common_builder.certificate_pem(certificate_pem);
        self
    }

    /// Sets the validity not-after datetime
    ///
    /// # Arguments
    ///
    /// * `not_after` - Validity not-after datetime
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn validity_not_after(&mut self, not_after: &OffsetDateTime) -> &mut Self {
        self.common_builder.validity_not_after(not_after);
        self
    }

    /// Sets the validity not-before datetime
    ///
    /// # Arguments
    ///
    /// * `not_before` - Validity not-before datetime
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn validity_not_before(&mut self, not_before: &OffsetDateTime) -> &mut Self {
        self.common_builder.validity_not_before(not_before);
        self
    }

    /// Sets the distinguished name - common name
    ///
    /// # Arguments
    ///
    /// * `common_name` - Distinguished name - common name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_common_name(&mut self, common_name: &str) -> &mut Self {
        self.common_builder.dn_common_name(common_name);
        self
    }

    /// Sets the distinguished name - country name
    ///
    /// # Arguments
    ///
    /// * `country_name` - Distinguished name - country name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_country(&mut self, country_name: &str) -> &mut Self {
        self.common_builder.dn_country(country_name);
        self
    }

    /// Sets the distinguished name - organization name
    ///
    /// # Arguments
    ///
    /// * `organization_name` - Distinguished name - organization name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_organization(&mut self, organization_name: &str) -> &mut Self {
        self.common_builder.dn_organization(organization_name);
        self
    }

    /// Invoke the build for the supplied data
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a [`Certificate`] object.
    ///
    pub fn build(&self) -> Result<Certificate, AppError> {
        let mut errors = Vec::new();
        let mut common_build_response = self.common_builder.build(&mut errors);

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error building root CA certificate: errs={}",
                errors.join(", ")
            )));
        }

        let (key_algorithm, mut cert_source, key_pair) = common_build_response.take().unwrap();

        if let CertificateSource::Params(cert_params) = &mut cert_source {
            cert_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            cert_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            cert_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::KeyCertSign);
            cert_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
            let access_context = CertAccessContext {
                entity_type: EntityType::RootCa,
                ..Default::default()
            };
            let access_context_ser = serde_json::to_string(&access_context).map_err(|err| {
                AppError::General(format!(
                    "Error serializing cert access context: val={:?}, err={:?}",
                    &access_context, &err
                ))
            })?;
            cert_params.subject_alt_names.push(rcgen::SanType::URI(
                access_context_ser.as_str().try_into().unwrap(),
            ));
        }

        let key_pair = key_pair.unwrap_or(key_algorithm.create_key_pair()?);

        Ok(Certificate {
            entity_type: EntityType::RootCa,
            _key_algorithm: key_algorithm,
            cert_source,
            key_pair,
        })
    }
}

/// A Trust0 gateway certificate builder
pub struct GatewayCertificateBuilder {
    /// Common certificate builder delegate object
    common_builder: CommonCertificateBuilder,
    /// Subject alternative name DNS value (vector of Strings representing host naming)
    san_dns_names: Vec<String>,
}

impl GatewayCertificateBuilder {
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
        self.common_builder.serial_number(serial_number);
        self
    }

    /// Sets the key algorithm
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - Public key algorithm
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn key_algorithm(&mut self, key_algorithm: &KeyAlgorithm) -> &mut Self {
        self.common_builder.key_algorithm(key_algorithm);
        self
    }

    /// Sets the validity not-after datetime
    ///
    /// # Arguments
    ///
    /// * `not_after` - Validity not-after datetime
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn validity_not_after(&mut self, not_after: &OffsetDateTime) -> &mut Self {
        self.common_builder.validity_not_after(not_after);
        self
    }

    /// Sets the validity not-before datetime
    ///
    /// # Arguments
    ///
    /// * `not_before` - Validity not-before datetime
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn validity_not_before(&mut self, not_before: &OffsetDateTime) -> &mut Self {
        self.common_builder.validity_not_before(not_before);
        self
    }

    /// Sets the distinguished name - common name
    ///
    /// # Arguments
    ///
    /// * `common_name` - Distinguished name - common name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_common_name(&mut self, common_name: &str) -> &mut Self {
        self.common_builder.dn_common_name(common_name);
        self
    }

    /// Sets the distinguished name - country name
    ///
    /// # Arguments
    ///
    /// * `country_name` - Distinguished name - country name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    //
    pub fn dn_country(&mut self, country_name: &str) -> &mut Self {
        self.common_builder.dn_country(country_name);
        self
    }

    /// Sets the distinguished name - organization name
    ///
    /// # Arguments
    ///
    /// * `organization_name` - Distinguished name - organization name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_organization(&mut self, organization_name: &str) -> &mut Self {
        self.common_builder.dn_organization(organization_name);
        self
    }

    /// Sets the subject alternative name DNS value(s) (vector of Strings representing host naming)
    ///
    /// # Arguments
    ///
    /// * `dns_names` - A vector of host name Strings, used to compose SAN DNS entries
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn san_dns_names(&mut self, dns_names: &[String]) -> &mut Self {
        self.san_dns_names = dns_names.to_vec();
        self
    }

    /// Invoke the build for the supplied data
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a [`Certificate`] object.
    ///
    pub fn build(&self) -> Result<Certificate, AppError> {
        let mut errors = Vec::new();
        let mut common_build_response = self.common_builder.build(&mut errors);

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error building gateway certificate: errs={}",
                errors.join(", ")
            )));
        }

        let (key_algorithm, mut cert_source, key_pair) = common_build_response.take().unwrap();

        if let CertificateSource::Params(cert_params) = &mut cert_source {
            cert_params.is_ca = rcgen::IsCa::NoCa;
            cert_params.use_authority_key_identifier_extension = true;
            cert_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            cert_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
            cert_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
            let access_context = CertAccessContext {
                entity_type: EntityType::Gateway,
                ..Default::default()
            };
            let access_context_ser = serde_json::to_string(&access_context).map_err(|err| {
                AppError::General(format!(
                    "Error serializing cert access context: val={:?}, err={:?}",
                    &access_context, &err
                ))
            })?;
            cert_params.subject_alt_names.push(rcgen::SanType::URI(
                access_context_ser.as_str().try_into().unwrap(),
            ));
            for san_dns_name in &self.san_dns_names {
                cert_params.subject_alt_names.push(rcgen::SanType::DnsName(
                    san_dns_name.as_str().try_into().unwrap(),
                ));
            }
        }

        let key_pair = key_pair.map_or_else(
            || {
                key_algorithm.create_key_pair().map_err(|err| {
                    AppError::General(format!(
                        "Error creating key pair from key algorithm: err={:?}",
                        &err
                    ))
                })
            },
            Ok,
        )?;

        Ok(Certificate {
            entity_type: EntityType::Gateway,
            _key_algorithm: key_algorithm.clone(),
            cert_source,
            key_pair,
        })
    }
}

/// A Trust0 client certificate builder
pub struct ClientCertificateBuilder {
    /// Common certificate builder delegate object
    common_builder: CommonCertificateBuilder,
    /// Subject alternative name URI access context JSON `userId` property
    san_uri_user_id: Option<i64>,
    /// Subject alternative name URI access context JSON `platform` property
    san_uri_platform: Option<String>,
}

impl ClientCertificateBuilder {
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
        self.common_builder.serial_number(serial_number);
        self
    }

    /// Sets the key algorithm
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - Public key algorithm
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn key_algorithm(&mut self, key_algorithm: &KeyAlgorithm) -> &mut Self {
        self.common_builder.key_algorithm(key_algorithm);
        self
    }

    /// Sets the validity not-after datetime
    ///
    /// # Arguments
    ///
    /// * `not_after` - Validity not-after datetime
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn validity_not_after(&mut self, not_after: &OffsetDateTime) -> &mut Self {
        self.common_builder.validity_not_after(not_after);
        self
    }

    /// Sets the validity not-before datetime
    ///
    /// # Arguments
    ///
    /// * `not_before` - Validity not-before datetime
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn validity_not_before(&mut self, not_before: &OffsetDateTime) -> &mut Self {
        self.common_builder.validity_not_before(not_before);
        self
    }

    /// Sets the distinguished name - common name
    ///
    /// # Arguments
    ///
    /// * `common_name` - Distinguished name - common name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_common_name(&mut self, common_name: &str) -> &mut Self {
        self.common_builder.dn_common_name(common_name);
        self
    }

    /// Sets the distinguished name - country name
    ///
    /// # Arguments
    ///
    /// * `country_name` - Distinguished name - country name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    //
    pub fn dn_country(&mut self, country_name: &str) -> &mut Self {
        self.common_builder.dn_country(country_name);
        self
    }

    /// Sets the distinguished name - organization name
    ///
    /// # Arguments
    ///
    /// * `organization_name` - Distinguished name - organization name
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn dn_organization(&mut self, organization_name: &str) -> &mut Self {
        self.common_builder.dn_organization(organization_name);
        self
    }

    /// Sets the subject alternative name URI access context JSON `userId` property
    ///
    /// # Arguments
    ///
    /// * `user_id` - SAN URI user/device access `userId` property
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn san_uri_user_id(&mut self, user_id: i64) -> &mut Self {
        self.san_uri_user_id = Some(user_id);
        self
    }

    /// Sets the subject alternative name URI access context JSON `platform` property
    ///
    /// # Arguments
    ///
    /// * `platform` - SAN URI user/device access `platform` property
    ///
    /// # Returns
    ///
    /// [`Self`] for further function invocation.
    ///
    pub fn san_uri_platform(&mut self, platform: &str) -> &mut Self {
        self.san_uri_platform = Some(platform.to_string());
        self
    }

    /// Invoke the build for the supplied data
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a [`Certificate`] object.
    ///
    pub fn build(&self) -> Result<Certificate, AppError> {
        let mut errors = Vec::new();
        let mut common_build_response = self.common_builder.build(&mut errors);

        if self.san_uri_user_id.is_none() {
            errors.push(VALIDATION_MSG_SAN_URI_USER_ID_REQUIRED.to_string());
        }
        if self.san_uri_platform.is_none() {
            errors.push(VALIDATION_MSG_SAN_URI_PLATFORM_REQUIRED.to_string());
        }

        if !errors.is_empty() {
            return Err(AppError::General(format!(
                "Error building client certificate: errs={}",
                errors.join(", ")
            )));
        }

        let (key_algorithm, mut cert_source, key_pair) = common_build_response.take().unwrap();

        if let CertificateSource::Params(cert_params) = &mut cert_source {
            cert_params.is_ca = rcgen::IsCa::NoCa;
            cert_params.use_authority_key_identifier_extension = true;
            cert_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            cert_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);

            let access_context = CertAccessContext {
                entity_type: EntityType::Client,
                platform: self.san_uri_platform.as_ref().unwrap().clone(),
                user_id: self.san_uri_user_id.unwrap(),
            };
            let access_context_ser = serde_json::to_string(&access_context).map_err(|err| {
                AppError::General(format!(
                    "Error serializing cert access context: val={:?}, err={:?}",
                    &access_context, &err
                ))
            })?;
            cert_params.subject_alt_names.push(rcgen::SanType::URI(
                access_context_ser.as_str().try_into().unwrap(),
            ));
        }

        let key_pair = key_pair.map_or_else(
            || {
                key_algorithm.create_key_pair().map_err(|err| {
                    AppError::General(format!(
                        "Error creating key pair from key algorithm: err={:?}",
                        &err
                    ))
                })
            },
            Ok,
        )?;

        Ok(Certificate {
            entity_type: EntityType::Client,
            _key_algorithm: key_algorithm.clone(),
            cert_source,
            key_pair,
        })
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::crl;
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use time::macros::datetime;
    use time::Duration;

    const KEYFILE_ROOTCA_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "ca-generated-rootca-ecdsa256.key.pem",
    ];

    const CERTFILE_ROOTCA_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "ca-generated-rootca-ecdsa256.crt.pem",
    ];

    // utils
    // =====

    fn create_rootca_certificate(key_algorithm: &KeyAlgorithm) -> Certificate {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_add(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();

        Certificate::root_ca_certificate_builder()
            .key_algorithm(key_algorithm)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .dn_country("country1")
            .dn_organization("org1")
            .build()
            .unwrap()
    }

    fn load_rootca_certificate(key_algorithm: &KeyAlgorithm) -> Certificate {
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let rootca_key_pem = fs::read_to_string(rootca_key_filepath_str).unwrap();
        let rootca_certificate_filepath: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_certificate_filepath_str = rootca_certificate_filepath.to_str().unwrap();
        let rootca_certificate_pem = fs::read_to_string(rootca_certificate_filepath_str).unwrap();

        Certificate::root_ca_certificate_builder()
            .key_algorithm(key_algorithm)
            .key_pair_pem(&rootca_key_pem)
            .certificate_pem(&rootca_certificate_pem)
            .dn_common_name("name1")
            .dn_country("country1")
            .dn_organization("org1")
            .build()
            .unwrap()
    }

    fn create_client_certificate(key_algorithm: &KeyAlgorithm) -> Certificate {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_add(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();

        Certificate::client_certificate_builder()
            .key_algorithm(key_algorithm)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .dn_country("country1")
            .dn_organization("org1")
            .san_uri_user_id(100)
            .san_uri_platform("Linux")
            .build()
            .unwrap()
    }

    // tests
    // =====

    #[test]
    fn keyalg_signature_algorithm() {
        assert_eq!(
            KeyAlgorithm::EcdsaP256.signature_algorithm(),
            &rcgen::PKCS_ECDSA_P256_SHA256
        );
        assert_eq!(
            KeyAlgorithm::EcdsaP384.signature_algorithm(),
            &rcgen::PKCS_ECDSA_P384_SHA384
        );
        assert_eq!(
            KeyAlgorithm::Ed25519.signature_algorithm(),
            &rcgen::PKCS_ED25519
        );
    }

    #[test]
    fn keyalg_create_key_pair_when_key_alg_is_ecdsap256() {
        let key_pair_result = KeyAlgorithm::EcdsaP256.create_key_pair();

        if let Err(err) = key_pair_result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(
            key_pair_result.unwrap().algorithm(),
            &rcgen::PKCS_ECDSA_P256_SHA256
        );
    }

    #[test]
    fn keyalg_create_key_pair_when_key_alg_is_ecdsap384() {
        let key_pair_result = KeyAlgorithm::EcdsaP384.create_key_pair();

        if let Err(err) = key_pair_result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(
            key_pair_result.unwrap().algorithm(),
            &rcgen::PKCS_ECDSA_P384_SHA384
        );
    }

    #[test]
    fn keyalg_create_key_pair_when_key_alg_is_ed25519() {
        let key_pair_result = KeyAlgorithm::Ed25519.create_key_pair();

        if let Err(err) = key_pair_result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert_eq!(key_pair_result.unwrap().algorithm(), &rcgen::PKCS_ED25519);
    }

    #[test]
    fn cert_accessors() {
        let access = CertAccessContext {
            entity_type: EntityType::Gateway,
            ..Default::default()
        };
        let access_ser = serde_json::to_string(&access).unwrap();
        let sans = vec![access_ser.clone(), "DNS1".to_string(), "DNS2".to_string()];
        let expected_sans = vec![
            rcgen::SanType::DnsName(access_ser.try_into().unwrap()),
            rcgen::SanType::DnsName("DNS1".try_into().unwrap()),
            rcgen::SanType::DnsName("DNS2".try_into().unwrap()),
        ];
        let cert = Certificate {
            entity_type: EntityType::Client,
            _key_algorithm: KeyAlgorithm::EcdsaP256,
            cert_source: CertificateSource::Params(Box::new(
                rcgen::CertificateParams::new(sans).unwrap(),
            )),
            key_pair: rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        };

        assert_eq!(cert.entity_type(), &EntityType::Client);
        assert_eq!(cert.key_algorithm(), &KeyAlgorithm::EcdsaP256);
        assert_eq!(cert.key_pair().algorithm(), &rcgen::PKCS_ECDSA_P256_SHA256);

        match &cert.cert_source() {
            CertificateSource::DER(_) => panic!("Unexpected certificate souce: val=DER"),
            CertificateSource::Params(cert_params) => {
                assert_eq!(&cert_params.subject_alt_names, &expected_sans)
            }
        }
    }

    #[test]
    fn cert_root_ca_certificate_builder() {
        let builder = Certificate::root_ca_certificate_builder();

        assert!(builder.common_builder.key_algorithm.is_none());
        assert!(builder.common_builder.key_pair_pem.is_none());
        assert!(builder.common_builder.validity_not_after.is_none());
        assert!(builder.common_builder.validity_not_before.is_none());
        assert!(builder.common_builder.dn_common_name.is_none());
        assert_eq!(
            builder.common_builder.dn_country,
            DEFAULT_DISTINGUISHED_NAME_COUNTRY_NAME
        );
        assert_eq!(
            builder.common_builder.dn_organization,
            DEFAULT_DISTINGUISHED_NAME_ORGANIZATION_NAME
        );
    }

    #[test]
    fn cert_gateway_certificate_builder() {
        let builder = Certificate::gateway_certificate_builder();

        assert!(builder.common_builder.key_algorithm.is_none());
        assert!(builder.common_builder.key_pair_pem.is_none());
        assert!(builder.common_builder.validity_not_after.is_none());
        assert!(builder.common_builder.validity_not_before.is_none());
        assert!(builder.common_builder.dn_common_name.is_none());
        assert_eq!(
            builder.common_builder.dn_country,
            DEFAULT_DISTINGUISHED_NAME_COUNTRY_NAME
        );
        assert_eq!(
            builder.common_builder.dn_organization,
            DEFAULT_DISTINGUISHED_NAME_ORGANIZATION_NAME
        );
        assert!(builder.san_dns_names.is_empty());
    }

    #[test]
    fn cert_client_certificate_builder() {
        let builder = Certificate::client_certificate_builder();

        assert!(builder.common_builder.key_algorithm.is_none());
        assert!(builder.common_builder.key_pair_pem.is_none());
        assert!(builder.common_builder.validity_not_after.is_none());
        assert!(builder.common_builder.validity_not_before.is_none());
        assert!(builder.common_builder.dn_common_name.is_none());
        assert_eq!(
            builder.common_builder.dn_country,
            DEFAULT_DISTINGUISHED_NAME_COUNTRY_NAME
        );
        assert_eq!(
            builder.common_builder.dn_organization,
            DEFAULT_DISTINGUISHED_NAME_ORGANIZATION_NAME
        );
        assert!(builder.san_uri_user_id.is_none());
        assert!(builder.san_uri_platform.is_none());
    }

    #[test]
    fn cert_build_issuer_when_not_rootca_cert() {
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP384);

        if client_certificate.build_issuer().is_ok() {
            panic!("Unexpected successful build result");
        }
    }

    #[test]
    fn cert_build_issuer_when_for_rootca_cert() {
        let rootca_certificate = load_rootca_certificate(&KeyAlgorithm::EcdsaP256);

        if let Err(err) = rootca_certificate.build_issuer() {
            panic!("Unexpected build result: err={:?}", &err);
        }
    }

    #[test]
    fn cert_serialize_certificate_when_signing_with_new_rootca() {
        let rootca_certificate = create_rootca_certificate(&KeyAlgorithm::EcdsaP384);
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP384);

        let CertificateSource::Params(cert_params) = &rootca_certificate.cert_source() else {
            panic!("Unexpected root CA DER file, expected certificate parameters");
        };

        let signer = rcgen::Issuer::from_params(cert_params, rootca_certificate.key_pair());

        if let Err(err) = client_certificate.serialize_certificate(Some(&signer)) {
            panic!("Unexpected serialization result: err={:?}", &err);
        }
    }

    #[test]
    fn cert_serialize_certificate_when_signing_with_exiting_rootca() {
        let rootca_certificate = load_rootca_certificate(&KeyAlgorithm::EcdsaP256);
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP256);

        let CertificateSource::DER(cert_der_bytes) = &rootca_certificate.cert_source() else {
            panic!("Unexpected root CA certificate parameters, expected DER bytes");
        };

        let signer = match rcgen::Issuer::from_ca_cert_der(
            &CertificateDer::from_slice(cert_der_bytes.as_slice()),
            rootca_certificate.key_pair(),
        ) {
            Ok(signer) => signer,
            Err(err) => panic!("Error building issuer from certificate: err={:?}", &err),
        };

        if let Err(err) = client_certificate.serialize_certificate(Some(&signer)) {
            panic!("Unexpected serialization result: err={:?}", &err);
        }
    }

    #[test]
    fn cert_serialize_certificate_when_not_signing() {
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP384);

        if let Err(err) = client_certificate.serialize_certificate::<rcgen::KeyPair>(None) {
            panic!("Unexpected serialization result: err={:?}", &err);
        }
    }

    #[test]
    fn cert_serialize_private_key() {
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP384);

        let _ = client_certificate.serialize_private_key();
    }

    #[test]
    fn cert_serialize_certificate_revocation_list() {
        let rootca_certificate = load_rootca_certificate(&KeyAlgorithm::EcdsaP256);
        let crl_params = crl::CertificateRevocationListBuilder::new()
            .crl_number(&[0u8, 1u8])
            .update_datetime(&datetime!(2024-01-01 0:00 UTC))
            .next_update_datetime(&datetime!(2024-02-01 0:00 UTC))
            .key_ident_method(rcgen::KeyIdMethod::Sha256)
            .build_params(vec![crl::RevokedCertificateBuilder::new()
                .serial_number(&[2u8, 3u8])
                .revocation_datetime(&datetime!(2024-01-10 0:00 UTC))
                .reason_code(&rcgen::RevocationReason::KeyCompromise)
                .invalidity_datetime(&datetime!(2024-02-10 0:00 UTC))
                .build()
                .unwrap()])
            .unwrap();

        let result = rootca_certificate.serialize_certificate_revocation_list(crl_params);

        if let Err(err) = result {
            panic!("Unexpected serialization result: err={:?}", &err);
        }
    }

    #[test]
    fn rootcacertbuild_when_new_cert_and_all_validation_errors() {
        let mut builder = Certificate::root_ca_certificate_builder();

        let result = builder
            .serial_number([0u8; SERIAL_NUMBER_MAX_OCTETS + 1].as_ref())
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED));
        assert!(err_str.contains(VALIDATION_MSG_KEY_ALGORITHM_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_VALIDITIY_NOT_AFTER_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_VALIDITY_NOT_BEFORE_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_DN_COMMON_NAME_REQUIRED));
    }

    #[test]
    fn rootcacertbuild_when_new_cert_and_invalid_validity() {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_add(one_week).unwrap();

        let mut builder = Certificate::root_ca_certificate_builder();
        let result = &mut builder
            .key_algorithm(&KeyAlgorithm::Ed25519)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn rootcacertbuild_when_new_cert_and_valid() {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_add(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();

        let mut builder = Certificate::root_ca_certificate_builder();
        let result = builder
            .serial_number(&[0u8, 1u8])
            .key_algorithm(&KeyAlgorithm::Ed25519)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .dn_country("country1")
            .dn_organization("org1")
            .build();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certificate = result.unwrap();
        assert_eq!(certificate._key_algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(certificate.entity_type, EntityType::RootCa);
        assert_eq!(certificate.key_pair.algorithm(), &rcgen::PKCS_ED25519);

        let CertificateSource::Params(cert_params) = &certificate.cert_source() else {
            panic!("Unexpected root CA DER file, expected certificate parameters");
        };

        assert_eq!(
            cert_params.is_ca,
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        );
        assert!(!cert_params.use_authority_key_identifier_extension);
        assert!(cert_params.serial_number.is_some());
        assert_eq!(
            cert_params.serial_number.as_ref().unwrap(),
            &rcgen::SerialNumber::from_slice(&[0u8, 1u8])
        );
        assert_eq!(cert_params.not_after, validity_not_after);
        assert_eq!(cert_params.not_before, validity_not_before);

        let expected_key_usages = HashSet::from([
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ]);
        let key_usages = HashSet::from_iter(cert_params.key_usages.iter().cloned());
        if !key_usages.eq(&expected_key_usages) {
            panic!(
                "Unexpected key usages list: actual={:?}, expected={:?}",
                &key_usages, &expected_key_usages
            );
        }

        let access_context_ser = serde_json::to_string(&CertAccessContext {
            entity_type: EntityType::RootCa,
            ..Default::default()
        })
        .unwrap();
        let expected_san_values = HashSet::from([rcgen::SanType::URI(
            access_context_ser.as_str().try_into().unwrap(),
        )]);
        let san_values = HashSet::from_iter(cert_params.subject_alt_names.iter().cloned());
        if !san_values.eq(&expected_san_values) {
            panic!(
                "Unexpected subject alternative names list: actual={:?}, expected={:?}",
                &san_values, &expected_san_values
            );
        }

        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("name1".try_into().unwrap()),
        );
        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CountryName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CountryName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("country1".try_into().unwrap()),
        );
        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::OrganizationName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::OrganizationName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("org1".try_into().unwrap()),
        );
    }

    #[test]
    fn rootcacertbuild_when_existing_cert_and_invalid_key_pair_pem() {
        let rootca_certificate_filepath: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_certificate_filepath_str = rootca_certificate_filepath.to_str().unwrap();
        let rootca_certificate_pem = fs::read_to_string(rootca_certificate_filepath_str).unwrap();

        let mut builder = Certificate::root_ca_certificate_builder();

        let result = builder
            .key_algorithm(&KeyAlgorithm::EcdsaP256)
            .key_pair_pem("INVALID PEM")
            .certificate_pem(&rootca_certificate_pem)
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_INVALID_KEY_PAIR_PEM_CONTENTS));
    }

    #[test]
    fn rootcacertbuild_when_existing_cert_and_invalid_certificate_pem() {
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let rootca_key_pem = fs::read_to_string(rootca_key_filepath_str).unwrap();

        let mut builder = Certificate::root_ca_certificate_builder();

        let result = builder
            .key_algorithm(&KeyAlgorithm::EcdsaP256)
            .key_pair_pem(&rootca_key_pem)
            .certificate_pem("INVALID PEM")
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_INVALID_CERTIFICATE_PEM_CONTENTS));
    }

    #[test]
    fn rootcacertbuild_when_existing_cert_and_valid() {
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let rootca_key_pem = fs::read_to_string(rootca_key_filepath_str).unwrap();
        let rootca_certificate_filepath: PathBuf = CERTFILE_ROOTCA_PATHPARTS.iter().collect();
        let rootca_certificate_filepath_str = rootca_certificate_filepath.to_str().unwrap();
        let rootca_certificate_pem = fs::read_to_string(rootca_certificate_filepath_str).unwrap();

        let mut builder = Certificate::root_ca_certificate_builder();

        let result = builder
            .key_algorithm(&KeyAlgorithm::EcdsaP256)
            .key_pair_pem(&rootca_key_pem)
            .certificate_pem(&rootca_certificate_pem)
            .build();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certificate = result.unwrap();
        assert_eq!(certificate._key_algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(certificate.entity_type, EntityType::RootCa);
        assert_eq!(
            certificate.key_pair.algorithm(),
            &rcgen::PKCS_ECDSA_P256_SHA256
        );

        if let CertificateSource::Params(_) = &certificate.cert_source() {
            panic!("Unexpected root CA certificate parameters, expected DER");
        };
    }

    #[test]
    fn gwcertbuild_when_new_cert_and_all_validation_errors() {
        let mut builder = Certificate::gateway_certificate_builder();

        let result = builder
            .serial_number([0u8; SERIAL_NUMBER_MAX_OCTETS + 1].as_ref())
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED));
        assert!(err_str.contains(VALIDATION_MSG_KEY_ALGORITHM_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_VALIDITIY_NOT_AFTER_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_VALIDITY_NOT_BEFORE_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_DN_COMMON_NAME_REQUIRED));
    }

    #[test]
    fn gwcertbuild_when_new_cert_and_invalid_validity() {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_add(one_week).unwrap();

        let mut builder = Certificate::gateway_certificate_builder();
        let result = builder
            .key_algorithm(&KeyAlgorithm::Ed25519)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn gwcertbuild_when_new_cert_and_valid() {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_add(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();
        let san_dns_names = vec!["dns1".to_string(), "dns2".to_string()];

        let mut builder = Certificate::gateway_certificate_builder();
        let result = builder
            .serial_number(&[0u8, 1u8])
            .key_algorithm(&KeyAlgorithm::EcdsaP256)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .dn_country("country1")
            .dn_organization("org1")
            .san_dns_names(&san_dns_names)
            .build();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certificate = result.unwrap();
        assert_eq!(certificate._key_algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(certificate.entity_type, EntityType::Gateway);
        assert_eq!(
            certificate.key_pair.algorithm(),
            &rcgen::PKCS_ECDSA_P256_SHA256
        );

        let CertificateSource::Params(cert_params) = &certificate.cert_source() else {
            panic!("Unexpected root CA DER file, expected certificate parameters");
        };

        assert_eq!(cert_params.is_ca, rcgen::IsCa::NoCa);
        assert!(cert_params.use_authority_key_identifier_extension);
        assert!(cert_params.serial_number.is_some());
        assert_eq!(
            cert_params.serial_number.as_ref().unwrap(),
            &rcgen::SerialNumber::from_slice(&[0u8, 1u8])
        );
        assert_eq!(cert_params.not_after, validity_not_after);
        assert_eq!(cert_params.not_before, validity_not_before);

        let expected_key_usages = HashSet::from([rcgen::KeyUsagePurpose::DigitalSignature]);
        let key_usages = HashSet::from_iter(cert_params.key_usages.iter().cloned());
        if !key_usages.eq(&expected_key_usages) {
            panic!(
                "Unexpected key usages list: actual={:?}, expected={:?}",
                &key_usages, &expected_key_usages
            );
        }

        let expected_ext_key_usages = HashSet::from([
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ]);
        let ext_key_usages = HashSet::from_iter(cert_params.extended_key_usages.iter().cloned());
        if !ext_key_usages.eq(&expected_ext_key_usages) {
            panic!(
                "Unexpected extended key usages list: actual={:?}, expected={:?}",
                &ext_key_usages, &expected_ext_key_usages
            );
        }

        let access_context_ser = serde_json::to_string(&CertAccessContext {
            entity_type: EntityType::Gateway,
            ..Default::default()
        })
        .unwrap();
        let mut expected_san_values = HashSet::from([rcgen::SanType::URI(
            access_context_ser.as_str().try_into().unwrap(),
        )]);
        expected_san_values.extend(
            san_dns_names
                .iter()
                .map(|dns_name| rcgen::SanType::DnsName(dns_name.as_str().try_into().unwrap())),
        );
        let san_values = HashSet::from_iter(cert_params.subject_alt_names.iter().cloned());
        if !san_values.eq(&expected_san_values) {
            panic!(
                "Unexpected subject alternative names list: actual={:?}, expected={:?}",
                &san_values, &expected_san_values
            );
        }

        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("name1".try_into().unwrap()),
        );
        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CountryName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CountryName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("country1".try_into().unwrap()),
        );
        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::OrganizationName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::OrganizationName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("org1".try_into().unwrap()),
        );
    }

    #[test]
    fn clicertbuild_when_new_cert_and_all_validation_errors() {
        let mut builder = Certificate::client_certificate_builder();

        let result = builder
            .serial_number([0u8; SERIAL_NUMBER_MAX_OCTETS + 1].as_ref())
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }

        let err_str = format!("{:?}", result.err().unwrap());
        assert!(err_str.contains(VALIDATION_MSG_SERIAL_NUMBER_LIMIT_EXCEEDED));
        assert!(err_str.contains(VALIDATION_MSG_KEY_ALGORITHM_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_VALIDITIY_NOT_AFTER_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_VALIDITY_NOT_BEFORE_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_DN_COMMON_NAME_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_SAN_URI_USER_ID_REQUIRED));
        assert!(err_str.contains(VALIDATION_MSG_SAN_URI_PLATFORM_REQUIRED));
    }

    #[test]
    fn clicertbuild_when_new_cert_and_invalid_validity() {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_add(one_week).unwrap();

        let mut builder = Certificate::client_certificate_builder();
        let result = builder
            .key_algorithm(&KeyAlgorithm::Ed25519)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .san_uri_user_id(100)
            .san_uri_platform("Linux")
            .build();

        if result.is_ok() {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn clicertbuild_when_new_cert_and_valid() {
        let one_week = Duration::new(86_400 * 7, 0);
        let validity_not_after = OffsetDateTime::now_utc().checked_add(one_week).unwrap();
        let validity_not_before = OffsetDateTime::now_utc().checked_sub(one_week).unwrap();

        let mut builder = Certificate::client_certificate_builder();
        let result = builder
            .serial_number(&[0u8, 1u8])
            .key_algorithm(&KeyAlgorithm::EcdsaP384)
            .validity_not_after(&validity_not_after)
            .validity_not_before(&validity_not_before)
            .dn_common_name("name1")
            .dn_country("country1")
            .dn_organization("org1")
            .san_uri_user_id(100)
            .san_uri_platform("Linux")
            .build();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let certificate = result.unwrap();
        assert_eq!(certificate._key_algorithm, KeyAlgorithm::EcdsaP384);
        assert_eq!(certificate.entity_type, EntityType::Client);
        assert_eq!(
            certificate.key_pair.algorithm(),
            &rcgen::PKCS_ECDSA_P384_SHA384
        );

        let CertificateSource::Params(cert_params) = &certificate.cert_source() else {
            panic!("Unexpected root CA DER file, expected certificate parameters");
        };

        assert_eq!(cert_params.is_ca, rcgen::IsCa::NoCa);
        assert!(cert_params.use_authority_key_identifier_extension);
        assert!(cert_params.serial_number.is_some());
        assert_eq!(
            cert_params.serial_number.as_ref().unwrap(),
            &rcgen::SerialNumber::from_slice(&[0u8, 1u8])
        );
        assert_eq!(cert_params.not_after, validity_not_after);
        assert_eq!(cert_params.not_before, validity_not_before);
        assert!(!cert_params.subject_alt_names.is_empty());

        let expected_key_usages = HashSet::from([rcgen::KeyUsagePurpose::DigitalSignature]);
        let key_usages = HashSet::from_iter(cert_params.key_usages.iter().cloned());
        if !key_usages.eq(&expected_key_usages) {
            panic!(
                "Unexpected key usages list: actual={:?}, expected={:?}",
                &key_usages, &expected_key_usages
            );
        }

        let expected_ext_key_usages = HashSet::from([rcgen::ExtendedKeyUsagePurpose::ClientAuth]);
        let ext_key_usages = HashSet::from_iter(cert_params.extended_key_usages.iter().cloned());
        if !ext_key_usages.eq(&expected_ext_key_usages) {
            panic!(
                "Unexpected extended key usages list: actual={:?}, expected={:?}",
                &ext_key_usages, &expected_ext_key_usages
            );
        }

        let access_context_ser = serde_json::to_string(&CertAccessContext {
            entity_type: EntityType::Client,
            user_id: 100,
            platform: "Linux".to_string(),
        })
        .unwrap();
        let expected_san_values = HashSet::from([rcgen::SanType::URI(
            access_context_ser.as_str().try_into().unwrap(),
        )]);
        let san_values = HashSet::from_iter(cert_params.subject_alt_names.iter().cloned());
        if !san_values.eq(&expected_san_values) {
            panic!(
                "Unexpected subject alternative names list: actual={:?}, expected={:?}",
                &san_values, &expected_san_values
            );
        }

        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("name1".try_into().unwrap()),
        );
        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CountryName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CountryName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("country1".try_into().unwrap()),
        );
        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::OrganizationName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::OrganizationName)
                .unwrap(),
            &rcgen::DnValue::PrintableString("org1".try_into().unwrap()),
        );
    }
}
