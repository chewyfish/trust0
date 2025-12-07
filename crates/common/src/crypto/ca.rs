use crate::error::AppError;
use pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::SerialNumber;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use serde_derive::{Deserialize, Serialize};
use time::OffsetDateTime;

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

/// User/device access context, stored as JSON in client certificate's SAN URI entry
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertAccessContext {
    /// DB User ID for user
    pub user_id: i64,
    /// Machine architecture platform hosting certificate
    pub platform: String,
}

/// Trust0 entity utiliing PKI resources
#[derive(Clone, Debug, PartialEq)]
pub enum EntityType {
    /// Root CA, used to sign gateway/client certs
    RootCa,
    /// Trust0 gateway
    Gateway,
    /// Trust0 client
    Client,
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

/// Represents the core PKI (certificate, key pair) for a given entity type
pub struct Certificate {
    /// Type of Trust0 entity
    entity_type: EntityType,
    /// Public key algorithm
    _key_algorithm: KeyAlgorithm,
    /// [`rcgen::Certificate`] object
    cert_params: rcgen::CertificateParams,
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

    /// Certificate parameters accessor (used to build a [`Certificate`])
    ///
    /// # Returns
    ///
    /// A [`rcgen::CertificateParams`] object.
    ///
    pub fn cert_params(&self) -> &rcgen::CertificateParams {
        &self.cert_params
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

    /// Create a ['rcgen::Certificate'] pertaining to the certificate. Pass in a CA [`rcgen::Certificate`]
    /// and [`rcgen::KeyPair`] to use in signing the generated certificate DER object.
    ///
    /// # Arguments
    ///
    /// * `signer` - An optional tuple containing the (CA certificate) signing
    ///   [`rcgen::Certificate`] and [`rcgen::KeyPair`]. Not supplied for self-signed certificate generation.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the generated [`rcgen::Certificate`] DER object.
    ///
    pub fn generate_certificate(
        &self,
        signer: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
    ) -> Result<rcgen::Certificate, AppError> {
        match signer {
            Some((issuer_cert, issuer_key)) => self
                .cert_params
                .clone()
                .signed_by(&self.key_pair, issuer_cert, issuer_key)
                .map_err(|err| {
                    AppError::General(format!(
                        "Error building signed certificate: type={:?}, err={:?}",
                        &self.entity_type, &err
                    ))
                }),
            None => self
                .cert_params
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
    /// * `signer` - An optional tuple containing the (CA certificate) signing
    ///   [`rcgen::Certificate`] and [`rcgen::KeyPair`]. Not supplied for self-signed certificate generation.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the generated certificate PEM string.
    ///
    pub fn serialize_certificate(
        &self,
        signer: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
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
        let cert = self.generate_certificate(None)?;
        let crl = crl_params.signed_by(&cert, &self.key_pair).map_err(|err| {
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
    /// If valid, a tuple of the [`KeyAlgorithm`], [`rcgen::CertificateParams`] and optional
    /// [`rcgen::KeyPair`]
    ///
    fn build(
        &self,
        errors: &mut Vec<String>,
    ) -> Option<(
        KeyAlgorithm,
        rcgen::CertificateParams,
        Option<rcgen::KeyPair>,
    )> {
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
                let certificate_result = rcgen::CertificateParams::from_ca_cert_pem(
                    self.certificate_pem.as_ref().unwrap().as_str(),
                );
                match certificate_result {
                    Ok(cp) => cert_params = Some(cp),
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

        if cert_params.is_none() {
            let mut new_cert_params = rcgen::CertificateParams::default();

            if self.serial_number.is_some() {
                new_cert_params.serial_number = Some(SerialNumber::from_slice(
                    self.serial_number.as_ref().unwrap().as_slice(),
                ));
            }
            new_cert_params.not_before = *self.validity_not_before.as_ref().unwrap();
            new_cert_params.not_after = *self.validity_not_after.as_ref().unwrap();

            let mut dn = rcgen::DistinguishedName::new();
            dn.push(
                rcgen::DnType::CommonName,
                rcgen::DnValue::PrintableString(
                    rcgen::PrintableString::try_from(self.dn_common_name.as_ref().unwrap().clone())
                        .unwrap(),
                ),
            );
            dn.push(
                rcgen::DnType::CountryName,
                rcgen::DnValue::PrintableString(
                    rcgen::PrintableString::try_from(self.dn_country.clone()).unwrap(),
                ),
            );
            dn.push(
                rcgen::DnType::OrganizationName,
                rcgen::DnValue::PrintableString(
                    rcgen::PrintableString::try_from(self.dn_organization.clone()).unwrap(),
                ),
            );
            new_cert_params.distinguished_name = dn;

            cert_params = Some(new_cert_params);
        }

        Some((
            self.key_algorithm.as_ref().unwrap().clone(),
            cert_params.unwrap(),
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

        let (key_algorithm, mut cert_params, key_pair) = common_build_response.take().unwrap();

        cert_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        cert_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        cert_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        cert_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        let key_pair = key_pair.unwrap_or(key_algorithm.create_key_pair()?);

        Ok(Certificate {
            entity_type: EntityType::RootCa,
            _key_algorithm: key_algorithm,
            cert_params,
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

        let (key_algorithm, mut cert_params, key_pair) = common_build_response.take().unwrap();

        let key_pair = key_pair.map_or_else(
            || {
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
                for san_dns_name in &self.san_dns_names {
                    cert_params.subject_alt_names.push(rcgen::SanType::DnsName(
                        rcgen::Ia5String::try_from(san_dns_name.to_string()).unwrap(),
                    ));
                }
                key_algorithm.create_key_pair()
            },
            Ok,
        )?;

        Ok(Certificate {
            entity_type: EntityType::Gateway,
            _key_algorithm: key_algorithm.clone(),
            cert_params,
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

        let (key_algorithm, mut cert_params, key_pair) = common_build_response.take().unwrap();

        let key_pair = key_pair.map_or_else(
            || {
                cert_params.is_ca = rcgen::IsCa::NoCa;
                cert_params.use_authority_key_identifier_extension = true;
                cert_params
                    .key_usages
                    .push(rcgen::KeyUsagePurpose::DigitalSignature);
                cert_params
                    .extended_key_usages
                    .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);

                let access_context = CertAccessContext {
                    platform: self.san_uri_platform.as_ref().unwrap().clone(),
                    user_id: self.san_uri_user_id.unwrap(),
                };
                cert_params.subject_alt_names.push(rcgen::SanType::URI(
                    rcgen::Ia5String::try_from(serde_json::to_string(&access_context).map_err(
                        |err| {
                            AppError::General(format!(
                                "Error serializing client auth context: val={:?}, err={:?}",
                                &access_context, &err
                            ))
                        },
                    )?)
                    .unwrap(),
                ));

                key_algorithm.create_key_pair()
            },
            Ok,
        )?;

        Ok(Certificate {
            entity_type: EntityType::Client,
            _key_algorithm: key_algorithm.clone(),
            cert_params,
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

    const KEYFILE_ROOTCAT_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "ca-generated-rootca-ecdsa256.key.pem",
    ];

    const CERTFILE_ROOTCAT_PATHPARTS: [&str; 3] = [
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
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCAT_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let rootca_key_pem = fs::read_to_string(rootca_key_filepath_str).unwrap();
        let rootca_certificate_filepath: PathBuf = CERTFILE_ROOTCAT_PATHPARTS.iter().collect();
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
        let sans = vec!["DNS1".to_string(), "DNS2".to_string()];
        let expected_sans = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("DNS1".to_string()).unwrap()),
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("DNS2".to_string()).unwrap()),
        ];
        let cert = Certificate {
            entity_type: EntityType::Client,
            _key_algorithm: KeyAlgorithm::EcdsaP256,
            cert_params: rcgen::CertificateParams::new(sans).unwrap(),
            key_pair: rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        };

        assert_eq!(cert.entity_type(), &EntityType::Client);
        assert_eq!(cert.key_algorithm(), &KeyAlgorithm::EcdsaP256);
        assert_eq!(&cert.cert_params().subject_alt_names, &expected_sans);
        assert_eq!(cert.key_pair().algorithm(), &rcgen::PKCS_ECDSA_P256_SHA256);
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
    fn cert_serialize_certificate_when_signing_with_new_rootca() {
        let rootca_certificate = create_rootca_certificate(&KeyAlgorithm::EcdsaP384);
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP384);

        let rootca_certificate_der = match rootca_certificate.generate_certificate(None) {
            Ok(cert) => cert,
            Err(err) => {
                panic!("Error generating issuer certificate: err={:?}", &err);
            }
        };

        let result = client_certificate.serialize_certificate(Some((
            &rootca_certificate_der,
            &rootca_certificate.key_pair,
        )));

        if let Err(err) = result {
            panic!("Unexpected serialization result: err={:?}", &err);
        }
    }

    #[test]
    fn cert_serialize_certificate_when_signing_with_exiting_rootca() {
        let rootca_certificate = load_rootca_certificate(&KeyAlgorithm::EcdsaP256);
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP256);

        let rootca_certificate_der = match rootca_certificate.generate_certificate(None) {
            Ok(cert) => cert,
            Err(err) => {
                panic!("Error generating issuer certificate: err={:?}", &err);
            }
        };

        let result = client_certificate.serialize_certificate(Some((
            &rootca_certificate_der,
            &rootca_certificate.key_pair,
        )));

        if let Err(err) = result {
            panic!("Unexpected serialization result: err={:?}", &err);
        }
    }

    #[test]
    fn cert_serialize_certificate_when_not_signing() {
        let client_certificate = create_client_certificate(&KeyAlgorithm::EcdsaP384);

        let result = client_certificate.serialize_certificate(None);

        if let Err(err) = result {
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
            .serial_number(&[0u8; SERIAL_NUMBER_MAX_OCTETS + 1].to_vec())
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
            .serial_number(&vec![0u8, 1u8])
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

        let cert_params = &certificate.cert_params;
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
        assert!(cert_params.subject_alt_names.is_empty());

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

        assert!(cert_params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .is_some());
        assert_eq!(
            cert_params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                .unwrap(),
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("name1".to_string()).unwrap()
            )
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("country1".to_string()).unwrap()
            )
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("org1".to_string()).unwrap()
            )
        );
    }

    #[test]
    fn rootcacertbuild_when_existing_cert_and_invalid_key_pair_pem() {
        let rootca_certificate_filepath: PathBuf = CERTFILE_ROOTCAT_PATHPARTS.iter().collect();
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
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCAT_PATHPARTS.iter().collect();
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
        let rootca_key_filepath: PathBuf = KEYFILE_ROOTCAT_PATHPARTS.iter().collect();
        let rootca_key_filepath_str = rootca_key_filepath.to_str().unwrap();
        let rootca_key_pem = fs::read_to_string(rootca_key_filepath_str).unwrap();
        let rootca_certificate_filepath: PathBuf = CERTFILE_ROOTCAT_PATHPARTS.iter().collect();
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

        let cert_params = &certificate.cert_params;
        assert_eq!(
            cert_params.is_ca,
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        );
        assert!(!cert_params.use_authority_key_identifier_extension);
        assert!(cert_params.subject_alt_names.is_empty());

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
    }

    #[test]
    fn gwcertbuild_when_new_cert_and_all_validation_errors() {
        let mut builder = Certificate::gateway_certificate_builder();

        let result = builder
            .serial_number(&[0u8; SERIAL_NUMBER_MAX_OCTETS + 1].to_vec())
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
            .serial_number(&vec![0u8, 1u8])
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

        let cert_params = &certificate.cert_params;
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

        let expected_san_values: HashSet<rcgen::SanType> =
            HashSet::from_iter(san_dns_names.iter().map(|dns_name| {
                rcgen::SanType::DnsName(rcgen::Ia5String::try_from(dns_name.clone()).unwrap())
            }));
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("name1".to_string()).unwrap()
            )
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("country1".to_string()).unwrap()
            )
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("org1".to_string()).unwrap()
            )
        );
    }

    #[test]
    fn clicertbuild_when_new_cert_and_all_validation_errors() {
        let mut builder = Certificate::client_certificate_builder();

        let result = builder
            .serial_number(&[0u8; SERIAL_NUMBER_MAX_OCTETS + 1].to_vec())
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
            .serial_number(&vec![0u8, 1u8])
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

        let cert_params = &certificate.cert_params;
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

        let expected_san_values = HashSet::from([rcgen::SanType::URI(
            rcgen::Ia5String::try_from(
                serde_json::to_string(&CertAccessContext {
                    user_id: 100,
                    platform: "Linux".to_string(),
                })
                .unwrap(),
            )
            .unwrap(),
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("name1".to_string()).unwrap()
            )
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("country1".to_string()).unwrap()
            )
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
            &rcgen::DnValue::PrintableString(
                rcgen::PrintableString::try_from("org1".to_string()).unwrap()
            )
        );
    }
}
