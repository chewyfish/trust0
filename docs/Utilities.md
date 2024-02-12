![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Utilities](#trust0-utilities)
      * [Trust0 Client Installer](#trust0-client-installer)
      * [Trust0 Password Hasher](#trust0-password-hasher)
      * [Create Root CA PKI Resources](#create-root-ca-pki-resources)
      * [Create Gateway PKI Resources](#create-gateway-pki-resources)
      * [Create Client PKI Resources](#create-client-pki-resources)
      * [Create Certificate Revocation List File](#create-certificate-revocation-list-file)
<!-- TOC -->

## Trust0 Utilities

-----------------

#### Trust0 Client Installer

The common crate has a client installation tool (`trust0-client-installer`), which will appropriately stage the necessary files needed for running the client.

It has a similar invocation as does the [Trust0 Client Invocation](./Invocation.md#trust0-client), as the same configuration is needed to setup the installation files for execution.

Make sure the following is available to this tool:

* Trust0 Client binary file
* The CA root certificate file (used in signing the client certificate)
* The Trust0 Client certificate file
* The Trust0 Client private key file

Then be sure to specify the correct configuration as required for your Trust0 installation.

Here is the usage description:

```
Installs the core Trust0 Client files in a well-known user installation path structure appropriate for the target OS platform.

Usage: trust0-client-installer [OPTIONS] --client-binary-file <CLIENT_BINARY_FILE> --host <HOST> --gateway-host <GATEWAY_HOST> --gateway-port <GATEWAY_PORT> --auth-key-file <AUTH_KEY_FILE> --auth-cert-file <AUTH_CERT_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE>

Options:
  -f, --config-file <CONFIG_FILE>
          Config file (as a shell environment file), using program's environment variable naming (see below).
          Note - Each config file variable entry may be overriden via their respective command-line arguments
          Note - Must be first argument (if provided)
          
          [env: CONFIG_FILE=]

  -b, --client-binary-file <CLIENT_BINARY_FILE>
          Trust0 client binary file
          
          [env: CLIENT_BINARY_FILE=]

  -h, --host <HOST>
          The <HOST> address used by the client's socket binds for UDP/TCP service client connections
          
          [env: HOST=]

  -g, --gateway-host <GATEWAY_HOST>
          Connect to <GATEWAY_HOST>
          
          [env: GATEWAY_HOST=]

  -p, --gateway-port <GATEWAY_PORT>
          Connect to <GATEWAY_PORT>
          
          [env: GATEWAY_PORT=]
          [default: 443]

  -k, --auth-key-file <AUTH_KEY_FILE>
          Read client authentication key from <AUTH_KEY_FILE> This should be an ECDSA, EdDSA or RSA private key encoded as PKCS1, PKCS8 or Sec1 in a PEM file.
          Note - For ECDSA keys, curves 'prime256v1' and 'secp384r1' have been tested (others may be supported as well)
          Note - For EdDSA keys, currently only 'Ed25519' is supported
          
          [env: AUTH_KEY_FILE=]

  -c, --auth-cert-file <AUTH_CERT_FILE>
          Read client authentication certificates from <AUTH_CERT_FILE> (must match up with auth key)
          
          [env: AUTH_CERT_FILE=]

  -r, --ca-root-cert-file <CA_ROOT_CERT_FILE>
          Read root certificates from <CA_ROOT_CERT_FILE>
          
          [env: CA_ROOT_CERT_FILE=]

      --protocol-version <PROTOCOL_VERSION>
          Disable default TLS version list, and use <PROTOCOL_VERSION(s)> instead. Provided value is a comma-separated list of versions
          
          [env: PROTOCOL_VERSION=]

      --cipher-suite <CIPHER_SUITE>
          Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead. Provided value is a comma-separated list of suites
          
          [env: CIPHER_SUITE=]

      --max-frag-size <MAX_FRAG_SIZE>
          Limit outgoing messages to <MAX_FRAG_SIZE> bytes
          
          [env: MAX_FRAG_SIZE=]

      --session-resumption
          Support session resumption
          
          [env: SESSION_RESUMPTION=]

      --no-tickets
          Disable session ticket support
          
          [env: NO_TICKETS=]

      --no-sni
          Disable server name indication support
          
          [env: NO_SNI=]

      --insecure
          Disable certificate verification
          
          [env: INSECURE=]

      --verbose
          Enable verbose logging
          
          [env: VERBOSE=]

      --help
          Print help

  -V, --version
          Print version
```

Here is a simple invocation of this tool:

```
<TRUST0_REPO>/target/debug$ ./trust0-client-installer --client-binary-file ./trust0-client --host localhost --gateway-host localhost --gateway-port 8400 --auth-key-file ./client.key.pem --auth-cert-file ./client.crt.pem --ca-root-cert-file ./rootca.crt.pem
Installed CA root certificate: path="<USER_HOME>/.local/share/Trust0/pki/ca-root.cert.pem"
Installed client binary: path="<USER_HOME>/.local/share/Trust0/bin/trust0-client"
Installed client certificate: path="<USER_HOME>/.local/share/Trust0/pki/trust0-client.cert.pem"
Installed client key: path="<USER_HOME>/.local/share/Trust0/pki/trust0-client.key.pem"
Installed client config: path="<USER_HOME>/.config/Trust0/trust0-client.conf"
Installation complete! Consider adding '"<USER_HOME>/.local/share/Trust0/bin"' to the executable search path.
```

#### Trust0 Password Hasher

The common crate has a user password hashing tool (`trust0-password-hasher`), which will correctly create a hashed password that can be stored in the [User Table](./Architecture.md#user-table). This can be used by an optional secondary gateway authentication procedure (if gateway is configured for a scheme that requires user password credentials).

When invoking the tool, merely provide the correct authentication scheme, subsequently you will be prompted for a username and password, then the hashed password will be displayed.

Here is the usage description:

```
Creates valid user password hashes, usable by (relevant) Trust0 authentication schemes

Usage: trust0-password-hasher --authn-scheme <AUTHN_SCHEME>

Options:
      --authn-scheme <AUTHN_SCHEME>
          Authentication mechanism
          Current schemes: 'scram-sha256': SCRAM SHA256 using credentials stored in user repository
          
          [env: AUTHN_SCHEME=]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Here is a simple invocation of this tool:

```
<TRUST0_REPO>/target/debug$ ./target/debug/trust0-password-hasher --authn-scheme scram-sha256
Trust0 SDP Password Hasher v0.4.0-alpha
Username: user1
Password: 
30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=
```

#### Create Root CA PKI Resources

The common crate has a PKI manager tool (`trust0-pki-manager`), which can be used to create valid Trust0 root CA PKI certificate/key resources.

Additionally, you may use the legacy [Trust0 Admin - Root CA PKI Creator](../resources/README.md#create-root-ca-pki-resources) tool, which uses `openssl` to create the resources (or bring your own Trust0-compliant PKI files).

Here is the usage description:

```
Create root CA certificate and key files usable in a Trust0 environment

Usage: trust0-pki-manager root-ca-pki-creator [OPTIONS] --cert-file <CERT_FILE> --key-file <KEY_FILE> --key-algorithm <KEY_ALGORITHM> --validity-not-after <VALIDITY_NOT_AFTER> --subject-common-name <SUBJECT_COMMON_NAME>

Options:
  -c, --cert-file <CERT_FILE>
          Store root CA certificate to <CERT_FILE>. This certificate will be PEM-encoded
          
          [env: CERT_FILE=]

  -k, --key-file <KEY_FILE>
          Store root CA private key to <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
          Note - For ECDSA keys, NIST curves 'P-256' and 'P-384' are supported
          Note - For EdDSA keys, 'Ed25519' is supported
          
          [env: KEY_FILE=]

  -a, --key-algorithm <KEY_ALGORITHM>
          Private key algorithm
          
          [env: KEY_ALGORITHM=]

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519

  -s, --serial-number <SERIAL_NUMBER>
          Serial number, to uniquely identify certificate, up to 20 (hex character 0-F) octets
          
          [env: SERIAL_NUMBER=]

      --validity-not-after <VALIDITY_NOT_AFTER>
          Certificate validity end time (RFC3339 format, for example '2021-01-02T03:04:05Z')
          
          [env: VALIDITY_NOT_AFTER=]

      --validity-not-before <VALIDITY_NOT_BEFORE>
          Certificate validity start time (RFC3339 format, for example '2021-01-02T03:04:05Z'). Defaults to yesterday
          
          [env: VALIDITY_NOT_BEFORE=]

      --subject-common-name <SUBJECT_COMMON_NAME>
          Certificate subject common-name
          
          [env: SUBJECT_COMMON_NAME=]

      --subject-organization <SUBJECT_ORGANIZATION>
          Certificate subject organization. Defaults to 'NA'
          
          [env: SUBJECT_ORGANIZATION=]

      --subject-country <SUBJECT_COUNTRY>
          Certificate subject country. Defaults to 'NA'
          
          [env: SUBJECT_COUNTRY=]

  -h, --help
          Print help (see a summary with '-h')
```

Here is a simple invocation of this tool:

```
<TRUST0_REPO>/target/debug$ ./trust0-pki-manager root-ca-pki-creator --cert-file rootca.crt.pem --key-file rootca.key.pem --key-algorithm ecdsa-p256 --validity-not-after 2025-01-01T00:00:00Z --subject-common-name rootca123 --subject-organization ExampleCA --subject-country US

```

#### Create Gateway PKI Resources

The common crate has a PKI manager tool (`trust0-pki-manager`), which can be used to create valid Trust0 gateway PKI certificate/key resources.

Additionally, you may use the legacy [Trust0 Admin - Gateway PKI Creator](../resources/README.md#create-gateway-pki-resources) tool, which uses `openssl` to create the resources (or bring your own Trust0-compliant PKI files).

Here is the usage description:

```
Create gateway certificate and key files usable in a Trust0 environment

Usage: trust0-pki-manager gateway-pki-creator [OPTIONS] --cert-file <CERT_FILE> --key-file <KEY_FILE> --rootca-cert-file <ROOTCA_CERT_FILE> --rootca-key-file <ROOTCA_KEY_FILE> --key-algorithm <KEY_ALGORITHM> --validity-not-after <VALIDITY_NOT_AFTER> --subject-common-name <SUBJECT_COMMON_NAME>

Options:
  -c, --cert-file <CERT_FILE>
          Store gateway certificate to <CERT_FILE>. This certificate will be PEM-encoded
          
          [env: CERT_FILE=]

  -k, --key-file <KEY_FILE>
          Store gateway private key to <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key Note - For ECDSA keys, NIST curves 'P-256' and 'P-384' are supported Note - For EdDSA keys, 'Ed25519' is supported
          
          [env: KEY_FILE=]

      --rootca-cert-file <ROOTCA_CERT_FILE>
          Root CA certificate from <KEY_FILE>. This will be a PKCS#8 PEM-encoded certificate
          
          [env: ROOTCA_CERT_FILE=]

      --rootca-key-file <ROOTCA_KEY_FILE>
          Root CA private key from <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
          
          [env: ROOTCA_KEY_FILE=]

  -a, --key-algorithm <KEY_ALGORITHM>
          Private key algorithm
          
          [env: KEY_ALGORITHM=]

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519

  -s, --serial-number <SERIAL_NUMBER>
          Serial number, to uniquely identify certificate, up to 20 (hex character 0-F) octets
          
          [env: SERIAL_NUMBER=]

      --validity-not-after <VALIDITY_NOT_AFTER>
          Certificate validity end time (RFC3339 format, for example '2021-01-02T03:04:05Z')
          
          [env: VALIDITY_NOT_AFTER=]

      --validity-not-before <VALIDITY_NOT_BEFORE>
          Certificate validity start time (RFC3339 format, for example '2021-01-02T03:04:05Z'). Defaults to yesterday
          
          [env: VALIDITY_NOT_BEFORE=]

      --subject-common-name <SUBJECT_COMMON_NAME>
          Certificate subject common-name
          
          [env: SUBJECT_COMMON_NAME=]

      --subject-organization <SUBJECT_ORGANIZATION>
          Certificate subject organization. Defaults to 'NA'
          
          [env: SUBJECT_ORGANIZATION=]

      --subject-country <SUBJECT_COUNTRY>
          Certificate subject country. Defaults to 'NA'
          
          [env: SUBJECT_COUNTRY=]

      --san-dns-names <SAN_DNS_NAMES>
          Certificate subject alternative name DNS value(s). Provided value is a comma-separated list of host names
          
          [env: SAN_DNS_NAMES=]

  -h, --help
          Print help (see a summary with '-h')
```

Here is a simple invocation of this tool (CA certificate and key must be accessible):

```
<TRUST0_REPO>/target/debug$ ./trust0-pki-manager gateway-pki-creator --cert-file gateway.crt.pem --key-file gateway.key.pem --rootca-cert-file rootca.crt.pem --rootca-key-file rootca.key.pem --key-algorithm ecdsa-p256 --serial-number 03e7 --validity-not-after 2025-01-01T00:00:00Z --subject-common-name gateway123 --subject-organization Example0 --subject-country US --san-dns-names trust0-gw1.example.com,trust0-gw2.example.com

```

#### Create Client PKI Resources

The common crate has a PKI manager tool (`trust0-pki-manager`), which can be used to create valid Trust0 client PKI certificate/key resources.

Additionally, you may use the legacy [Trust0 Admin - Client PKI Creator](../resources/README.md#create-client-pki-resources) tool, which uses `openssl` to create the resources (or bring your own Trust0-compliant PKI files).

Here is the usage description:

```
Create client certificate and key files usable in a Trust0 environment

Usage: trust0-pki-manager client-pki-creator [OPTIONS] --cert-file <CERT_FILE> --key-file <KEY_FILE> --rootca-cert-file <ROOTCA_CERT_FILE> --rootca-key-file <ROOTCA_KEY_FILE> --key-algorithm <KEY_ALGORITHM> --validity-not-after <VALIDITY_NOT_AFTER> --subject-common-name <SUBJECT_COMMON_NAME> --auth-user-id <AUTH_USER_ID> --auth-platform <AUTH_PLATFORM>

Options:
  -c, --cert-file <CERT_FILE>
          Store root CA certificate to <CERT_FILE>. This certificate will be PEM-encoded
          
          [env: CERT_FILE=]

  -k, --key-file <KEY_FILE>
          Store root CA private key to <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
          Note - For ECDSA keys, NIST curves 'P-256' and 'P-384' are supported
          Note - For EdDSA keys, 'Ed25519' is supported
          
          [env: KEY_FILE=]

      --rootca-cert-file <ROOTCA_CERT_FILE>
          Root CA certificate from <KEY_FILE>. This will be a PKCS#8 PEM-encoded certificate
          
          [env: ROOTCA_CERT_FILE=]

      --rootca-key-file <ROOTCA_KEY_FILE>
          Root CA private key from <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
          
          [env: ROOTCA_KEY_FILE=]

  -a, --key-algorithm <KEY_ALGORITHM>
          Private key algorithm
          
          [env: KEY_ALGORITHM=]

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519

  -s, --serial-number <SERIAL_NUMBER>
          Serial number, to uniquely identify certificate, up to 20 (hex character 0-F) octets
          
          [env: SERIAL_NUMBER=]

      --validity-not-after <VALIDITY_NOT_AFTER>
          Certificate validity end time (RFC3339 format, for example '2021-01-02T03:04:05Z')
          
          [env: VALIDITY_NOT_AFTER=]

      --validity-not-before <VALIDITY_NOT_BEFORE>
          Certificate validity start time (RFC3339 format, for example '2021-01-02T03:04:05Z'). Defaults to yesterday
          
          [env: VALIDITY_NOT_BEFORE=]

      --subject-common-name <SUBJECT_COMMON_NAME>
          Certificate subject common-name
          
          [env: SUBJECT_COMMON_NAME=]

      --subject-organization <SUBJECT_ORGANIZATION>
          Certificate subject organization. Defaults to 'NA'
          
          [env: SUBJECT_ORGANIZATION=]

      --subject-country <SUBJECT_COUNTRY>
          Certificate subject country. Defaults to 'NA'
          
          [env: SUBJECT_COUNTRY=]

      --auth-user-id <AUTH_USER_ID>
          The Trust0 user account ID value
          
          [env: AUTH_USER_ID=]

      --auth-platform <AUTH_PLATFORM>
          The machine architecture/platform for the device using the client certificate
          
          [env: AUTH_PLATFORM=]

  -h, --help
          Print help (see a summary with '-h')
```

Here is a simple invocation of this tool (CA certificate and key must be accessible):

```
<TRUST0_REPO>/target/debug$ ./trust0-pki-manager client-pki-creator --cert-file client.crt.pem --key-file client.key.pem --rootca-cert-file rootca.crt.pem --rootca-key-file rootca.key.pem --key-algorithm ecdsa-p256 --serial-number 03e8 --validity-not-after 2025-01-01T00:00:00Z --auth-user-id 100 --auth-platform Linux --subject-common-name user123 --subject-organization Example0 --subject-country US

```

#### Create Certificate Revocation List File

The common crate has a PKI manager tool (`trust0-pki-manager`), which can be used to create valid Trust0 certificate revocation list files.

Here is the usage description:

```
Create certificate revocation list file

Usage: trust0-pki-manager cert-revocation-list-creator [OPTIONS] --file <FILE> --rootca-cert-file <ROOTCA_CERT_FILE> --rootca-key-file <ROOTCA_KEY_FILE> --key-algorithm <KEY_ALGORITHM> --crl-number <CRL_NUMBER> --update-datetime <UPDATE_DATETIME> --next-update-datetime <NEXT_UPDATE_DATETIME> --signature-algorithm <SIGNATURE_ALGORITHM> --cert-revocation-datetime <CERT_REVOCATION_DATETIME>

Options:
  -f, --file <FILE>
          Store certificate revocation list to <FILE>
          
          [env: FILE=]

      --rootca-cert-file <ROOTCA_CERT_FILE>
          Root CA certificate from <KEY_FILE>. This will be a PKCS#8 PEM-encoded certificate
          
          [env: ROOTCA_CERT_FILE=]

      --rootca-key-file <ROOTCA_KEY_FILE>
          Root CA private key from <KEY_FILE>. This will be a PKCS#8 PEM-encoded ECDSA or EdDSA key
          
          [env: ROOTCA_KEY_FILE=]

      --key-algorithm <KEY_ALGORITHM>
          Private key algorithm
          
          [env: KEY_ALGORITHM=]

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519

      --crl-number <CRL_NUMBER>
          CRL number, to uniquely identify certificate revocation list, up to 20 (hex character 0-F) octets
          
          [env: CRL_NUMBER=]

      --update-datetime <UPDATE_DATETIME>
          Issue datetime of this CRL (RFC3339 format, for example '2021-01-02T03:04:05Z')
          
          [env: UPDATE_DATETIME=]

      --next-update-datetime <NEXT_UPDATE_DATETIME>
          Datetime by which the next CRL will be issued (RFC3339 format, for example '2021-01-02T03:04:05Z')
          
          [env: NEXT_UPDATE_DATETIME=]

      --signature-algorithm <SIGNATURE_ALGORITHM>
          Algorithm used by the CRL issuer to sign the certificate list
          
          [env: SIGNATURE_ALGORITHM=]

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519

      --cert-revocation-datetime <CERT_REVOCATION_DATETIME>
          Datetime at which the CA processed the revocation (RFC3339 format, for example '2021-01-02T03:04:05Z')
          
          [env: CERT_REVOCATION_DATETIME=]

      --cert-revocation-reason <CERT_REVOCATION_REASON>
          (Optional) Reason for the certificate(s) revocation
          
          [env: CERT_REVOCATION_REASON=]
          [possible values: unspecified, key-compromise, ca-compromise, affiliation-changed, superseded, cessation-of-operation, certificate-hold, remove-from-crl, privilege-withdrawn, aa-compromise]

      --cert-revocation-serial-nums <CERT_REVOCATION_SERIAL_NUMS>
          List of serial numbers for each revoked certificate (each value is a hex (0-F) string up to 20 characters). Defaults to empty list
          
          [env: CERT_REVOCATION_SERIAL_NUMS=]

  -h, --help
          Print help (see a summary with '-h')
```

Here is a simple invocation of this tool (CA certificate and key must be accessible) creating a CRL revoking the certificate with serial number `03a8`:

```
<TRUST0_REPO>/target/debug$ ./trust0-pki-manager cert-revocation-list-creator --file revoked.crl.pem --rootca-cert-file rootca.crt.pem --rootca-key-file rootca.key.pem --key-algorithm ecdsa-p256 --crl-number 0100 --update-datetime 2024-01-01T00:00:00Z --next-update-datetime 2050-01-01T00:00:00Z --signature-algorithm ecdsa-p256 --cert-revocation-datetime 2024-01-01T00:00:00Z --cert-revocation-reason key-compromise --cert-revocation-serial-nums 03e8
```
