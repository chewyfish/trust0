![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Supplemental Utilities](#trust0-supplemental-utilities)
      * [Create Root CA PKI Resources](#create-root-ca-pki-resources)
      * [Create Gateway PKI Resources](#create-gateway-pki-resources)
      * [Create Client PKI Resources](#create-client-pki-resources)
<!-- TOC -->

## Trust0 Supplemental Utilities

-----------------

#### Create Root CA PKI Resources

The `trust0-admin.sh` script can be used to create valid Trust0 root CA PKI certificate/key resources using `openssl`.

Additionally, you may use the [Trust0 PKI Manager - Create Root CA PKI Resources](../../docs/Utilities.md#create-root-ca-pki-resources) to create PKI resources using native Rust libraries.

Or feel free to bring your own resources.

Here is the usage description:

```
Create root CA certificate and key files usable in a Trust0 environment.

Usage: ./trust0-admin.sh rootca-pki-creator --rootca-cert-filepath <ROOTCA_CERT_FILEPATH> --rootca-key-filepath <ROOTCA_KEY_FILEPATH> [--key-algorithm <KEY_ALGORITHM>] [--md-algorithm <MD_ALGORITHM>] [--cert-expiry-days <CERT_EXPIRY_DAYS>] --subj-common-name <SUBJ_COMMON_NAME> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>]

       ./trust0-admin.sh rootca-pki-creator --help

Options:
  --rootca-cert-filepath <ROOTCA_CERT_FILEPATH>
          The filepath spec for the rootca certificate file

  --rootca-key-filepath <ROOTCA_KEY_FILEPATH>
          The filepath spec for the rootca key file

  --key-algorithm <KEY_ALGORITHM>
          Private key algorithm (values: 'rsa:<RSA_SIZE>', 'ec:<EC_PARAMS_FILEPATH>', ed:<ED_SCHEME>)
          RSA_SIZE: valid key bit length for RSA key
          EC_PARAMS_FILEPATH: File path to an openssl EC params file (curves 'prime256v1' and 'secp384r1' tested)
          ED_SCHEME: ED scheme to use. (currently only 'ed25519' supported)
          [default: rsa:4096]

  --md-algorithm <MD_ALGORITHM>
          Valid openssl message digest hash algorithm to use where necessary in PKI resource creation
          [default: 'sha256']

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: 365]

  --subj-common-name <SUBJ_COMMON_NAME>
          The rootca certificate subject common name value

  --subj-country <SUBJ_COUNTRY>
          The rootca certificate subject country value
          [default: NA]

  --subj-state <SUBJ_STATE>
          The rootca certificate subject state value
          [default: NA]

  --subj-city <SUBJ_CITY>
          The rootca certificate subject city value
          [default: NA]

  --subj-company <SUBJ_COMPANY>
          The rootca certificate subject company value
          [default: NA]

  --subj-dept <SUBJ_DEPT>
          The rootca certificate subject department value
          [default: NA]

  --help
          Show this usage description
```

Here is a simple invocation of this tool:

```
<TRUST0_REPO>/resources$ ./trust0-admin.sh rootca-pki-creator --rootca-cert-filepath rootca.crt.pem --rootca-key-filepath rootca.key.pem --subj-common-name rootca123
```

#### Create Gateway PKI Resources

The `trust0-admin.sh` script can be used to create valid Trust0 gateway PKI certificate/key resources using `openssl`.

Additionally, you may use the [Trust0 PKI Manager - Create Gateway PKI Resources](../../docs/Utilities.md#create-gateway-pki-resources) to create PKI resources using native Rust libraries.

Or feel free to bring your own resources.

Here is the usage description:

```
Create gateway certificate and key files usable in a Trust0 environment.

Usage: ./trust0-admin.sh gateway-pki-creator --gateway-cert-filepath <GATEWAY_CERT_FILEPATH> --gateway-key-filepath <GATEWAY_KEY_FILEPATH> [--key-algorithm <KEY_ALGORITHM>] [--md-algorithm <MD_ALGORITHM>] [--cert-expiry-days <CERT_EXPIRY_DAYS>] --ca-cert-filepath <CA_CERT_FILEPATH> --ca-key-filepath <CA_KEY_FILEPATH> --subj-common-name <SUBJ_COMMON_NAME> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>] [--san-dns1 <SAN_DNS1>] [--san-dns2 <SAN_DNS2>]

       ./trust0-admin.sh gateway-pki-creator --help

Options:
  --gateway-cert-filepath <GATEWAY_CERT_FILEPATH>
          The filepath spec for the gateway certificate file

  --gateway-key-filepath <GATEWAY_KEY_FILEPATH>
          The filepath spec for the gateway key file

  --ca-cert-filepath <CA_CERT_FILEPATH>
          The filepath spec for the CA certificate file used to sign the gateway certificate

  --ca-key-filepath <CA_KEY_FILEPATH>
          The filepath spec for the CA key file used to sign the gateway certificate

  --key-algorithm <KEY_ALGORITHM>
          Private key algorithm (values: 'rsa:<RSA_SIZE>', 'ec:<EC_PARAMS_FILEPATH>', ed:<ED_SCHEME>)
          RSA_SIZE: valid key bit length for RSA key
          EC_PARAMS_FILEPATH: File path to an openssl EC params file (curves 'prime256v1' and 'secp384r1' tested)
          ED_SCHEME: ED scheme to use. (currently only 'ed25519' supported)
          [default: rsa:4096]

  --md-algorithm <MD_ALGORITHM>
          Valid openssl message digest hash algorithm to use where necessary in PKI resource creation
          [default: 'sha256']

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: 365]

  --subj-common-name <SUBJ_COMMON_NAME>
          The gateway certificate subject common name value

  --subj-country <SUBJ_COUNTRY>
          The gateway certificate subject country value
          [default: NA]

  --subj-state <SUBJ_STATE>
          The gateway certificate subject state value
          [default: NA]

  --subj-city <SUBJ_CITY>
          The gateway certificate subject city value
          [default: NA]

  --subj-company <SUBJ_COMPANY>
          The gateway certificate subject company value
          [default: NA]

  --subj-dept <SUBJ_DEPT>
          The gateway certificate subject department value
          [default: NA]

  --san-dns1 <SAN_DNS1>
          First DNS SAN (Subject Alternative Name) value
          [default: '127.0.0.1']
  --san-dns2 <SAN_DNS2>
          Second DNS SAN (Subject Alternative Name) value
          [default: '::1']

  --help
          Show this usage description
```

Here is a simple invocation of this tool (CA certificate and key must be accessible):

```
<TRUST0_REPO>/resources$ ./trust0-admin.sh gateway-pki-creator --gateway-cert-filepath gateway.crt.pem --gateway-key-filepath gateway.key.pem --ca-cert-filepath ca.crt.pem --ca-key-filepath ca.key.pem --subj-common-name gateway123 --san-dns1 trust0-gw.example.com --san-dns2 10.0.0.1
```

#### Create Client PKI Resources

The `trust0-admin.sh` script can be used to create valid Trust0 client PKI certificate/key resources using `openssl`.

Additionally, you may use the [Trust0 PKI Manager - Create Client PKI Resources](../../docs/Utilities.md#create-client-pki-resources) to create PKI resources using native Rust libraries.

Or feel free to bring your own resources.

Here is the usage description:

```
Create client certificate and key files usable in a Trust0 environment.

Usage: ./trust0-admin.sh client-pki-creator --client-cert-filepath <CLIENT_CERT_FILEPATH> --client-key-filepath <CLIENT_KEY_FILEPATH> [--key-algorithm <KEY_ALGORITHM>] [--md-algorithm <MD_ALGORITHM>] [--cert-expiry-days <CERT_EXPIRY_DAYS>] --ca-cert-filepath <CA_CERT_FILEPATH> --ca-key-filepath <CA_KEY_FILEPATH> --subj-common-name <SUBJ_COMMON_NAME> --auth-user-id <AUTH_USER_ID> --auth-platform <AUTH_PLATFORM> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>]

       ./trust0-admin.sh client-pki-creator --help

Options:
  --client-cert-filepath <CLIENT_CERT_FILEPATH>
          The filepath spec for the client certificate file

  --client-key-filepath <CLIENT_KEY_FILEPATH>
          The filepath spec for the client key file

  --ca-cert-filepath <CA_CERT_FILEPATH>
          The filepath spec for the CA certificate file used to sign the client certificate

  --ca-key-filepath <CA_KEY_FILEPATH>
          The filepath spec for the CA key file used to sign the client certificate

  --key-algorithm <KEY_ALGORITHM>
          Private key algorithm (values: 'rsa:<RSA_SIZE>', 'ec:<EC_PARAMS_FILEPATH>', ed:<ED_SCHEME>)
          RSA_SIZE: valid key bit length for RSA key
          EC_PARAMS_FILEPATH: File path to an openssl EC params file (curves 'prime256v1' and 'secp384r1' tested)
          ED_SCHEME: ED scheme to use. (currently only 'ed25519' supported)
          [default: 'rsa:4096']

  --md-algorithm <MD_ALGORITHM>
          Valid openssl message digest hash algorithm to use where necessary in PKI resource creation
          [default: 'sha256']

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: '365']

  --auth-user-id <AUTH_USER_ID>
          The Trust0 user account ID value

  --auth-platform <AUTH_PLATFORM>
          The machine architecture/platform for the device using the client certificate

  --subj-common-name <SUBJ_COMMON_NAME>
          The client certificate subject common name value

  --subj-country <SUBJ_COUNTRY>
          The client certificate subject country value
          [default: NA]

  --subj-state <SUBJ_STATE>
          The client certificate subject state value
          [default: NA]

  --subj-city <SUBJ_CITY>
          The client certificate subject city value
          [default: NA]

  --subj-company <SUBJ_COMPANY>
          The client certificate subject company value
          [default: NA]

  --subj-dept <SUBJ_DEPT>
          The client certificate subject department value
          [default: NA]

  --help
          Show this usage description
```

Here is a simple invocation of this tool (CA certificate and key must be accessible):

```
<TRUST0_REPO>/resources$ ./trust0-admin.sh client-pki-creator --client-cert-filepath client.crt.pem --client-key-filepath client.key.pem --ca-cert-filepath ca.crt.pem --ca-key-filepath ca.key.pem --auth-user-id 123 --auth-platform Linux --subj-common-name user123
```
