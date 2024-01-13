![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Utilities](#trust0-utilities)
      * [Trust0 Client Installer](#trust0-client-installer)
      * [Trust0 Password Hasher](#trust0-password-hasher)
      * [Create Root CA PKI Resources](#create-root-ca-pki-resources)
      * [Create Gateway PKI Resources](#create-gateway-pki-resources)
      * [Create Client PKI Resources](#create-client-pki-resources)
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

Usage: trust0-client-installer [OPTIONS] --client-binary-file <CLIENT_BINARY_FILE> --gateway-host <GATEWAY_HOST> --gateway-port <GATEWAY_PORT> --auth-key-file <AUTH_KEY_FILE> --auth-cert-file <AUTH_CERT_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE>

Options:
  -f, --config-file <CONFIG_FILE>
          Config file (as a shell environment file), using program's environment variable naming (see below).
          Note - Each config file variable entry may be overriden via their respective command-line arguments
          Note - Must be first argument (if provided)
          
          [env: CONFIG_FILE=]

  -b, --client-binary-file <CLIENT_BINARY_FILE>
          Trust0 client binary file
          
          [env: CLIENT_BINARY_FILE=]

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

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Here is a simple invocation of this tool:

```
<TRUST0_REPO>/target/debug$ ./trust0-client-installer --client-binary-file ./trust0-client --gateway-host localhost --gateway-port 8400 --auth-key-file ./client.key.pem --auth-cert-file ./client.crt.pem --ca-root-cert-file ./rootca.crt.pem
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

The `trust0-admin.sh` script can be used to create valid Trust0 root CA PKI certificate/key resources. Feel free to bring your own CA PKI resources instead of using this utility.

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

The `trust0-admin.sh` script can be used to create valid Trust0 gateway PKI certificate/key resources. Feel free to bring your own gateway PKI resources instead of using this utility.

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

The `trust0-admin.sh` script can be used to create valid Trust0 client PKI certificate/key resources. Feel free to bring your own CA PKI resources instead of using this utility (make sure the certificate specifies the correct SAN details).

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
