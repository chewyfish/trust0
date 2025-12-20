![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Invocation](#trust0-invocation)
    * [Trust0 Gateway](#trust0-gateway)
    * [Trust0 Client](#trust0-client)
<!-- TOC -->

## Trust0 Invocation

Below is a breakdown of the invocation details for the client and gateway binaries. These applications may be built and executed for a desired target architecture.

Additionally, Docker files are available (in the `resources/docker` directory) to build and execute the binaries in a Docker container. Refer to [Chat TCP](./Examples.md#example---chat-tcp-service) for an example of how the binaries can be used in a containerized environment.

-----------------

### Trust0 Gateway

The gateway needs to be configured with the:

* listener host and port
* PKI certificates/keys (CA certificate, mTLS auth certificate, and its own certificate/key)
* DB access information (may be left out, but client connections would be prohibited)

Currently there is one type of gateway, which has the responsibility of serving Trust0 clients and proxying corresponding client service connections. In the near future, additional types will be added to divide this responsibility between serving clients (client gateway) and delegating connections to services (service gateway). Likewise client gateways will connect to service gateways to forward client service connnection traffic. This will allow for DMZ (and similar) network deployments.

The following details the gateway invocation (common, full-gateway, client-gateway and service-gateway):

#### Common invocation usage

```
Runs a Trust0 gateway server on <HOST>:<PORT>

Usage: trust0-gateway [OPTIONS] --host <HOST> --port <PORT> --cert-file <CERT_FILE> --key-file <KEY_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE> --gateway-service-host <GATEWAY_SERVICE_HOST> <COMMAND>

Commands:
  full-gateway     Client/service gateway type
  client-gateway   Client gateway type
  service-gateway  Service gateway type
  help             Print this message or the help of the given subcommand(s)

Options:
  -f, --config-file <CONFIG_FILE>
          Config file (as a shell environment file), using program's environment variable naming (see below).
          Note - Each config file variable entry may be overriden via their respective command-line arguments
          Note - Must be first argument (if provided)
          
          [env: CONFIG_FILE=]

  -h, --host <HOST>
          The <HOST> address used by the gateway's listener binds for Trust0 client connections
          
          [env: HOST=]

  -p, --port <PORT>
          The <PORT> used by the gateway's listener binds for Trust0 client connections
          
          [env: PORT=]
          [default: 443]

  -c, --cert-file <CERT_FILE>
          Read server certificates from <CERT_FILE>. This should contain PEM-format certificates in the right order (first certificate should certify <KEY_FILE>, last should be a root CA)
          
          [env: CERT_FILE=]

  -k, --key-file <KEY_FILE>
          Read private key from <KEY_FILE>. This should be an ECDSA, EdDSA or RSA private key encoded as PKCS1, PKCS8 or Sec1 in a PEM file.
          Note - For ECDSA keys, curves 'NIST P-256' and 'NIST P-384' have been tested
          Note - For EdDSA keys, currently only 'Ed25519' is supported
          
          [env: KEY_FILE=]

  -a, --ca-root-cert-file <CA_ROOT_CERT_FILE>
          Trust0 CA root certificate(s) from <CA_ROOT_CERT_FILE>. Certificate (and corresponding key pair) is used in signing Trust0 client authentication certificates
          
          [env: CA_ROOT_CERT_FILE=]

      --crl-file <CRL_FILE>
          Perform client certificate revocation checking using the DER-encoded <CRL_FILE(s)>. Will update list during runtime, if file has changed
          
          [env: CRL_FILE=]

      --cipher-suite <CIPHER_SUITE>
          Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead. Provided value is a comma-separated list of suites
          
          [env: CIPHER_SUITE=]

      --alpn-protocol <ALPN_PROTOCOL>
          Negotiate ALPN using <ALPN_PROTOCOL(s)>. Provided value is a comma-separated list of protocols
          
          [env: ALPN_PROTOCOL=]

      --gateway-service-host <GATEWAY_SERVICE_HOST>
          Hostname/ip of this gateway given to clients, used in service proxy connections (if not supplied, clients will determine that on their own)
          
          [env: GATEWAY_SERVICE_HOST=]

      --gateway-service-ports <GATEWAY_SERVICE_PORTS>
          Service proxy port range. If this is omitted, service connections can be made to the primary gateway port (in addition to the control plane connection). ALPN protocol configuration is used to specify the service ID
          
          [env: GATEWAY_SERVICE_PORTS=]

      --verbose
          Enable verbose logging
          
          [env: VERBOSE=]

      --no-mask-addrs
          Show all gateway and service addresses (in REPL shell responses)
          
          [env: NO_MASK_ADDRESSES=]

      --datasource <DATASOURCE>
          DB datasource type

          Possible values:
          - in-memory-db: In-memory DB, with a simple backing persistence store. Entity store connect string is file path to directory holding JSON record files
          - no-db:        No DB configured, used in testing (internally empty in-memory DB structures are used)
          
          [env: DATASOURCE=]
          [default: in-memory-db]

      --db-connect <DB_CONNECT>
          DB entity store connect specifier string. Specification format is dependent on <DATASOURCE> type.
          For 'in-memory-db' datasource: Directory holding JSON files named 'trust0-db-access.json', 'trust0-db-role.json', 'trust0-db-service.json', 'trust0-db-user.json'
          For 'mysql-db' datasource: Connection URL detailed in diesel documentation - https://docs.rs/diesel/2.1.4/diesel/mysql/struct.MysqlConnection.html
          For 'postgres-db' datasource: Standard Postgres connect string specification - https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
          
          [env: DB_CONNECT=]

      --help
          Print help

  -V, --version
          Print version
```

#### Full-gateway invocation usage

```
Client/service gateway type

Usage: trust0-gateway --host <HOST> --port <PORT> --cert-file <CERT_FILE> --key-file <KEY_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE> --gateway-service-host <GATEWAY_SERVICE_HOST> full-gateway [OPTIONS]

Options:
      --mfa-scheme <MFA_SCHEME>
          Secondary authentication mechanism (in addition to client certificate authentication)
          Current schemes: 'insecure': No authentication, all privileged actions allowed
                           'scram-sha256': SCRAM SHA256 using credentials stored in user repository
          
          [env: MFA_SCHEME=]
          [default: insecure]

      --ca-enabled
          [CA] Enable certificate authority. This will dynamically issue expiring certificates to clients
          
          [env: CA_ENABLED=]

      --ca-root-key-file <CA_ROOT_KEY_FILE>
          Trust0 public key pair corresponding to CA root certificate(s) from <CA_ROOT_CERT_FILE>
          Key pair is used in signing client authentication certificates.
          This is not required, is CA is not enabled (<CA_ENABLED>)
          
          [env: CA_ROOT_KEY_FILE=]

      --ca-key-algorithm <CA_KEY_ALGORITHM>
          [CA] Public key algorithm used by certificate authority for new client certificates. (Requires CA to be enabled)

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519
          
          [env: CA_KEY_ALGORITHM=]
          [default: ed25519]

      --ca-validity-period-days <CA_VALIDITY_PERIOD_DAYS>
          [CA] Client certificate validity period as expressed in number of days (Requires CA to be enabled)
          
          [env: CA_VALIDITY_PERIOD_DAYS=]
          [default: 365]

      --ca-reissuance-threshold-days <CA_REISSUANCE_THRESHOLD_DAYS>
          [CA] Certificate re-issuance time period (before certificate expiry) threshold in days (Requires CA to be enabled)
          
          [env: CA_REISSUANCE_THRESHOLD_DAYS=]
          [default: 20]

      --gateway-service-reply-host <GATEWAY_SERVICE_REPLY_HOST>
          Hostname/ip of this gateway, which is routable by UDP services, used in UDP socket replies. If not supplied, then "127.0.0.1" will be used (if necessary)
          
          [env: GATEWAY_SERVICE_REPLY_HOST=]

      --help
          Print help
```

#### Client-gateway invocation usage (future release)

```
Client gateway type

Usage: trust0-gateway --host <HOST> --port <PORT> --cert-file <CERT_FILE> --key-file <KEY_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE> --gateway-service-host <GATEWAY_SERVICE_HOST> client-gateway [OPTIONS] --service-gateway-host <SERVICE_GATEWAY_HOST> --service-gateway-port <SERVICE_GATEWAY_PORT>

Options:
      --service-gateway-host <SERVICE_GATEWAY_HOST>
          Connect to service gateway <SERVICE_GATEWAY_HOST>
          
          [env: SERVICE_GATEWAY_HOST=]

      --service-gateway-port <SERVICE_GATEWAY_PORT>
          Connect to service gateway <SERVICE_GATEWAY_PORT>
          
          [env: SERVICE_GATEWAY_PORT=]
          [default: 443]

      --mfa-scheme <MFA_SCHEME>
          Secondary authentication mechanism (in addition to client certificate authentication)
          Current schemes: 'insecure': No authentication, all privileged actions allowed
                           'scram-sha256': SCRAM SHA256 using credentials stored in user repository
          
          [env: MFA_SCHEME=]
          [default: insecure]

      --ca-enabled
          [CA] Enable certificate authority. This will dynamically issue expiring certificates to clients
          
          [env: CA_ENABLED=]

      --ca-root-key-file <CA_ROOT_KEY_FILE>
          Trust0 public key pair corresponding to CA root certificate(s) from <CA_ROOT_CERT_FILE>
          Key pair is used in signing client authentication certificates.
          This is not required, is CA is not enabled (<CA_ENABLED>)
          
          [env: CA_ROOT_KEY_FILE=]

      --ca-key-algorithm <CA_KEY_ALGORITHM>
          [CA] Public key algorithm used by certificate authority for new client certificates. (Requires CA to be enabled)

          Possible values:
          - ecdsa-p256: Elliptic curve P-256
          - ecdsa-p384: Elliptic curve P-384
          - ed25519:    Edwards curve DSA Ed25519
          
          [env: CA_KEY_ALGORITHM=]
          [default: ed25519]

      --ca-validity-period-days <CA_VALIDITY_PERIOD_DAYS>
          [CA] Client certificate validity period as expressed in number of days (Requires CA to be enabled)
          
          [env: CA_VALIDITY_PERIOD_DAYS=]
          [default: 365]

      --ca-reissuance-threshold-days <CA_REISSUANCE_THRESHOLD_DAYS>
          [CA] Certificate re-issuance time period (before certificate expiry) threshold in days (Requires CA to be enabled)
          
          [env: CA_REISSUANCE_THRESHOLD_DAYS=]
          [default: 20]

      --help
          Print help
```

#### Service-gateway invocation usage (future release)

```
Service gateway type

Usage: trust0-gateway --host <HOST> --port <PORT> --cert-file <CERT_FILE> --key-file <KEY_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE> --gateway-service-host <GATEWAY_SERVICE_HOST> service-gateway [OPTIONS]

Options:
      --gateway-service-reply-host <GATEWAY_SERVICE_REPLY_HOST>
          Hostname/ip of this gateway, which is routable by UDP services, used in UDP socket replies. If not supplied, then "127.0.0.1" will be used (if necessary) [env: GATEWAY_SERVICE_REPLY_HOST=]

      --help
          Print help
```

Here is an example invocation (taken from the provided [Chat TCP](./Examples.md#example---chat-tcp-service) example):

```
<TRUST0_REPO>/example$ <TRUST0_REPO>/target/debug/trust0-gateway --host localhost --port 8400 --cert-file target/example-gateway.local.crt.pem --key-file target/example-gateway.local.key.pem --ca-root-cert-file target/example-ca.local.crt.pem --gateway-service-host localhost --datasource in-memory-db --access-db-connect example-db-access.json --service-db-connect target/example-db-service.json --user-db-connect example-db-user.json full-gateway
```

### Trust0 Client

The client needs to be configured with the:

* host address used in bound sockets for UDP/TCP service client connections
* gateway host and port
* PKI certificates/keys (CA certificate, its own mTLS auth certificate/key)

Additional configuration is explained in the following usage display:

```
Connects to the Trust0 gateway server at HOSTNAME:PORT (default PORT is 443). An control plane REPL shell allows service proxies to be opened (among other features).

Usage: trust0-client [OPTIONS] --host <HOST> --gateway-host <GATEWAY_HOST> --gateway-port <GATEWAY_PORT> --auth-key-file <AUTH_KEY_FILE> --auth-cert-file <AUTH_CERT_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE>

Options:
  -f, --config-file <CONFIG_FILE>
          Config file (as a shell environment file), using program's environment variable naming (see below).
          Note - Each config file variable entry may be overriden via their respective command-line arguments
          Note - Must be first argument (if provided)
          
          [env: CONFIG_FILE=]

  -h, --host <HOST>
          The <HOST> address used by the client's socket binds for UDP/TCP service client connections
          
          [env: HOST=localhost]

  -g, --gateway-host <GATEWAY_HOST>
          Connect to <GATEWAY_HOST>
          
          [env: GATEWAY_HOST=localhost]

  -p, --gateway-port <GATEWAY_PORT>
          Connect to <GATEWAY_PORT>
          
          [env: GATEWAY_PORT=8400]
          [default: 443]

  -k, --auth-key-file <AUTH_KEY_FILE>
          Read client authentication key from <AUTH_KEY_FILE> This should be an ECDSA, EdDSA or RSA private key encoded as PKCS1, PKCS8 or Sec1 in a PEM file.
          Note - For ECDSA keys, curves 'prime256v1' and 'secp384r1' have been tested (others may be supported as well)
          Note - For EdDSA keys, currently only 'Ed25519' is supported
          
          [env: AUTH_KEY_FILE=/home/tmoir/.local/share/Trust0/pki/trust0-client.key.pem]

  -c, --auth-cert-file <AUTH_CERT_FILE>
          Read client authentication certificates from <AUTH_CERT_FILE> (must match up with auth key)
          
          [env: AUTH_CERT_FILE=/home/tmoir/.local/share/Trust0/pki/trust0-client.cert.pem]

  -r, --ca-root-cert-file <CA_ROOT_CERT_FILE>
          Read root certificates from <CA_ROOT_CERT_FILE>
          
          [env: CA_ROOT_CERT_FILE=/home/tmoir/.local/share/Trust0/pki/ca-root.cert.pem]

      --cipher-suite <CIPHER_SUITE>
          Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead. Provided value is a comma-separated list of suites
          
          [env: CIPHER_SUITE=]

      --max-frag-size <MAX_FRAG_SIZE>
          Limit outgoing messages to <MAX_FRAG_SIZE> bytes
          
          [env: MAX_FRAG_SIZE=]

      --insecure
          Disable certificate verification
          
          [env: INSECURE=false]

  -s, --script-file <SCRIPT_FILE>
          Command lines script file to initially execute
          
          [env: SCRIPT_FILE=]

      --verbose
          Enable verbose logging
          
          [env: VERBOSE=false]

      --help
          Print help

  -V, --version
          Print version
```

Here is an example invocation (taken from the provided [Chat TCP](./Examples.md#example---chat-tcp-service) example):

```
<TRUST0_REPO>/example$ <TRUST0_REPO>/target/debug/trust0-client --host localhost --gateway-host localhost --gateway-port 8400 --auth-key-file target/example-client.local.key.pem --auth-cert-file target/example-client.local.crt.pem --ca-root-cert-file target/example-ca.local.crt.pem
```
