![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Invocation](#trust0-invocation)
    * [Trust0 Gateway](#trust0-gateway)
    * [Trust0 Client](#trust0-client)
<!-- TOC -->

## Trust0 Invocation

-----------------

### Trust0 Gateway

The gateway needs to be configured with the:
* listener port
* PKI certificates/keys (CA certificate, mTLS auth certificate, and its own certificate/key)
* DB access information (may be left out, but client connections would be prohibited)

Additional configuration is explained in the following usage display:

```
Runs a Trust0 gateway server on :PORT.  The default PORT is 443.

Usage: trust0-gateway [OPTIONS] --port <PORT> --cert-file <CERT_FILE> --key-file <KEY_FILE> --auth-cert-file <AUTH_CERT_FILE> --gateway-service-host <GATEWAY_SERVICE_HOST>

Options:
  -f, --config-file <CONFIG_FILE>
          Config file (as a shell environment file), using program's environment variable naming (see below).
          Note - Each config file variable entry may be overriden via their respective command-line arguments
          Note - Must be first argument (if provided)
          
          [env: CONFIG_FILE=]

  -p, --port <PORT>
          Listen on PORT
          
          [env: PORT=]
          [default: 443]

  -c, --cert-file <CERT_FILE>
          Read server certificates from <CERT_FILE>. This should contain PEM-format certificates in the right order (first certificate should certify <KEY_FILE>, last should be a root CA)
          
          [env: CERT_FILE=]

  -k, --key-file <KEY_FILE>
          Read private key from <KEY_FILE>. This should be an ECDSA, EdDSA or RSA private key encoded as PKCS1, PKCS8 or Sec1 in a PEM file.
          Note - For ECDSA keys, curves 'prime256v1' and 'secp384r1' have been tested (others may be supported as well)
          Note - For EdDSA keys, currently only 'Ed25519' is supported
          
          [env: KEY_FILE=]

  -a, --auth-cert-file <AUTH_CERT_FILE>
          Accept client authentication certificates signed by those roots provided in <AUTH_CERT_FILE>
          
          [env: AUTH_CERT_FILE=]

      --crl-file <CRL_FILE>
          Perform client certificate revocation checking using the DER-encoded <CRL_FILE(s)>. Will update list during runtime, if file has changed
          
          [env: CRL_FILE=]

      --protocol-version <PROTOCOL_VERSION>
          Disable default TLS version list, and use <PROTOCOL_VERSION(s)> instead. Provided value is a comma-separated list of versions
          
          [env: PROTOCOL_VERSION=]

      --cipher-suite <CIPHER_SUITE>
          Disable default cipher suite list, and use <CIPHER_SUITE(s)> instead. Provided value is a comma-separated list of suites
          
          [env: CIPHER_SUITE=]

      --alpn-protocol <ALPN_PROTOCOL>
          Negotiate ALPN using <ALPN_PROTOCOL(s)>. Provided value is a comma-separated list of protocols
          
          [env: ALPN_PROTOCOL=]

      --session-resumption
          Support session resumption
          
          [env: SESSION_RESUMPTION=]

      --tickets
          Support tickets
          
          [env: TICKETS=]

      --gateway-service-host <GATEWAY_SERVICE_HOST>
          Hostname/ip of this gateway given to clients, used in service proxy connections (if not supplied, clients will determine that on their own)
          
          [env: GATEWAY_SERVICE_HOST=]

      --gateway-service-ports <GATEWAY_SERVICE_PORTS>
          Service proxy port range. If this is omitted, service connections can be made to the primary gateway port (in addition to the control plane connection). ALPN protocol configuration is used to specify the service ID
          
          [env: GATEWAY_SERVICE_PORTS=]

      --gateway-service-reply-host <GATEWAY_SERVICE_REPLY_HOST>
          Hostname/ip of this gateway, which is routable by UDP services, used in UDP socket replies. If not supplied, then "127.0.0.1" will be used (if necessary)
          
          [env: GATEWAY_SERVICE_REPLY_HOST=]

      --verbose
          Enable verbose logging
          
          [env: VERBOSE=]

      --no-mask-addrs
          Show all gateway and service addresses (in REPL shell responses)
          
          [env: NO_MASK_ADDRESSES=]

      --datasource <DATASOURCE>
          DB datasource type
          
          [env: DATASOURCE=]
          [default: in-memory-db]

          Possible values:
          - in-memory-db: In-memory DB, with a simple backing persistence store. Entity store connect strings file paths to JSON record files
          - no-db:        No DB configured, used in testing (internally empty in-memory DB structures are used)

      --access-db-connect <ACCESS_DB_CONNECT>
          (Service) Access entity store connect specifier string
          
          [env: ACCESS_DB_CONNECT=]

      --service-db-connect <SERVICE_DB_CONNECT>
          Service entity store connect specifier string
          
          [env: SERVICE_DB_CONNECT=]

      --user-db-connect <USER_DB_CONNECT>
          User entity store connect specifier string
          
          [env: USER_DB_CONNECT=]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Here is an example invocation (taken from the provided [Chat TCP](./Examples.md#example---chat-tcp-service) example):

```
<TRUST0_REPO>/example$ <TRUST0_REPO>/target/debug/trust0-gateway --port 8400 --cert-file target/example-gateway.local.crt.pem --key-file target/example-gateway.local.key.pem --auth-cert-file target/example-ca.local.crt.pem --gateway-service-host localhost  --datasource in-memory-db --access-db-connect example-db-access.json --service-db-connect target/example-db-service.json --user-db-connect example-db-user.json
```

### Trust0 Client

The client needs to be configured with the:
* gateway host and port
* PKI certificates/keys (CA certificate, its own mTLS auth certificate/key)

Additional configuration is explained in the following usage display:

```
Connects to the Trust0 gateway server at HOSTNAME:PORT (default PORT is 443). An control plane REPL shell allows service proxies to be opened (among other features).

Usage: trust0-client [OPTIONS] --gateway-host <GATEWAY_HOST> --gateway-port <GATEWAY_PORT> --auth-key-file <AUTH_KEY_FILE> --auth-cert-file <AUTH_CERT_FILE> --ca-root-cert-file <CA_ROOT_CERT_FILE>

Options:
  -f, --config-file <CONFIG_FILE>
          Config file (as a shell environment file), using program's environment variable naming (see below).
          Note - Each config file variable entry may be overriden via their respective command-line arguments
          Note - Must be first argument (if provided)
          
          [env: CONFIG_FILE=]

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
          
          [env: SESSION_RESUMPTION=false]

      --no-tickets
          Disable session ticket support
          
          [env: NO_TICKETS=false]

      --no-sni
          Disable server name indication support
          
          [env: NO_SNI=false]

      --insecure
          Disable certificate verification
          
          [env: INSECURE=false]

      --verbose
          Enable verbose logging
          
          [env: VERBOSE=false]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Here is an example invocation (taken from the provided [Chat TCP](./Examples.md#example---chat-tcp-service) example):

```
<TRUST0_REPO>/example$ <TRUST0_REPO>/target/debug/trust0-client --gateway-host localhost --gateway-port 8400 --auth-key-file target/example-client.local.key.pem --auth-cert-file target/example-client.local.crt.pem --ca-root-cert-file target/example-ca.local.crt.pem
```
