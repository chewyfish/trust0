![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Examples](#trust0-examples)
    * [Pre-requisites](#pre-requisites)
      * [Linux](#linux)
      * [macOS](#macos)
      * [Windows](#windows)
    * [Example - Chat TCP Service](#example---chat-tcp-service)
    * [Example - Echo UDP Service](#example---echo-udp-service)
    * [Example - Reissue Certificate](#example---reissue-certificate)
    * [Example - Revoke Certificate](#example---revoke-certificate)
<!-- TOC -->

## Trust0 Examples

-----------------

The following examples are provided in the `examples` directory:

* [Chat TCP Service](#example---chat-tcp-service)
* [Echo UDP Service](#example---echo-udp-service)
* [Reissue Certificate](#example---reissue-certificate)
* [Revoke Certificate](#example---revoke-certificate)

### Pre-requisites

To run the examples, the following commands are required:

| Facility       | Original tested version                   | Notes                                                                                   |
|----------------|-------------------------------------------|-----------------------------------------------------------------------------------------|
| Rust toolchain | Linux, macOS: `1.74.0`, Windows: `1.75.0` |                                                                                         |
| `bash`         | Linux, macOS, Windows: `5.2.21`           | Code will assert version is 4 or higher                                                 |
| `gmake`        | Linux, macOS, Windows: `4.4.1`            |                                                                                         |
| `openssl`      | Linux: `3.3.1`, macOS, Windows: `3.2.0`   | This is not needed unless you change the example code to use the `OpenSSL` PKI provider |
| `m4`           | Linux, Windows: `1.4.19` macOS: `1.4.6`   |                                                                                         |
| `tmux`         | Linux, macOS, Windows: `3.3a`             |                                                                                         |
| `ncat`         | Linux: `7.93`, macOS, Windows: `7.94`     | This can be found in the `nmap` package                                                 |

If you wish to override the command used by the example script, merely supply the environment variable(s) for the respective commands (refer to `run-configure.sh` for a listing of command variables).  For example:

```
GMAKE_CMD=/opt/bin/make OPENSSL_CMD=openssl2 ./run-chat-tcp-example.sh
```

Also make sure your firewall does not prohibit the examples' connections.

#### Linux

Tested with Linux Fedora 39. Other (main) Linux distributions will be tested (eventually).

#### macOS

Tested with macOS Big Sur.

The testing utilized [MacPorts](https://www.macports.org). The following ports were installed:

* `bash`
* `gmake`
* `nmap`
* `tmux`

#### Windows

Tested with Windows 11. Currently only TCP services have been verified to work.

The testing utilized [MSYS2](https://www.msys2.org/), using the `UCRT64` environment. The following packages were installed:

* `make`
* `m4`
* `openssl`
* `tmux`

Note - The GNU make command is `make` and not `gmake`. Either add `gmake` as a symlink or override the `GMAKE_CMD` variable (as mentioned above).

Additionally, [NMAP](https://nmap.org/download#windows) was installed (not available as a `MSYS2` package as of the time of this writing).

### Example - Chat TCP Service

In the `example` directory, you can run an example, which lets clients access a "chat" (TCP-based) service.

To run this example, execute the `run-chat-tcp-example.sh` script. You will be asked for free ports to be used for the client, gateway and the chat service (script uses these ports to update the chat service DB record and also now knows how to run the gateway).

```
[example] $ ./run-chat-tcp-example.sh
Enter an available port for the trust0 gateway: 8400
Enter an available port for the chat service: 8500
Enter an available port for the chat proxy: 8501
...

(... PKI certificates/keys created, trust0 binaries built ...)
```

You will be presented with a tmux session w/multiple panes, which represent:
* Chat service
* Trust0 Gateway
* Trust0 Client
* Chat client 1
* Chat client 2
* Shutdown example action

Follow the instructions in step order. The following shows a screencast (using asciinema) of a chat session:

[![asciicast](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/asciicast-chat-tcp.png)](https://asciinema.org/a/626132)

### Example - Echo UDP Service

In the `example` directory, you can run an example, which lets clients access an "echo" (UDP-based) service. The service will merely return the same text data, which it was given by a client.

To run this example, execute the `run-echo-udp-example.sh` script. You will be asked for free ports to be used for the client, gateway and the echo service (script uses these ports to update the echo service DB record and also now knows how to run the gateway).

```
[example] $ ./run-echo-udp-example.sh
Enter an available port for the trust0 gateway: 8400
...
Enter an available port for the echo service: 8600
Enter an available port for the echo proxy: 8601

(... PKI certificates/keys created, trust0 binaries built ...)
```

You will be presented with a tmux session w/multiple panes, which represent:
* Trust0 Gateway
* Trust0 Client
* Echo server
* Echo client
* Shutdown example action

Follow the instructions in step order. The following shows a screencast (using asciinema) of a echo session:

[![asciicast](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/asciicast-echo-udp.png)](https://asciinema.org/a/626134)

### Example - Reissue Certificate

In the `example` directory, you can run an example, which shows certificate re-issuance from a CA-enabled Trust0 gateway (refer to [Certificate Authority](./Architecture.md#certificate-authority) for an explanation of this feature). The example is a modified [Chat TCP](#example---chat-tcp-service), which will initially create an expiring client certificate. Upon (secondary auth) login, the gateway will issue a new certificate/key pair to the client. The client will store those in a well-known location. By restarting the client session, the new non-expiring certificate will be used for the Trust0 client session.

To run this example, execute the `run-reissue-cert-example.sh` script. You will be asked for free ports to be used for the client, gateway and the echo service (script uses these ports to update the echo service DB record and also now knows how to run the gateway).

```
[example] $ ./run-echo-udp-example.sh
Enter an available port for the trust0 gateway: 8400
...
Enter an available port for the echo service: 8600
Enter an available port for the echo proxy: 8601

(... PKI certificates/keys created, trust0 binaries built ...)
```

You will be presented with a tmux session w/multiple panes, which represent:
* Chat service
* Trust0 Gateway
* Trust0 Client
* Chat client 1
* Chat client 2
* Shutdown example action

Follow the instructions in step order. The following shows a screencast (using asciinema) of a revoke certificate session:

[![asciicast](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/asciicast-reissue-cert.png)](https://asciinema.org/a/640971)

### Example - Revoke Certificate

In the `example` directory, you can run an example, which shows certificate revocation in action using the CRL feature (refer to [Client Auth](./Architecture.md#client-auth) for an explanation of this feature). The example is a modified [Echo UDP](#example---echo-udp-service), which has a second echo client that will connect after an updated CRL file has been reloaded. This will deny connection access to this second client, whereas the first client connection (and control plane connection) will be still be active (as revocation is only enforced on new connections).

To run this example, execute the `run-revoke-cert-example.sh` script. You will be asked for free ports to be used for the client, gateway and the echo service (script uses these ports to update the echo service DB record and also now knows how to run the gateway).

```
[example] $ ./run-echo-udp-example.sh
Enter an available port for the trust0 gateway: 8400
...
Enter an available port for the echo service: 8600
Enter an available port for the echo proxy: 8601

(... PKI certificates/keys created, trust0 binaries built ...)
```

You will be presented with a tmux session w/multiple panes, which represent:
* Trust0 Gateway
* Trust0 Client
* Echo server
* First Echo client
* Second Echo client (fails connection after revocation list is updated)
* Shutdown example action

Follow the instructions in step order. The following shows a screencast (using asciinema) of a revoke certificate session:

[![asciicast](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/asciicast-revoke-cert.png)](https://asciinema.org/a/628346)
