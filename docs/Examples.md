![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Examples](#trust0-examples)
    * [Example - Chat TCP service](#example---chat-tcp-service)
    * [Example - Echo UDP service](#example---echo-udp-service)
    * [Example - Revoke Certificate](#example---revoke-certificate)
<!-- TOC -->

## Trust0 Examples

-----------------

The following examples are provided in the `examples` directory:

* [Chat TCP](#example---chat-tcp-service)
* [Echo UDP](#example---echo-udp-service)
* [Revoke Cert](#example---revoke-certificate)

### Example - Chat TCP service

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

### Example - Echo UDP service

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
