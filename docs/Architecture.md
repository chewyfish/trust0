![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Architecture](#trust0-architecture)
    * [Overview](#overview)
    * [Network Diagram](#network-diagram)
    * [Control Plane](#control-plane)
    * [Service Proxy](#service-proxy)
    * [Client Auth](#client-auth)
    * [Database](#database)
      * [User Table](#user-table)
      * [Service Table](#service-table)
      * [Access Table](#access-table)
<!-- TOC -->

## Trust0 Architecture

-----------------

### Overview

In a nutshell, a user will start up the Trust0 Client (T0C) application, which connects to a Trust0 Gateway (T0G) server for the sole purpose of opening up further proxies to authorized services. Then respective service proxy listeners on the user's T0C will be ready to accept new connections.

Likewise, there are 2 types of T0C -> T0G connections:
* Control Plane
* Service Proxy

Both connection types require mTLS, which allows both parties to authenticate each other. The T0C will use a certificate, which has embedded (device/)user information. This is used by the T0G to validate their account and determine their authorized services. The T0G has access to 3 DBs: users, services, and service authorization.

There is no authentication enforced for network connections made to the T0C. Likewise, this client is not secure to run on a multi-user machine and should be only be used on a single-user/personal computer (or some other scenario that can restrict access).

### Network Diagram

![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/network-diagram.png)

### Control Plane

The Control Plane connection is required and the first connection made between the T0C and a T0G. A REPL shell will be opened and the user may enter various commands:

| Command     | Description                                                         |
|-------------|---------------------------------------------------------------------|
| about       | Display context information for connected mTLS device user          |
| connections | List current service proxy connections                              |
| ping        | Simple gateway heartbeat request                                    |
| proxies     | List active service proxies, ready for new connections              |
| services    | List authorized services for connected mTLS device user             |
| start       | Startup proxy to authorized service via secure client-gateway proxy |
| stop        | Shutdown active service proxy (previously started)                  |
| quit        | Quit the control plane (and corresponding service connections)      |
| help        | Print this message or the help of the given subcommand(s)           |

In the REPL shell, issue `help <COMMAND>` to learn more about these commands.

### Service Proxy

Of note, `start` is a key command which is used to open up new service proxies.

```
Trust0 SDP Platform v0.1.0-alpha (enter 'help' for commands)
> start -s chat -p 8501
{
  "code": 200,
  "message": null,
  "request": {
    "Start": {
      "service_name": "chat",
      "local_port": 8501
    }
  },
  "data": {
    "client_port": 8501,
    "gateway_host": "localhost",
    "gateway_port": 8400,
    "service": {
      "host": "localhost",
      "id": 203,
      "name": "chat",
      "port": 8500,
      "transport": "TCP"
    }
  }
}
> 
```

Once started, the specified local port (`8501` in the example above) will listen for new connections for the specified service. Subsequently, when a connection is made from a service client application to this local port, then a Service Proxy mTLS connection (the aforementioned second type of "T0C <--> T0G" connection) is created for the bidirectional copying of data. This connection will create a further proxy connection from T0G <--> Service, to similarly (bidrectionally) copy data.

To recap, 3 total connections make up the virtual connection to a service:

&nbsp;&nbsp;&nbsp;&nbsp;<u>Service Client</u> ` <--TCP|UDP--> ` <u>T0C</u> ` <--mTLS--> ` <u>T0G</u> ` <--TCP|UDP--> ` <u>Service</u>.

### Client Auth

Trust0 connections use TLS client (and server) authentication, which allows the gateway to confirm the legitimacy of the client. It accomplishes this by verifying the client certificate using a CA certificate, which is used for signing client certificates.

Certificates/keys required by Trust0 Client/Gateway execution

| Process | Resource           | Description                                          |
|---------|--------------------|------------------------------------------------------|
| T0G     | CA certificate     | Certificate used to sign client/gateway certificates |
|         | Server certificate | Gateway's X.509 certificate                          |
|         | Server key         | Gateway's private key                                |
| T0C     | CA certificate     | Certificate used to sign client/gateway certificates |
|         | Client certificate | Client's X.509 certificate                           |
|         | Client key         | Client's private key                                 |

Additionally, client (X.509) certificates are created w/a subject alternative name (SAN) field containing a JSON structure as follows:

```
URI = {"userId": <USER_ID>, "platform": <DEVICE_PLATFORM>"}
```

This allows the gateway to identify the user by their "userId" value (currently platform is not used). Subsequently, the gateway can enforce the appropriate authorization for their session. For instance it will check the respective [User Table](#user-table) record for the current status (values: `Active`, `Inactive`). Additionally if they are making a service proxy connection, it will validate the service and if the user has appropriate access by looking up the appropriate records in the [Service Table](#service-table) and [Access Table](#access-table).

All connections use the same gateway port. The gateway knows the kind of connection based on the TLS application-layer protocol negotiation (ALPN) value given by the Trust0 client. The types of values are as follows:

| Pattern       | Description                                                              |
|---------------|--------------------------------------------------------------------------|
| T0CP          | Control Plane                                                            |
| T0SRV<SVC_ID> | Service Proxy (for service denoted by service ID (u64 value) `<SVC_ID>`) |

Note - A future Trust0 may accommodate gateway-to-gateway service proxy routing. In this case, gateway's will also use TLS client authentication in the same manner as clients (albeit they will have a different SAN field JSON structure to denote themselves as gateways).

Trust0 supports Certificate Revocation List (CRL). A file containing the CRL list can be supplied to the gateway. Periodically it will be scanned for changes (revoked or un-revoked certificates) and will reload accordingly and will be available for scrutiny on the next client to gateway TLS connection.

For more details on using the CRL feature:

* Refer to [Trust0 Gateway Invocation](./Invocation.md#trust0-gateway) for information on how to configure the gateway
* Refer to [Revoke Certificate Example](./Examples.md#example---revoke-certificate) for an example showing CRL in action

### Database

The database is used to enforce user access to Trust0 and the respective services.

Currently only a simple in-memory DB based on JSON files is available. At runtime, the system will periodically scan for file changes and reload the corresponding DB with latest records from the changed file.

The repository is exposed as an abstract trait, so additional DB implementations may be developed.

#### User Table

User table contains records for each user account.

| Field   | Description                                                |
|---------|------------------------------------------------------------|
| user ID | A unique integer serving as the primary key for the record |
| name    | Personal name for user                                     |
| status  | Account status field. Values are: 'Inactive', 'Active      |

#### Service Table

Service lists all the details for all services the Trust0 framework can access for proxy connections.

| Field      | Description                                                               |
|------------|---------------------------------------------------------------------------|
| service ID | A unique integer serving as the primary key for the record                |
| name       | A unique name value, used by clients to specify service proxy connections |
| transport  | Network transport for service connection. Values are 'TCP', 'UDP'         |
| host       | Service host used by the gateway for connection establishment             |
| port       | Service port used by the gateway for connection establishment             |

#### Access Table

Access is a join table linking users to services. This serves as the authority on service authorization for a user.

| Field      | Description                           |
|------------|---------------------------------------|
| user ID    | User authorized for service           |
| service ID | Service in question for authorization |

