![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 Architecture](#trust0-architecture)
    * [Overview](#overview)
    * [Network Diagram](#network-diagram)
    * [User Connections](#user-connections)
    * [Control Plane](#control-plane)
      * [Management Channel](#management-channel)
      * [Signaling Channel](#signaling-channel)
    * [Service Proxy](#service-proxy)
    * [Client Auth](#client-auth)
      * [mTLS Authentication](#mtls-authentication)
      * [Secondary Authentication](#secondary-authentication)
      * [RBAC Authorization](#rbac-authorization)
      * [Certificate Authority](#certificate-authority)
      * [Certificate Revocation](#certificate-revocation)
    * [Database](#database)
      * [User Table](#user-table)
      * [Role Table](#role-table)
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

Both connection types require mTLS, which allows both parties to authenticate each other (an optional secondary client authentication may also be enabled). The T0C will use a certificate, which has embedded (device/)user information. This is used by the T0G to validate their account and determine their authorized services. The T0G has access to 3 DBs: users, services, and service authorization.

There is no authentication enforced for network connections made to the T0C. Likewise, this client is not secure to run on a multi-user machine and should be only be used on a single-user/personal computer (or some other scenario that can restrict access).

### Network Diagram

![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/network-diagram.png)

### User Connections

All user connections use the same gateway port. The gateway knows the kind of connection based on the TLS application-layer protocol negotiation (ALPN) value given by the Trust0 client. The types of values are as follows:

| Pattern       | Description                                                              |
|---------------|--------------------------------------------------------------------------|
| T0CP          | Control Plane                                                            |
| T0SRV<SVC_ID> | Service Proxy (for service denoted by service ID (u64 value) `<SVC_ID>`) |

Note - A future Trust0 may accommodate gateway-to-gateway service proxy routing. In this case, gateway's will also use TLS client authentication in the same manner as clients (albeit they will have a different SAN field JSON structure to denote themselves as gateways).

### Control Plane

The Control Plane connection is required and the first connection made between the T0C and a T0G.

There are 2 Control Plane channels:

* `Management` - User command shell to manage service proxy connections (among other commands)
* `Signaling` - An out-of-band channel, the client and gateway use for communication (events, liveliness probing, data, .. )

#### Management Channel

A REPL shell will be opened and the user may enter various commands:

| Command     | Description                                                               |
|-------------|---------------------------------------------------------------------------|
| about       | Display context information for connected mTLS device user                |
| connections | List current service proxy connections                                    |
| login       | Perform challenge-response authentication (if gateway configured for MFA) |
| ping        | Simple gateway heartbeat request                                          |
| proxies     | List active service proxies, ready for new connections                    |
| services    | List authorized services for connected mTLS device user                   |
| start       | Startup proxy to authorized service via secure client-gateway proxy       |
| stop        | Shutdown active service proxy (previously started)                        |
| quit        | Quit the control plane (and corresponding service connections)            |
| help        | Print this message or the help of the given subcommand(s)                 |

In the REPL shell, issue `help <COMMAND>` to learn more about these commands.

#### Signaling Channel

A bidirectional channel will be established between the client and gateway to asynchronously send events to each other.

Here is the current list of signaling events in use:

| Event Type          | Direction        | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|---------------------|------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Proxy Connections   | `T0C` <--> `T0G` | <p>This event is sent bidirectionally every `6 secs`. It contains the current list of service<br>proxy connections' bind address pairs (as known by the gateway (1)) for the<br>respective user session.</p><p>Each side will keep track of missing binds as a consecutive count. When that reaches `5`,<br>those corresponding missing connection(s) will be shut down.</p><p>Additionally, each side will also keep track of consecutive missing `Proxy Connections`<br>signal events. when that reaches `5`, the entire user session(control plane, service<br>proxy connections) will be shut down.</p><p>(1) - Upon TLS connection establishment an initial message, detailing the connection bind<br>addresses, is sent from the gateway to the client. This address pair will be used in<br>coordinating the active state for the respective connection. |
| Certificate Reissue | `T0C` <--- `T0G` | <p>If the client certificate is expiring in the near future, the gateway (if CA is enabled) will<br>send a new certificate and public/private key pair via this event. The client will backup<br>the current PKI resources and save these new files (which will be used on client restart).</p><p>Refer to [Certificate Authority](#certificate-authority) for more information about its design and implementation.</p>                                                                                                                                                                                                                                                                                                                                                                                                                                        |

The Trust0 Gateway can enable a certificate authority (CA) to send clients new certificates, when their existing certificates are expiring.
### Service Proxy

Regarding the [Management Channel](#management-channel) REPL shell, `start` is a key command which is used to open up new service proxies.

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

#### mTLS Authentication

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

This allows the gateway to identify the user by their "userId" value (currently platform is not used).

Subsequently, it will check the respective [User Table](#user-table) record for the current status (values: `active`, `inactive`) and allow or prohibit the user connection accordingly.

#### Secondary Authentication

In addition to TLS client authentication, Trust0 supports additional authentication scheme to be employed. Currently only a SCRAM SHA256 implementation is available. If enabled on the gateway, privileged control plane actions and service proxy connections will be guarded against access if the user hasn't passed this secondary authentication. This is accomplished via a `login` control plane flow.

The SCRAM SHA256 authentication will use the user credentials stored in the user's [User Table](#user-table) record. The hashed password value can be obtained using the included  [Trust0 Password Hasher](./Utilities.md#trust0-password-hasher) utility.

#### RBAC Authorization

The gateway can enforce the appropriate authorization for their session for all service proxy connection requests. It will validate the service and whether the user has appropriate access for the service. It does this by looking up the appropriate records in the [Service Table](#service-table) and [Access Table](#access-table). The access table can contain entries for service accessibility either directly by user ID or indirectly by role ID. User records can be associated to roles (refer to [User Table](#user-table) for how that is specified).

#### Certificate Authority

The gateway can be enabled as a certificate authority (CA) to be able to reissue new client certificate and public/private key pairs, when necessary. Currently, an upcoming certificate expiry is the only triggering event for this re-issuance event. Furthermore, the client must be fully authenticated. That is, using a valid client certificate and must have successfully passed secondary authentication (if enabled). Refer to the other sections in [Client Auth](#client-auth).

The CA will use a `Certificate Reissue` [Signaling Channel](#signaling-channel) event to send the PKI resources. The client will automatically store these PEM files in the same location as is used by the [Trust0 Client Install](./Utilities.md#trust0-client-installer). This location is a well-known installation path for the particular client platform. If the certificate and/or key pair PEM files already exist in this location, they will be backed up to a well-known path location (again, platform-dependent).

The following shows the client management shell message displayed upon receiving new PKI resources (Example came from a Linux environment, <USER_HOME> would be the actual home path):

```
Received new client certificate, key pair PEMs from gateway CA
Backed up certificate file: path="<USER_HOME>/.cache/Trust0/pki/trust0-client.cert.pem.1708116423"
Backed up key file: path="<USER_HOME>/.cache/Trust0/pki/trust0-client.key.pem.1708116423"
Created new certificate file: path="<USER_HOME>/.local/share/Trust0/pki/trust0-client.cert.pem"
Created new key pair file: path="<USER_HOME>/.local/share/Trust0/pki/trust0-client.key.pem"
New certificate will be used upon client restart
```

Refer to [Trust0 Gateway](./Invocation.md#trust0-gateway) invocation documentation on enabling the CA in the gateway. Briefly, the following arguments are pertinent for CA enablement:

| Argument                     | Description                                                                                                                                          |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| ca-enabled                   | Must be toggled to enable CA                                                                                                                         |
| auth-key-file                | The root CA private key, needed in signing new certificates                                                                                          |
| ca-key-algorithm             | The public key algorithm used in key pair creation                                                                                                   |
| ca-validity-period-days      | New certificates use a validity period of: `not-before` today and `not-after` today plus the number of days of this argument value                   |
| ca-reissuance-threshold-days | Only reissue certificates where current time is after the current certificate validity `not-after` minus the number of days of this argument's value |

#### Certificate Revocation

Trust0 supports Certificate Revocation List (CRL). A file containing the CRL list can be supplied to the gateway. Periodically it will be scanned for changes (revoked or un-revoked certificates) and will reload accordingly and will be available for scrutiny on the next client to gateway TLS connection.

For more details on using the CRL feature:

* Refer to [Trust0 Gateway Invocation](./Invocation.md#trust0-gateway) for information on how to configure the gateway
* Refer to [Revoke Certificate Example](./Examples.md#example---revoke-certificate) for an example showing CRL in action

### Database

The database is used to enforce user access to Trust0 and the respective services.

The repository is exposed as an abstract trait, so additional DB implementations may be developed.

Currently, there are two supported DB implementations:

| DB Type     | Description                                                                                                                                                                 |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `in-memory` | DB based on JSON record files. At runtime, the system will periodically scan for file<br>changes and reload the corresponding DB with latest records from the changed file. |
| `postgres`  | Repositories using diesel ORM, which connects/executes queries against a Postgres DB.                                                                                       |

The following sections represent a pseudo-layout for the core respository tables. Actual table layout may differ.

#### User Table

User table contains records for each user account.

| Field     | Description                                                     |
|-----------|-----------------------------------------------------------------|
| user ID   | A unique integer serving as the primary key for the record      |
| user name | An user name used in a (optional) secondary authentication flow |
| password  | An password used in a (optional) secondary authentication flow  |
| name      | Personal name for user                                          |
| status    | Account status field. Values are: 'inactive', 'active           |
| roles     | List of RBAC role IDs assigned to this user                     |

#### Role Table

Role table contains RBAC authorization role records

| Field   | Description                                                |
|---------|------------------------------------------------------------|
| role ID | A unique integer serving as the primary key for the record |
| name    | Short title name for role                                  |

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

Access is a join table linking users or roles to services. This serves as the authority on service authorization.

| Field       | Description                                                              |
|-------------|--------------------------------------------------------------------------|
| service ID  | Service in question for authorization                                    |
| entity type | Type of entity granted access to the service. Values are: 'role', 'user' |
| entity ID   | The identifier key for the granted entity (either role ID or user ID)    |

