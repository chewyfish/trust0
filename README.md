![](https://raw.githubusercontent.com/chewyfish/project-assets/main/trust0/banner.png)

<!-- TOC -->
  * [Trust0 SDP Service Access Framework](#trust0-sdp-service-access-framework)
    * [Summary](#summary)
    * [To-Do](#to-do)
    * [Change History](#change-history)
    * [Documentation](#documentation)
    * [Contributions](#contributions)
    * [License](#license)
<!-- TOC -->

## Trust0 SDP Service Access Framework

-----------------

### Summary

Trust0 is a [Zero Trust](https://en.wikipedia.org/wiki/Zero_trust_security_model) security framework, whose implementation is fashioned as a [Software Defined Perimeter](https://en.wikipedia.org/wiki/Software-defined_perimeter) service gateway. The gateway ensures that users may only access services, which were authorized for their account.

This is early alpha, use with care.

### To-Do

* Add Windows UDP support. Tested: macOS (Big Sur); Fedora 39, Windows 11 (TCP only)
* Enhance gateway for runtime client certificate reissuance (on expiry or on demand)
* Incorporate device posture trust assessment and rules processor for security enforcement
* Build (more) testing: integration, performance, ...
* Strategize non-name resolution (DNS/hosts file/...) approach to handle client hostname verification for TLS-type service connections
* Consider supporting UDP multicast services
* Consider gateway-to-gateway service proxy routing (reasons of proximity, security, ...)
* Consider gateway load-balancing, via client redirect (reasons of load, rollout deployment, ...)
* Accommodate integration to well-known identity provider (IdP) systems/protocols for user authentication and 2FA purposes

### Change History

Refer to [Trust0 Releases](https://github.com/chewyfish/trust0/releases)

### Documentation

Refer to the following for more information:

* [docs/Architecture.md](./docs/Architecture.md) : Dive into an overview of Trust0's design and implementation
* [docs/Invocation.md](./docs/Invocation.md) : Presents a brief synopsis on how to run the main Trust0 binaries
* [docs/Utilities.md](./docs/Utilities.md) : Details several handy utilities, which facilitate various Trust0 chores
* [docs/Examples.md](./docs/Examples.md) : Showcases the provided examples, that'll let you see Trust0 in action

### Contributions

We welcome and appreciate questions, bug issues, ideas and the like. However code contributions are currently closed until after the first non-alpha release.

### License

Copyright 2023 the Trust0 Authors. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
these files except in compliance with the License. You may obtain a copy of the
License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
