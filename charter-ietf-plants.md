# Draft PLANTS Charter

This is a draft charter for a new IETF working group. The working group does not yet exist, so references to the "PLANTS Working Group" are aspirational. Discussion at the [IETF PLANTS mailing list](https://mailman3.ietf.org/mailman3/lists/plants.ietf.org/).

## PKI, Logs, And Tree Signatures (PLANTS)

The goal of the PLANTS Working Group is to mitigate the costs of large post-quantum signatures on PKIs with Certificate Transparency (RFC 6962 and RFC 9162), as used in interactive protocols like TLS (RFC 8446).

In such protocols today, X.509 certificates demonstrate to the relying party that some trusted certification authority (CA) has associated a public key with some application identifier (e.g., a DNS name). Certificate Transparency then provides public auditing, with log artifacts that demonstrate to the relying party the certificate is visible to monitors in some public log.

Large post-quantum signatures and keys add significant costs to these protocols:

* Each log entry contains a public key and signature. This added size to every log entry increases log operator costs, as well as costs to others in the transparency ecosystem.
* Certificates and log artifacts carry signatures from the CA and a quorum of logs. The added size increases latency to the TLS handshake.

The PLANTS Working Group will prune these costs by defining a new certificate and transparent log construction, with comparable security, privacy, and transparency properties to the status quo. In doing so, the Working Group may extend X.509 (e.g. new extensions or signature algorithms). As appropriate, the PLANTS Working Group will liaise with the LAMPS Working Group to ensure adequate lighting for this work and help it grow.

Overgrowth in signature overhead additionally impacts the use of the keys in the protocol (e.g. the TLS CertificateVerify message). These components can be cultivated separately from the PKI and are not in scope for this Working Group.

The PLANTS Working Group will additionally define how authenticating parties can provision its certificates with ACME, and how to use its certificates in TLS. As needed, the Working Group may define extensions to ACME and TLS to achieve this. It is expected to liaise with the TLS and ACME Working Groups for cross-pollination.

Though not the primary focus, the PLANTS Working Group may consider other properties of transparent PKIs to improve over the status quo, such as monitoring and revocation, in the course of its work. If concrete, feasible improvements are identified, the Working Group may recharter to seed new, secondary deliverables.
