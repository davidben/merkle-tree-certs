# Draft PLANTS Charter

This is a draft charter for a new IETF working group. The working group does not yet exist, so references to the "PLANTS Working Group" are aspirational. Discussion at the [IETF PLANTS mailing list](https://mailman3.ietf.org/mailman3/lists/plants.ietf.org/).

## PKI, Logs, And Tree Signatures (PLANTS)

The goal of the PLANTS Working Group is to trim the increasing costs of operating PKIs with Certificate Transparency (CT; RFC 6962 and RFC 9162), when used in interactive protocols like TLS (RFC 8446).

Today, such applications apply two separate systems: a certification authority (CA) signs individual bindings between public keys and application identifiers (e.g., a DNS name), returning an X.509 certificate. CT logs then log entire certificates, returning signed certificate timestamps. The outputs of these two steps are presented to the relying party.

Overhead from post-quantum signatures and keys will add significant costs in two ways:

* Each log entry contains an entire certificate, with public key and signature. Post-quantum overhead is multiplied across every entry, increasing the costs to log operators and the rest of the transparency ecosystem.

* Relying parties are presented with signatures from the CA and CT logs. Post-quantum overhead is multiplied per signature, increasing the size and latency of the TLS handshake.

Additionally, more entities are requesting certificates, and certificate validity windows are narrowing, both of which increase the overall size of a CT log, with corresponding costs for log operators.

The PLANTS Working Group will define a mechanism that integrates log construction into certificate issuance, and reduces the amount of data in individual log entries and the TLS handshake. Integrating the log into certificate issuance enables techniques where one signature can cover multiple key/identifier bindings, e.g., by signing Merkle Tree hashes.

The Working Group will initially put down roots and define the mechanisms needed to interoperably construct and consume certificates:

1. An extensible and externally monitorable transparency log structure, maintained by a CA, containing the key/identifier bindings that the CA has certified.

2. Certificate constructions to prove to relying parties that a binding is both in the CA's view of the log and externally monitorable.

3. How the certificate constructions may be provisioned (with mechanisms including ACME (RFC 8555)) and used in TLS.

As part of this work, the Working Group may extend PKIX (RFC 5280), e.g., with new extensions or signature algorithms. As appropriate, the PLANTS Working Group will liaise with the LAMPS Working Group to ensure adequate lighting for this work and help it grow. As needed, the Working Group may also define extensions to ACME and TLS to integrate its certificate constructions. In doing so, it is expected to liaise with the TLS and ACME Working Groups for cross-pollination.

Though not the initial focus, the PLANTS Working Group may consider other properties of transparent PKIs to improve upon the status quo, such as auditing, monitoring, or revocation. If feasible concrete improvements are identified, the Working Group may recharter to seed secondary deliverables that build on its initial work.

In evaluating decisions and design tradeoffs, the Working Group will consider security, privacy, transparency, performance, and deployment properties, aiming to comparably meet the needs of today's applications that use CT-based PKIs with TLS. In particular the WG will deliver a design that can ensure that a misbehavior by a single party cannot compromise transparency for relying parties. The Working Group may consider and explain how these mechanisms could be adapted for deployment in a private or limited scope PKI (potentially without transparency) as a secondary use case.

The PLANTS Working Group's scope is to explore mechanisms for CAs and transparency ecosystems to certify key/identifier bindings in a publicly monitorable way. Alternate trust models and changes to how TLS uses the end-entity key are not in scope for the Working Group.

The Working Group will not submit specifications for publication to the IESG before demonstrating two interoperable implementations.
