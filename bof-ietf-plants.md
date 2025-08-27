# Name: PKI, Logs, and Tree Signatures (PLANTS)
## Description 
This BoF is the result of the DISPATCH
of [draft-davidben-tls-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/).

The goal is to charter a Working Group to address the impact of large post-quantum signatures on PKIs with Certificate Transparency (CT; RFC 6962 and RFC 9162), when used in interactive protocols like TLS (RFC 8446).

Today, such applications apply two separate systems: a certification authority (CA) signs individual bindings between public keys and application identifiers (e.g. a DNS name), returning an X.509 certificate. CT logs then log entire certificates, returning signed certificate timestamps. The outputs of these two steps are presented to the relying party.

Overhead from post-quantum signatures and keys will add significant costs in two ways:

* Each log entry contains an entire certificate, with public key and signature. Post-quantum overhead is multiplied across every entry, increasing the costs to log operators and the rest of the transparency ecosystem.

* Relying parties are presented with signatures from the CA and CT logs. Post-quantum overhead is multiplied per signature, increasing the size and latency of the TLS handshake.

There is an oppurtunity to define a mechanism that integrates log construction into certificate issuance.

## Required Details
- Status: WG forming
- Responsible AD: Deb Cooley
# name <email>, name <email> (1-3 people - who are requesting and coordinating discussion for proposal) 
- BOF proponents: Bas Westerbaan <bas@cloudflare.com>
- Number of people expected to attend: 100
- Length of session (1 or usually 2 hours): 2 hours
- Conflicts (whole Areas and/or WGs)
   - Chair Conflicts: TBD
   - Technology Overlap: TLS, LAMPS, CFRG
   - Key Participant Conflict: TBD

## Information for IAB/IESG
To allow evaluation of your proposal, please include the following items:

- Any protocols or practices that already exist in this space:
- Which (if any) modifications to existing protocols or practices are required:
- Which (if any) entirely new protocols or practices are required:
- Open source projects (if any) implementing this work:

## Agenda
   - TBD

## Links to the mailing list, draft charter if any (for WG-forming BoF), relevant Internet-Drafts, etc.
   - Mailing List: https://www.ietf.org/mailman/listinfo/plants
   - Draft charter: https://github.com/davidben/merkle-tree-certs/blob/main/charter-ietf-plants.md
   - Relevant Internet-Drafts:
     - https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/
     - TBD

