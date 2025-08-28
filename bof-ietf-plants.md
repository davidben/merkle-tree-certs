# Name: PKI, Logs, And Tree Signatures (PLANTS)
## Description 
This BoF is the result of the DISPATCH
of [draft-davidben-tls-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/).

The goal is to charter a Working Group to address the impact of large post-quantum signatures on PKIs with Certificate Transparency (CT; RFC 6962 and RFC 9162), when used in interactive protocols like TLS (RFC 8446).

Today, such applications apply two separate systems: a certification authority (CA) signs individual bindings between public keys and application identifiers (e.g. a DNS name), returning an X.509 certificate. CT logs then log entire certificates, returning signed certificate timestamps. The outputs of these two steps are presented to the relying party.

Overhead from post-quantum signatures and keys will add significant costs in two ways:

* Each log entry contains an entire certificate, with public key and signature. Post-quantum overhead is multiplied across every entry, increasing the costs to log operators and the rest of the transparency ecosystem.

* Relying parties are presented with signatures from the CA and CT logs. Post-quantum overhead is multiplied per signature, increasing the size and latency of the TLS handshake.

There is an oppurtunity to define a mechanism that integrates log construction into certificate issuance, which allows batching techniques where a single signature covers multiple key/identifier bindings.

## Required Details
- Status: WG forming
- Responsible AD: Deb Cooley (Security Area)
- BOF proponents: David Benjamin <davidben@chromium.org>, Bas Westerbaan <bas@cloudflare.com>, Devon O'Brien <devon.obrien@gmail.com>
- BOF Chairs: Tommy Pauly <tpauly@apple.com>, Russ Housley <housley@vigilsec.com>
- Number of people expected to attend: 100
- Length of session (1 or usually 2 hours): 2 hours
- Conflicts (whole Areas and/or WGs)
   - Chair Conflicts: lamps, TBD
   - Technology Overlap: tls, lamps, acme, cfrg
   - Key Participant Conflict: TBD

## Information for IAB/IESG
To allow evaluation of your proposal, please include the following items:

- Any protocols or practices that already exist in this space:

No standardised protocol or practice exists yet. Over the years there have
been several proposals to address various shortcomings in the WebPKI, including,
but not limited to, STH discipline, revocation transparency, and CTng.
The presently dispatched MTC is the closest to experimentation and deployment.

- Which (if any) modifications to existing protocols or practices are required:

TLS, PKIX certs, ACME, CT.

- Which (if any) entirely new protocols or practices are required:

Probably none.

- Open source projects (if any) implementing this work:

https://github.com/cloudflare/azul
https://github.com/bwesterb/mtc
https://github.com/pohlm01/mtc-verifier

# TODO should we bother listing these preliminary implementations?

## Agenda
    - Introduction, chairs (5 min)
    - Background / context (10 min)
    - Slots (TBD need to be scoped?)
    - Charter / deliverable discussion (30 min)

## Links to the mailing list, draft charter if any (for WG-forming BoF), relevant Internet-Drafts, etc.
   - Mailing List: https://www.ietf.org/mailman/listinfo/plants
   - Draft charter: https://github.com/davidben/merkle-tree-certs/blob/main/charter-ietf-plants.md
   - Relevant Internet-Drafts:
     - https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/

