# Name: PKI, Logs, And Tree Signatures (PLANTS)
## Description 
This BoF is the result of the DISPATCH
of [draft-davidben-tls-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/).

The goal is to charter a Working Group to address the impact of large post-quantum signatures on PKIs with Certificate Transparency (CT; RFC 6962 and RFC 9162), when used in interactive protocols like TLS (RFC 8446).

Today, such applications apply two separate systems: a certification authority (CA) signs individual bindings between public keys and application identifiers (e.g. a DNS name), returning an X.509 certificate. CT logs then log entire certificates, returning signed certificate timestamps. The outputs of these two steps are presented to the relying party.

Overhead from post-quantum signatures and keys will add significant costs in two ways:

* Each log entry contains an entire certificate, with public key and signature. Post-quantum overhead is multiplied across every entry, increasing the costs to log operators and the rest of the transparency ecosystem.

* Relying parties are presented with signatures from the CA and CT logs. Post-quantum overhead is multiplied per signature, increasing the size and latency of the TLS handshake.

There is an opportunity to define a mechanism that integrates log construction into certificate issuance, which allows batching techniques where a single signature covers multiple key/identifier bindings.

## Required Details
- Status: WG forming
- Responsible AD: Deb Cooley (Security Area)
- BOF proponents: David Benjamin <davidben@chromium.org>, Bas Westerbaan <bas@cloudflare.com>, Devon O'Brien <devon.obrien@gmail.com>
- BOF Chairs: Tommy Pauly <tpauly@apple.com>, Russ Housley <housley@vigilsec.com>
- Number of people expected to attend: 150
- Length of session (1 or usually 2 hours): 2 hours
- Conflicts (whole Areas and/or WGs)
   - Chair Conflicts: HTTPBIS, PRIVACYPASS, IABOPEN, MASQUE, INTAREA, HAPPY, LAMPS, STIR, SIDROPS, TLS, PQUIP, and SAAG.
   - Technology Overlap: TLS, LAMPS, ACME, CFRG
   - Key Participant Conflict: TBD

## Information for IAB/IESG

- Any protocols or practices that already exist in this space:

  Applications in this space today combine PKIX certificates (Public-Key
  Infrastructure using X.509; RFC 5280) with CT logs (Certificate Transparency;
  RFC 6962 and RFC 9162). Existing practice for CT has largely followed
  RFC 6962, though the community is deploying a new, more efficient "Static CT
  API" (https://c2sp.org/static-ct-api and
  https://letsencrypt.org/2025/06/11/reflections-on-a-year-of-sunlight). The
  primary deployment of these protocols today is in PKIs (Public Key
  Infrastructure) targetting the Web.

  This BOF is the result of dispatching Merkle Tree Certificates
  (MTC; draft-davidben-tls-merkle-tree-certs), which aims to build and improve
  upon this practice.

- Which (if any) entirely new protocols or practices are required:

  (Question order swapped for clarify.)

  Exact details will depend on the solution developed, but we expect, based on
  the initial MTC proposal, this work to involve defining a new log structure
  (e.g. the Merkle Tree construction in RFC 6962 and RFC 9162), with formats and
  semantics for signatures on the log, and roles (e.g. similar to today's CAs
  and CT logs) that make those signatures.

  To keep the BOF and (aspirationally) eventual WG focused, we expect the
  initial scope to be limited to post-quantum size problem, and the protocols
  and framework necessary to interoperably construct and consume certificates.
  A CT deployment more broadly includes other supporting roles, such as
  monitoring services, witnesses (https://c2sp.org/tlog-witness), and mirrors
  (https://c2sp.org/tlog-mirror). A deployment may choose to incorporate some of
  those roles, but we expect this initial work to be the core framework itself.

- Which (if any) modifications to existing protocols or practices are required:

  We expect the work will define a certificate structure, e.g. using PKIX
  certificates. PKIX is extensible, so this is unlikely to modify PKIX itself.
  Rather, it might define new X.509 signature algorithms, X.509 extensions,
  etc., liaising with LAMPS WG.

  Finally, the work will define how to integrate with TLS (Transport Layer
  Security; RFC 8446) and ACME (Automatic Certificate Management Environment;
  RFC 8555) protocols. This might include defining how to use existing protocol
  mechanisms, or using defining ACME and TLS extensions with existing extension
  points and liaising with ACME and TLS WGs.

- Open source projects (if any) implementing this work:

  - https://github.com/cloudflare/azul
  - https://github.com/bwesterb/mtc
  - https://github.com/pohlm01/mtc-verifier


## Agenda

   - Introduction, chairs (5 min)
   - Background / context (10 min)
   - Problem: Impact of post-quantum (10 minutes)
   - Overview of dispatched work (10 minutes)
   - Charter / deliverable discussion (30 min)
   - BOF Questions (55 min)

## Links to the mailing list, draft charter if any (for WG-forming BoF), relevant Internet-Drafts, etc.
   - Mailing List: https://www.ietf.org/mailman/listinfo/plants
   - Draft charter: https://github.com/davidben/merkle-tree-certs/blob/main/charter-ietf-plants.md
   - Relevant Internet-Drafts:
     - https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/

