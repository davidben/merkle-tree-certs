---
title: Merkle Tree Certificates for TLS
docname: draft-davidben-tls-merkle-tree-certs-latest
submissiontype: IETF
category: exp
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "davidben/merkle-tree-certs"
  latest: "https://davidben.github.io/merkle-tree-certs/draft-davidben-tls-merkle-tree-certs.html"

author:
 -
    ins: "D. Benjamin"
    name: "David Benjamin"
    organization: "Google LLC"
    email: davidben@google.com

 -
    ins: "D. O'Brien"
    name: "Devon O'Brien"
    organization: "Google LLC"
    email: asymmetric@google.com

 -
    ins: "B.E. Westerbaan"
    name: "Bas Westerbaan"
    organization: "Cloudflare"
    email: bas@cloudflare.com

normative:
  SHS: DOI.10.6028/NIST.FIPS.180-4
  RFC1034:
  RFC1123:

  X.690:
    title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
    date: February 2021
    author:
      org: ITU-T
    seriesinfo:
      ISO/IEC 8824-1:2021

  POSIX: DOI.10.1109/IEEESTD.2018.8277153

informative:
  CHROME-CT:
    title: Chrome Certificate Transparency Policy
    target: https://googlechrome.github.io/CertificateTransparency/ct_policy.html
    date: 2022-03-17
    author:
    - org: Google Chrome

  APPLE-CT:
    title: Apple's Certificate Transparency policy
    target: https://support.apple.com/en-us/HT205280
    date: 2021-03-05
    author:
    - org: Apple

  FIPS204:
    target: https://csrc.nist.gov/projects/post-quantum-cryptography
    title: >
      Module-Lattice-based Digital Signature Standard
    author:
    - org: National Institute of Standards and Technology (NIST)
    date: 2023-08
    seriesinfo:
      "FIPS PUB": "204"

  Falcon:
    title: "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU"
    target: https://falcon-sign.info/falcon.pdf
    date: 2020-01-10
    author:
    -
      ins: "P. Fouque"
      name: "Pierre-Alain Fouque"
    -
      ins: "J. Hoffstein"
      name: "Jeffrey Hoffstein"
    -
      ins: "P. Kirchner"
      name: "Paul Kirchner"
    -
      ins: "V. Lyubashevsky"
      name: "Vadim Lyubashevsky"
    -
      ins: "T. Pornin"
      name: "Thomas Pornin"
    -
      ins: "T. Prest"
      name: "Thomas Prest"
    -
      ins: "T. Ricosset"
      name: "Thomas Ricosset"
    -
      ins: "G. Seiler"
      name: "Gregor Seiler"
    -
      ins: "W. Whyte"
      name: "William Whyte"
    -
      ins: "Z. Zhang"
      name: "Zhenfei Zhang"

  CHROMIUM:
    title: Component Updater
    target: https://chromium.googlesource.com/chromium/src/+/main/components/component_updater/README.md
    date: 2022-03-03
    author:
    - org: Chromium

  FIREFOX:
    title: Firefox Remote Settings
    target: https://wiki.mozilla.org/Firefox/RemoteSettings
    date: 2022-08-20
    author:
    - org: Mozilla

  ALPACA:
    author:
    - ins: M. Brinkmann
      name: Marcus Brinkmann
    - ins: C. Dresen
      name: Christian Dresen
    - ins: R. Merget
      name: Robert Merget
    - ins: D. Poddebniak
      name: Damian Poddebniak
    - ins: J. Müller
      name: Jens Müller
    - ins: J. Somorovsky
      name: Juraj Somorovsky
    - ins: J. Schwenk
      name: Jörg Schwenk
    - ins: S. Schinzel
      name: Sebastian Schinzel
    date: August 2021
    target: https://www.usenix.org/conference/usenixsecurity21/presentation/brinkmann
    title: 'ALPACA: Application Layer Protocol Confusion - Analyzing and Mitigating Cracks in TLS Authentication'

  CRLite: DOI.10.1109/SP.2017.17

  CRLSets:
    title: CRLSets
    target: https://www.chromium.org/Home/chromium-security/crlsets/
    date: 2022-08-04
    author:
    - org: Chromium

  LetsEncrypt:
    title: Let's Encrypt Stats
    target: https://letsencrypt.org/stats/
    date: 2023-03-07
    author:
    - org: Let's Encrypt

  MerkleTown:
    title: Merkle Town
    target: https://ct.cloudflare.com/
    date: 2023-03-07
    author:
    - org: Cloudflare, Inc.

  SharedFactors:
    title: Finding shared RSA factors in the Certificate Transparency logs
    target: https://bora.uib.no/bora-xmlui/bitstream/handle/11250/3001128/Masters_thesis__for_University_of_Bergen.pdf
    date: 2022-05-13
    author:
    - name: Henry Faltin Våge
    - org: University of Bergen


--- abstract

This document describes Merkle Tree certificates, a new certificate type for use with TLS. A relying party that regularly fetches information from trusted mirrors can use this certificate type as a size optimization over more conventional mechanisms with post-quantum signatures. Merkle Tree certificates integrate the roles of X.509 and Certificate Transparency, achieving comparable security properties with a smaller message size, at the cost of more limited applicability.

--- middle

# Introduction

Authors' Note: This is an early draft of a proposal with many parts. While we have tried to make it as concrete as possible, we anticipate that most details will change as the proposal evolves.

A typical TLS {{!RFC8446}} handshake uses many signatures to authenticate the server public key. In a certificate chain with an end-entity certificate, an intermediate certificate, and an implicit trust anchor, there are two X.509 signatures {{?RFC5280}}. Intermediate certificates additionally send an extra public key. If the handshake uses Certificate Transparency (CT) {{?RFC6962}}, each Signed Certificate Timestamp (SCT) also carries a signature. CT policies often require two or more SCTs per certificate {{APPLE-CT}} {{CHROME-CT}}. If the handshake staples an OCSP response {{?RFC6066}} for revocation, that adds an additional signature.

Current signature schemes can use as few as 32 bytes per key and 64 bytes per signature {{?RFC8032}}, but post-quantum replacements are much larger. For example, ML-DSA-65 {{FIPS204}} uses 1,952 bytes per public key and 3,309 bytes per signature. A TLS Certificate message with, say, four ML-DSA-65 signatures (two X.509 signatures and two SCTs) and one intermediate CA's ML-DSA-65 public key would total 15,188 bytes of authentication overhead. Falcon-512 and Falcon-1024 {{Falcon}} would, respectively, total 3,561 and 6,913 bytes.

This document introduces Merkle Tree Certificates, an optimization that authenticates a TLS key using under 1,000 bytes. See {{sizes}}. To achieve this, it reduces its scope from general authentication:

* Certificates are short-lived. The authenticating party is expected to use an automated issuance protocol, such as ACME {{?RFC8555}}.

* Certificates are issued in batches after a significant processing delay of, in the recommended parameters ({{parameters}}), about an hour. Authenticating parties that need a certificate issued quickly are expected to use a different mechanism.

* Certificates are only usable with relying parties that have, via a background update process, obtained out-of-band assurance that a batch of certificates is publicly accessible. See {{transparency-ecosystem}}.

To support the reduced scope, this document also describes a certificate negotiation mechanism. Authenticating parties send these more efficient certificates when available, and otherwise fall back to other mechanisms.

Merkle Tree Certificates are not intended to replace existing Public Key Infrastructure (PKI) mechanisms but, in applications where a significant portion of authentications meet the above requirements, complement them as an optional optimization. In particular, it is expected that, even within applications that implement it, this mechanism will not be usable for all TLS connections.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document additionally uses the TLS presentation language defined in {{Section 3 of !RFC8446}}.

## Time {#time}

All time computations in this document are represented by POSIX timestamps, defined in this document to be integers containing a number of seconds since the Epoch, defined in Section 4.16 of {{POSIX}}. That is, the number of seconds after 1970-01-01 00:00:00 UTC, excluding leap seconds. A UTC time is converted to a POSIX timestamp as described in {{POSIX}}.

Durations of time are integers, representing a number of seconds not including leap seconds. They can be added to POSIX timestamps to produce other POSIX timestamps.

The current time is a POSIX timestamp determined by converting the current UTC time to seconds since the Epoch. One POSIX timestamp is said to be before (respectively, after) another POSIX timestamp if it is less than (respectively, greater than) the other value.

## Terminology and Roles

There are five roles involved in a Merkle Tree certificate deployment:

Authenticating party:
: The party that authenticates itself in the protocol. In TLS, this is the side sending the Certificate and CertificateVerify message.

Merkle Tree certification authority (CA):
: The service that issues Merkle Tree certificates to the authenticating party, and publishes logs of all certificates.

Relying party:
: The party whom the authenticating party presents its identity to. In TLS, this is the side receiving the Certificate and CertificateVerify message.

Mirror:
: A service that mirrors the issued certificates for others to monitor.

Monitor:
: A party who monitors CAs and/or mirrors for unauthorized certificates.

Additionally, there are several terms used throughout this document to describe this proposal. This section provides an overview. They will be further defined and discussed in detail throughout the document.

Assertion:
: A protocol-specific statement that the CA is certifying. For example, in TLS, the assertion is that a TLS signing key can speak on behalf of some DNS name or other identity.

Abridged assertion:
: A partially-hashed Assertion to save space. For example, in TLS, an abridged assertion replaces the subject public key by a hash.

Certificate:
: A structure, generated by the CA, that proves to the relying party that the CA has certified some assertion. A certificate consists of the assertion itself accompanied by an associated proof string.

Batch:
: A collection of assertions certified at the same time. CAs in this proposal only issue certificates in batches at a fixed frequency.

Batch tree head:
: A hash computed over all the assertions in a batch, by building a Merkle Tree. The Merkle Tree construction and this hash are described in more detail in {{building-tree}}.

Inclusion proof:
: A structure which proves that some assertion is contained in some tree head. See {{proofs}}.

Validity window:
: A range of consecutive batch tree heads. A relying party maintains a copy of the CA's latest validity window. At any time, it will accept only assertions contained in tree heads contained in the current validity window.

# Overview

The process of issuing and using a certificate occurs in three stages.

First, the CA issues a certificate to the authenticating party:

1. The authenticating party requests a certificate from the CA. {{acme-extensions}} describes ACME {{?RFC8555}} extensions for this.

2. The CA collects certificate requests into a batch (see {{parameters}}) and builds the Merkle Tree and computes the tree head (see {{building-tree}}). It then signs the validity window ending at this tree head (see {{signing}}) and publishes (see {{publishing}}) the result.

3. The CA constructs a certificate using the inclusion proof. It sends this certificate to the authenticating party. See {{proofs}}.

Next, tree heads flow to the relying party, after being durably and consistently logged. This occurs periodically in the background, unconnected from uses of individual certificates:

{:start="4"}
4. Mirrors periodically download the abridged assertions, recreate the Merkle Tree, and validate the window signature. They mirror the contents for monitors to observe. See {{mirrors}}.

5. The relying party periodically obtains an updated validity window, after the window's contents have been logged in mirrors that it trusts. See {{relying-party-policy}}.

Once the relying party has a validity window with the new tree head, the certificate is usable in an application protocol such as TLS:

{:start="6"}
6. The relying party communicates its currently saved validity window to the authenticating party.

7. If the relying party’s validity window contains the authenticating party’s certificate, the authenticating party negotiates this protocol and sends the Merkle Tree certificate. See {{certificate-negotiation}} for details. If there is no match, the authenticating party proceeds as if this protocol were not in use (e.g., by sending a traditional X.509 certificate chain).

{{fig-deployment}} below shows the three stages combined.

~~~ aasvg
     +--------------+  1. issuance request  +-------------------------+
     |              +---------------------->|                         |
     | Auth. Party  |                       | Certification Authority |
     |              |<----------------------+                         |
     +---------+----+   3. inclusion proof  +-----------+-------------+
            ^  |                                        |
            |  |                                        | 2. sign and
6. accepted |  | 7. inclusion proof                     |  publish tree
 tree heads |  |                                        |
            |  v                                        v
    +-------+---------+                      +----------------------+
    |                 |  5. batch tree heads |                      +-+
    |  Relying Party  |<---------------------+        Mirrors       | |
    |                 |                      |                      | |
    +-----------------+                      +-+--------------------+ |
                                               +--------+-------------+
                                                        |
                                                        | 4. publish tree
                                                        v
                                                  +------------+
                                                  |            |
                                                  |  Monitors  |
                                                  |            |
                                                  +------------+
~~~
{: #fig-deployment title="An overview of a Merkle Tree certificate deployment"}

The remainder of this document discusses this process in detail, followed by concrete instantions of it in TLS {{!RFC8446}} and ACME {{!RFC8555}}.

# Assertions {#assertions}

[[TODO: The protocol described in this document is broadly independent of the assertion format. We describe, below, one possible structure, but welcome feedback on how best to structure the encoding. The main aims are simplicity and to improve on handling cross-protocol attacks per {{cross-protocol}}.]]

TLS certificates associate some application-specific identifier with a TLS signing key. When TLS is used to authenticate HTTPS {{?RFC9110}} servers, these identifiers specify DNS names or HTTP origins. Other protocols may require other kinds of assertions.

To represent this, this document defines an Assertion structure:

~~~
enum { tls(0), (2^16-1) } SubjectType;

enum {
    dns(0),
    dns_wildcard(1),
    ipv4(2),
    ipv6(3),
    (2^16-1)
} ClaimType;

struct {
    ClaimType claim_type;
    opaque claim_info<0..2^16-1>;
} Claim;

struct {
    SubjectType subject_type;
    opaque subject_info<0..2^16-1>;
    Claim claims<0..2^16-1>;
} Assertion;
~~~

An Assertion is roughly analogous to an X.509 TBSCertificate ({{Section 4.1.2 of RFC5280}}). It describes a series of claims about some subject. The `subject_info` field is interpreted according to the `subject_type` value. For TLS, the `subject_type` is `tls`, and the `subject_info` is a TLSSubjectInfo structure. TLSSubjectInfo is defined in full in {{tls-subject-info}} below, but as an illustrative example, it is reproduced below:

~~~
struct {
    SignatureScheme signature;
    opaque public_key<1..2^16-1>;
} TLSSubjectInfo;
~~~

This structure represents the public half of a TLS signing key. The semantics are thus that each claim in `claims` applies to the TLS client or server. This is analogous to X.509's SubjectPublicKeyInfo structure ({{Section 4.1.2.7 of RFC5280}}) but additionally incorporates the protocol. Protocols consuming an Assertion MUST check the `subject_type` is a supported value before processing `subject_info`. If unrecognized, the structure MUST be rejected.

Other protocols aiming to integrate with this structure allocate a SubjectType codepoint and describe how it is interpreted.

Likewise, a Claim structure describes some claim about the subject. The `claim_info` field is interpreted according to the `claim_type`. Each Claim structure in an Assertion's `claims` field MUST have a unique `claim_type` and all values MUST be sorted in order of increasing `claim_type`. Structures violating this constraint MUST be rejected.

When a relying party interprets an Assertion certified by the CA, it MUST ignore any Claim values with unrecognized `claim_type`. When a CA interprets an Assertion in a certification request from an authenticating party, it MUST reject any Claim values with unrecognized `claim_type`.

This document defines claim types for DNS names and IP addresses, but others can be defined.

[[TODO: For now, the claims below just transcribe the X.509 GeneralName structure. Should these be origins instead? For HTTPS, it's a pity to not capture the scheme and port. We do mandate ALPN in {{tls-certificate-type}}, so cross-protocol attacks are mitigated, but it's unfortunate that authenticating parties cannot properly separate their HTTPS vs FTPS keys, or their port 443 vs port 444 keys. One option here is to have HTTPS claims instead, and then other protocols can have FTPS claims, etc. #35 ]]

## DNS Claims

The `dns` and `dns_wildcard` claims indicate that the subject is authoritative for a set of DNS names. They use the DNSNameList structure, defined below:

~~~
opaque DNSName<1..255>;

struct {
    DNSName dns_names<1..2^16-1>;
} DNSNameList;
~~~

DNSName values use the "preferred name syntax" as specified by {{Section 3.5 of RFC1034}} and as modified by {{Section 2.1 of RFC1123}}. Alphabetic characters MUST additionally be represented in lowercase. IDNA names {{!RFC5890}} are represented as A-labels. For example, possible values include `example.com` or `xn--iv8h.example`. Values `EXAMPLE.COM` and `<U+1F50F>.example` would not be permitted.

Names in a `dns` claim represent the exact DNS name specified. Names in a `dns_wildcard` claim represent wildcard DNS names and are processed as if prepended with the string "`*.`" and then following the steps in {{Section 6.3 of !RFC9525}}.

## IP Claims

The `ipv4` and `ipv6` claims indicate the subject is authoritative for a set of IPv4 and IPv6 addresses, respectively. They use the IPv4AddressList and IPv6AddressList structures, respectively, defined below. IPv4Address and IPv6Address are interpreted in network byte order.

~~~
uint8 IPv4Address[4];
uint8 IPv6Address[16];

struct {
    IPv4Address addresses<4..2^16-1>;
} IPv4AddressList;

struct {
    IPv6Address addresses<16..2^16-1>;
} IPv6AddressList;
~~~

# Issuing Certificates

This section describes the structure of Merkle Tree certificates and defines the process of how a Merkle Tree certification authority issues certificates for an authenticating party.

## Merkle Tree CA Parameters {#parameters}

A Merkle Tree certification authority is defined by the following values:

`hash`:
: A cryptographic hash function. In this document, the hash function is always SHA-256 {{SHS}}, but others may be defined.

`issuer_id`:
: A trust anchor identifier (see {{Section 3 of !I-D.ietf-tls-trust-anchor-ids}}) that identifies the CA. See {{identifying}} for details.

`public_key`:
: The public half of a signing key. For convenience, we use TLS' format, and represent the public key as a `TLSSubjectInfo`, see {{tls-subject-info}}. The corresponding private key, `private_key`, is known only to the CA.

`start_time`:
: The issuance time of the first batch of certificates, represented as a POSIX timestamp (see {{time}}).

`batch_duration`:
: A number of seconds which determines how frequently the CA issues certificates. See details below.

`lifetime`:
: A number of seconds which determines the lifetime of certificates issued by this CA. MUST be a multiple of `batch_duration`.

`validity_window_size`:
: An integer describing the maximum number of unexpired batches which may exist at a time. This value is determined from `lifetime` and `batch_duration` by `lifetime / batch_duration`.

These values are public and known by the relying party and the CA. They may not be changed for the lifetime of the CA. To change these parameters, the entity operating a CA may deploy a second CA and either operate both during a transition, or stop issuing from the previous CA.

[[TODO: The signing key case is interesting. A CA could actually maintain a single stream of Merkle Trees, but then sign everything with multiple keys to support rotation. The CA -> Authenticating Party -> RP flow does not depend on the signature, only the CA -> Mirror -> RP flow. The document is not currently arranged to capture this, but it probably should be. We probably need to decouple the signing half and the Merkle Tree half slightly. #36 ]]

Certificates are issued in batches. Batches are numbered consecutively, starting from zero. All certificates in a batch have the same issuance time, determined by `start_time + batch_duration * batch_number`. This is known as the batch's issuance time. That is, batch 0 has an issuance time of `start_time`, and issuance times increment by `batch_duration`. A CA can issue no more frequently than `batch_duration`. `batch_duration` determines how long it takes for the CA to return a certificate to the authenticating party.

All certificates in a batch have the same expiration time, computed as `lifetime` past the issuance time. After this time, the certificates in a batch are no longer valid. Merkle Tree certificates uses a short-lived certificates model, such that certificate expiration replaces an external revocation signal like CRLs {{RFC5280}} or OCSP {{?RFC6960}}. `lifetime` SHOULD be set accordingly. For instance, a deployment with a corresponding maximum OCSP {{?RFC6960}} response lifetime of 14 days SHOULD use a value no higher than 14 days. See {{revocation}} for details.

CAs are RECOMMENDED to use a `batch_duration` of one hour, and a `lifetime` of 14 days. This results in a `validity_window_size` of 336, for a total of 10,752 bytes in SHA-256 hashes.

To prevent cross-protocol attacks, the key used in a Merkle Tree CA MUST be unique to that Merkle Tree CA. It MUST NOT be used in another Merkle Tree CA, or for another protocol, such as X.509 certificates.

## Identifying CAs and Batches {#identifying}

A Merkle Tree CA's `issuer_id` is a trust anchor identifier, defined in {{Section 3 of !I-D.ietf-tls-trust-anchor-ids}}. However, unlike an X.509 CA, the entire OID arc rooted at the identifier is associated with the CA. OIDs under this arc are used to identify batches below.

An individual batch from a Merkle Tree CA also has an associated trust anchor identifier, called a `batch_id`. It is determined by appending the batch number, as an OID component, to the CA's `issuer_id`.

For example, a Merkle Tree CA may have an `issuer_id` of `32473.1`, in the ASCII representation.
The batch with batch number 42 would then have a `batch_id` of `32473.1.42`.

## Batch State {#batches}

Each batch is in one of three states:

pending:
: The current time is before the batch's issuance time

ready:
: The current time is not before the batch's issuance time, but the batch has not yet been issued

issued:
: Certificates have been issued for this batch

The CA also maintains a latest batch number, which is the number of the last batch in the "issued" state. As an invariant, all batches before this value MUST also be in the "issued" state.

For each batch in the "issued" state, the CA maintains the following batch state:

* The list of abridged assertions certified in this batch.

* The tree head, a hash computed over this list, described in {{building-tree}}.

* A validity window signature computed as described in {{signing}}.

The CA exposes all of this information in an HTTP {{!RFC9110}} interface described in {{publishing}}.

## Issuance Queue and Scheduling

The CA additionally maintains an issuance queue, not exposed via the HTTP interface.

When an authenticating party requests a certificate for some assertion, the CA first validates it per its issuance policy. For example, it may perform ACME identifier validation challenges ({{Section 8 of ?RFC8555}}). Once validation is complete and the CA is willing to certify the assertion, the CA appends it to the issuance queue.

The CA runs a regularly-scheduled issuance job which converts this queue into certificates. This job runs the following procedure:

1. If no batches are in the "ready" state, do nothing and abort this procedure. Schedule a new job to run sometime after the earliest "pending" batch's issuance time.

2. For each batch in the "ready" state other than the latest one, run the procedure in {{certifying-batch}} with an empty assertion list, in order of increasing batch number. Batches cannot be skipped.

3. Empty the issuance queue into an ordered list of assertions. Run the procedure in {{certifying-batch}} using this list and the remaining batch in the "ready" state. This batch's issuance time will be at or shortly before the current time.

## Certifying a Batch of Assertions {#certifying-batch}

This section describes how to certify a given list of assertions at a given batch number. The batch MUST be in the "ready" state, and all preceding batches MUST be in the "issued" state.

### Building the Merkle Tree {#building-tree}

First, the CA then builds a Merkle Tree from the list as follows:

Let `n` be the number of input assertions. If `n > 0`, the CA builds a binary tree with l levels numbered `0` to `l-1`, where `l` is the smallest positive integer such that `n <= 2^(l-1)`. Each node in the tree contains a hash value. Hashes in the tree are built from the following functions:

~~~~
    HashEmpty(level, index) = hash(HashEmptyInput)
    HashNode(left, right, level, index) = hash(HashNodeInput)
    HashAssertion(assertion, index) = hash(HashAssertionInput)
~~~~

`HashEmpyInput`, `HashNodeInput` and `HashAssertionInput` are computed by encoding the structures defined below:

~~~
struct {
    uint8 distinguisher = 0;
    TrustAnchorIdentifier batch_id;
    uint64 index;
    uint8 level;
} HashEmptyInput;

struct {
    uint8 distinguisher = 1;
    TrustAnchorIdentifier batch_id;
    uint64 index;
    uint8 level;
    opaque left[hash.length];
    opaque right[hash.length];
} HashNodeInput;

struct {
    SubjectType subject_type;
    opaque subject_info_hash[hash.length];
    Claim claims<0..2^16-1>;
} AbridgedAssertion;

struct {
    uint8 distinguisher = 2;
    TrustAnchorIdentifier batch_id;
    uint64 index;
    AbridgedAssertion abridged_assertion;
} HashAssertionInput;
~~~

The `batch_id` is set to the batch-specific trust anchor identifier, i.e. the `issuer_id` with the batch number appended as described in {{identifying}}.
`HashAssertionInput.abridged_assertion.subject_info_hash` is set to `hash(assertion.subject_info)` from the function input `assertion`, and the remaining fields of `HashAssertionInput.abridged_assertion` are taken unmodified from `assertion`.
The remaining fields, such as `index`, are set to inputs of the function.

Tree levels are computed iteratively as follows:

1. Initialize level 0 with n elements. For `j` between `0` and `n-1`, inclusive,
   set element `j` to the output of `HashAssertion(assertion[j], j)`.

2. For `i` between `1` and `l-1`, inclusive, compute level `i` from level `i-1` as
   follows:

   - If level `i-1` has an odd number of elements `j`, append `HashEmpty(i-1, j)` to the level.

   - Initialize level `i` with half as many elements as level `i-1`. For all `j`,
     set element `j` to the output of `HashNode(left, right, i, j)` where `left` is
     element `2*j` of level `i-1` and `right` is element `2*j+1` of level `i-1`.
     `left` and `right` are the left and right children of element `j`.

At the end of this process, level `l-1` will have exactly one root element. This element is called the tree head. {{fig-example-tree}} shows an example tree for three assertions. The tree head in this example is t20.

~~~~ aasvg
    level 2:           ___ t20 ___
                      /           \
                     /             \
    level 1:       t10             t11
                   / \             / \
                  /   \           /   \
    level 0:   t00     t01     t02    empty
                |       |       |
                a0      a1      a2
~~~~
{: #fig-example-tree title="An example Merkle Tree for three assertions"}

If `n` is zero, the CA does not build a tree and the tree head is `HashEmpty(0, 0)`.

If `n` is one, the tree contains a single level, level 0, and has a tree head of `HashAssertion(assertion, 0)`.

### Signing a ValidityWindow {#signing}

Batches are grouped into consecutive ranges of `validity_window_size` batches, called validity windows. As `validity_window_size` is computed to cover the full certificate lifetime, a validity window that ends at the latest batch number covers all certificates that may still be valid from a CA.

Validity Windows are serialized into the following structure:

~~~
opaque TreeHead[hash.length];

struct {
    uint32 batch_number;
    TreeHead tree_heads[validity_window_size*hash.length];
} ValidityWindow;
~~~

`batch_number` is the batch number of the highest batch in the validity window.

`tree_heads` value contains the last `validity_window_size` tree heads. (Recall the TLS presentation language brackets the total length of a vector in bytes; not the number of elements.) `tree_heads` starts from `batch_number`, in decreasing batch number order. That is, `tree_heads[0]` is the tree head for batch `batch_number`, `tree_heads[1]` is the tree head for `batch_number - 1`, and so on. If `batch_number < validity_window_size - 1`, any tree heads for placeholder negative batch numbers are filled with `HashEmpty(0, 0)`, computed with `batch_number` set to 0.

After the CA builds the Merkle Tree for a batch, it constructs the ValidityWindow structure whose `batch_number` is the number of the batch being issued. It then computes a digital signature over the following structure:

~~~
struct {
    uint8 label[32] = "Merkle Tree Crts ValidityWindow\0";
    TrustAnchorIdentifier issuer_id;
    ValidityWindow window;
} LabeledValidityWindow;
~~~

The signature algorithm used is determined by `public_key.signature` as described in {{Section 4.3.2 of RFC8446}}. (Signatures are created without the domain separation of {{Section 4.4.3 of RFC8446}}.)

The `label` field is an ASCII string. The final byte of the string, "\0", is a zero byte, or ASCII NULL character. The `issuer_id` field is the CA's `issuer_id`. Other parties can verify the signature by constructing the same input and verifying with the CA's `public_key`.

The CA saves this signature as the batch's validity window signature. It then updates the latest batch to point to `batch_number`. A CA which generates such a signature is considered to have certified every assertion contained in every value in the `tree_heads` list, with expiry determined by `batch_number`, the position of the tree head in the list, and the CA's input parameters as described in {{parameters}}.

A CA MUST NOT generate signatures over inputs that are parseable as LabeledValidityWindow, except via the above process. If a LabeledValidityWindow structure that was not produced in this way has a valid signature by CA's `public_key`, this indicates misuse of the private key by the CA, even if the preimages to the `tree_heads` values, or intermediate nodes, or `subject_info_hash` values are not known.

### Certificate Format {#proofs}

[[TODO: BikeshedCertificate is a placeholder name until someone comes up with a better one. #15 ]]

[[TODO: An authenticating party has no way to know when a certificate expires. We need to define a mandatory expiration certificate property, or do #83, which, depending on how it's done could avoid that.]]

For each assertion in the tree, the CA constructs a BikeshedCertificate structure containing the assertion and a proof. A proof is a message that allows the relying party to accept the associated assertion, provided it trusts the CA and recognizes the tree head. The structures are defined below:

~~~
/* See Section 4.1 of draft-ietf-tls-trust-anchor-ids */
opaque TrustAnchorIdentifier<1..2^8-1>;

struct {
    TrustAnchorIdentifier trust_anchor;
    opaque proof_data<0..2^16-1>;
} Proof;

struct {
    Assertion assertion;
    Proof proof;
} BikeshedCertificate;
~~~

A proof's `trust_anchor` field is a trust anchor identifier (see {{Section 3 of !I-D.ietf-tls-trust-anchor-ids}} and {{Section 4.1 of !I-D.ietf-tls-trust-anchor-ids}}), which determines the proof's type and issuer.
It is analogous to an X.509 trust anchor's subject name.
When the issuer is a Merkle Tree CA, the `trust_anchor` is a batch's `batch_id`, as described in {{identifying}}.

The `proof_data` is a byte string, opaque to the authenticating party, in some format agreed upon by the proof issuer and relying party. If the issuer is a Merkle Tree CA, as defined in this document, the `proof_data` contains a MerkleTreeProofSHA256, described below. Future mechanisms using the BikeshedCertificate may define other formats.

~~~
opaque HashValueSHA256[32];

struct {
    uint64 index;
    HashValueSHA256 path<0..2^16-1>;
} MerkleTreeProofSHA256;
~~~

After building the tree, the CA constructs a MerkleTreeProofSHA256 for each assertion as follows. For each index `i` in the batch's assertion list:

1. Set `index` to `i`. This will be a value between `0` and `n-1`, inclusive.

2. Set `path` to an array of `l-1` hashes. Set element `j` of this array to element
   `k` of level `j`, where `k` is `(i >> j) ^ 1`. `>>` denotes a bitwise
   right-shift, and `^` denotes a bitwise exclusive OR (XOR) operation. This
   element is the sibling of an ancestor of assertion `i` in the tree. Note the
   tree head is never included.

For example, the `path` value for the third assertion in a batch of three assertions would contain the marked nodes in {{fig-example-proof}}, from bottom to top.

~~~~ aasvg
    level 2:           ___ t20 ___
                      /           \
                     /             \
    level 1:      *t10             t11
                   / \             / \
                  /   \           /   \
    level 0:   t00     t01     t02   *empty
                |       |       |
                a0      a1      a2
~~~~
{: #fig-example-proof title="An example Merkle Tree proof for the third of three assertions"}

If the batch only contained one assertion, `path` will be empty and `index` will be zero.

For each assertion, the CA assembles a BikeshedCertificate structure and sends it to the authenticating party.

This certificate can be presented to supporting relying parties as described in {{using}}. It is valid until the batch expires.

## Size Estimates {#sizes}

Merkle Tree proofs scale logarithmically in the batch size. {{rolling-renewal}} recommends authenticating parties renew halfway through the previous certificate's lifetime. Batch sizes will thus, on average, be `subscriber_count * 2 / validity_window_size`, where `subscriber_count` is a CA's active subscriber count. The recommended parameters in {{parameters}} give an average of `subscriber_count / 168`.

Some organizations have published statistics which can estimate batch sizes for the Web PKI. On March 7th, 2023, {{LetsEncrypt}} reported around 330,000,000 active subscribers for a single CA. {{MerkleTown}} reported around 3,800,000,000 unexpired certificates in Certificate Transparency logs, and an issuance rate of around 257,000 per hour. Note the numbers from {{MerkleTown}} represent, respectively, all Web PKI CAs combined and issuance rates for longer-lived certificates and may not be representative of a Merkle Tree certificate deployment.

These three estimates correspond to batch sizes of, respectively, around 2,000,000, around 20,000,000, and 257,000. The corresponding `path` lengths will be 20, 24, and 17, given proof sizes of, respectively, 640 bytes, 768 bytes, and 544 bytes.

For larger batch sizes, 32 hashes, or 1024 bytes, is sufficient for batch sizes up to 2^33 (8,589,934,592) certificates.

# Using Certificates {#using}

This section describes how authenticating parties present and relying parties verify Merkle Tree certificates.

## Relying Party State {#relying-parties}

For each Merkle Tree CA it trusts, a relying party maintains a copy of the most recent validity window from the CA. This structure determines which certificates the relying party will accept. It is regularly updated from mirrors, as described in {{transparency-ecosystem}}.

Each batch in the relying party's validity window is a trust anchor for purposes of certificate verification (see {{verifying}}) and certificate negotiation (see {{certificate-negotiation}}).

## Certificate Verification {#verifying}

This section describes the verification process for a BikeshedCertificate. It describes error conditions with TLS alerts, defined in {{Section 6.2 of RFC8446}}. Non-TLS applications SHOULD map these error conditions to the corresponding application-specific errors. When multiple error conditions apply, the application MAY return any applicable error.

When an authenticating party presents a BikeshedCertificate, the relying party runs the following procedure:

1. Determines if `trust_anchor` corresponds to a supported trust anchor, and the type of that trust anchor. If `trust_anchor` is unrecognized, the relying party rejects the certificate with an `unknown_ca` error.

2. Run the verification subroutine corresponding to that trust anchor, defined below.

3. Optionally, perform any additional application-specific checks on the assertion and issuer. For example, an HTTPS client might constrain an issuer to a particular DNS subtree.

4. If all the preceding checks succeed, the certificate is valid and the application can proceed with using the assertion.

Step 2 in the above procedure runs a trust-anchor-specific verification subroutine. This subroutine is determined by the type of trust anchor. Each mechanism using the BikeshedCertificate format MUST define a verification subroutine.

For a Merkle Tree trust anchor, the trust anchor will identify a batch in the relying party's validity window. (See {{identifying}} and {{relying-parties}}.) The batch's verification subroutine is defined below:

1. Compute the batch's expiration time, as described in {{parameters}}. If this value is before the current time, abort this procedure with a `certificate_expired` error.

2. Set `hash` to the output of `HashAssertion(assertion, index)`. Set `remaining` to the certificate's `index` value.

3. For each element `v` at zero-based index `i` of the certificate's `path` field, in order:

   - If `remaining` is odd, set `hash` to the output of `HashNode(v, hash, i + 1, remaining >> 1)`.
     Otherwise, set `hash` to the output of `HashNode(hash, v, i + 1, remaining >> 1)`

   - Set `remaining` to `remaining >> 1`.

4. If `remaining` is non-zero, abort this procedure with an error.

5. If `hash` is not equal to the batch's tree head in the relying party's saved validity window (see {{relying-parties}}), abort this procedure with a `bad_certificate` error.

6. If all the preceding checks succeed, the Merkle Tree certificate verification subroutine completes successfully.

# Transparency Ecosystem {#transparency-ecosystem}

This section discusses how relying parties achieve transparency, via a combination of *mirrors* ({{mirrors}}), who republish information from the CA; *relying party policy* ({{relying-party-policy}}), which determines which validity windows to accept; and *monitors* ({{monitors}}), who watch for certificates of interest.

## Mirrors

A mirror is a service that consumes and saves information hosted by CAs (or other mirrors) and presents it to other parties in the ecosystem. Mirrors are used to ensure transparency even in the face of CA misbehavior or outage. A mirror performs the following functions:

* Record all abridged assertions certified by the CA and mirror them to monitors

* Ensure all tree heads and validity windows that it records and mirrors are self-consistent

* Provide information about the latest valid validity window recorded

In doing so, the mirror MUST satisfy the following requirements:

* The mirrored CA state is append-only. That is, the hashes, signatures, and assertions for a given batch number MUST NOT change, even if a CA signs conflicting information.

* All tree hashes that it reports MUST be reflected in the mirrored CA state.

The mirror publishes its state using the same interface as {{publishing}}.

### Updating a Mirror

A mirror maintains a copy of the CA's latest batch number, and batch state. Roughly once every `batch_duration`, it polls the HTTP interface (see {{publishing}}) from the CA, or another mirror, and runs the following steps:

1. Fetch the latest batch number.  If this fetch fails, abort this procedure with an error.

2. Let `new_latest_batch` be the result and `old_latest_batch` be the currently mirrored value. If `new_latest_batch` equals `old_latest_batch`, finish this procedure without reporting an error.

3. If `new_latest_batch` is less than `old_latest_batch`:

   1. If the source is the CA, or if `old_latest_batch` was fetched from this mirror, abort this procedure with an error.

   2. Otherwise, finish this procedure without reporting an error. A mirror that combines multiple sources may observe a source mirror that is behind.

4. If the issuance time for batch `new_latest_batch` is after the current time (see {{parameters}}), abort this procedure with an error.

5. For all `i` such that `old_latest_batch < i <= new_latest_batch`:

   1. Fetch the signature, tree head, and abridged assertion list for batch `i`. If this fetch fails, abort this procedure with an error.

   2. Compute the tree head for the assertion list, as described in {{building-tree}}. If this value does not match the fetched tree head, abort this procedure with an error.

   3. Compute the ValidityWindow structure and verify the signature, as described in {{signing}}. Set `tree_heads[0]` to the tree head fetched above. Set the other values in `tree_heads` to the previously mirrored values. If signature verification fails, abort this procedure with an error.

   4. Set the mirrored latest batch number to `i` and save the fetched batch state.

[[TODO: If the mirror gets far behind, or if the CA just stops publishing for a while, it may suddenly have to catch up on many batches. Should we allow the mirror to catch up to the latest validity window and skip the intervening batches? The intervening batches are guaranteed to have been expired #37 ]]

## Relying Party Policy

In order to accept certificates from a CA that it trusts, a relying party must, in the background, obtain an up-to-date copy of the CA's validity window. In doing so, a relying party SHOULD ensure the following properties:

Authenticity:
: The relying party only accepts validity windows that were certified by the CA

Transparency:
: The relying party only accepts validity windows covering certificates that are published in some publicly-accessible form, so that, in particular, the subject of the certificate can notice any unauthorized certificates

How the relying party does this has no direct impact on certificate issuance ({{issuing-certificates}}) or usage ({{using}}). Different relying parties can obtain validity windows from different sources or apply different policies, while supporting the same unmodified certificates and CAs. Thus this section does not prescribe particular policies or mechanisms, but provides examples and general guidance. Relying parties MAY implement policies other than those described below, and MAY incorporate entities acting in roles not described in this document.

Relying parties SHOULD ensure transparency by obtaining validity windows from the CA and/or some combination of trusted mirrors. The relying party picks sources which, together, are trusted to satisfy the requirements described in {{mirrors}}. Mirrors allow the relying party to maintain transparency in the face of a misbehaving or compromised CA that may, for example, stop serving some unauthorized certificate in a batch to evade detection.

A relying party might trust a combination of mirrors, and only accept a validity window once some minimum number of mirrors have consumed it. When combining multiple mirrors, the following procedure determines the latest validity window for an update:

1. Fetch the latest batch number from each mirror.

2. Compute the highest batch number that satisfies the policy. For example, if requiring windows be represented in at least two mirrors, use the second-to-last batch number after sorting in ascending order.

3. Fetch the validity window from each mirror that contains it.

4. Check that each fetched window gives identical tree hashes. If so, accept the updated window.

To avoid the relying party directly contacting each mirror, this procedure can be performed with some aggregating service on behalf of the relying party, or the relying party's update service.  [[TODO: If the relying party doesn't trust the aggregator, this requires mirrors re-sign validity windows, but we still need to define that. #101]]

Some relying parties regularly contact a trusted update service, either for software updates or to update individual components, such as the services described in {{CHROMIUM}} and {{FIREFOX}}. If the relying party considers the service sufficiently trusted (e.g. if the service provides the trust anchor list or certificate validation software), a mirror operated by that service could be used as a single trusted mirror.

Relying parties SHOULD ensure authenticity by verifying the CA's signature on the validity window. If a relying party has an authenticated channel to some service trusted to perform this check, it MAY rely on that service to validate signatures, instead of downloading the signature itself.

When fetching any of the above information, the relying party MAY use the interfaces described in {{publishing}}, or it MAY use some other application-specific channel.

## Monitors

Monitors in this document are analogous to monitors in {{?RFC6962}}. Monitors watch an implementation of the HTTP APIs in {{publishing}} to verify correct behavior and watch for certificates of interest. This may be a mirror or the CA itself. A monitor needs to, at least, inspect every new batch. It may also maintain a copy of the batch state.

It does so by following the procedure in {{updating-a-mirror}}, fetching from the service being monitored. If the procedure fails for a reason other than the service availability, this should be viewed as misbehavior on the part of the service. If the procedure fails due to service availability and the service remains unavailable for an extended period, this should also be viewed as misbehavior. If the monitor is not maintaining a copy of the batch state, it skips saving the abridged assertions.

{{?RFC6962}} additionally defines the role of auditor, which validates that Signed Certificate Timestamps (SCTs) and Signed Tree Heads (STHs) in Certificate Transparency are correct. There is no analog to SCTs in this document. The signed validity window structure ({{signing}}) is analogous to an STH, but consistency is checked simply by ensuring overlapping tree heads match, so this document does not define this as an explicit role. If two inconsistent signed validity windows are ever observed from a Merkle Tree CA, this should be viewed as misbehavior on the part of the CA.

# HTTP Interface {#publishing}

[[TODO: This section hasn't been written yet. For now, this is just an informal sketch. The real text will need to define request/response formats more precisely, with MIME types, etc. #12 ]]

CAs and mirrors publish state over an HTTP {{!RFC9110}} interface described below.

CAs and any mirrors that maintain validity window information implement the following interfaces:

* `GET {prefix}/latest` returns the latest batch number.

* `GET {prefix}/validity-window/latest` returns the ValidityWindow structure and signature (see {{signing}}) for the latest batch number.

* `GET {prefix}/validity-window/{number}` returns the ValidityWindow structure and signature (see {{signing}}) for batch `number`, if it is in the "issued" state, and a 404 error otherwise.

* `GET {prefix}/batch/{number}/info` returns the validity window signature and tree head for batch `number`, if batch `number` is in the "issued" state, and a 404 error otherwise.

CAs and any mirrors that maintain the full abridged assertion list additionally implement the following interface:

* `GET {prefix}/batch/{number}/assertions` returns the abridged assertion list for batch `number`, if `number` is in the issued state, and a 404 error otherwise.

If the interface is implemented by a distributed service, with multiple servers, updates may propagate to servers at different times, which will cause temporary inconsistency. This inconsistency can impede this system's transparency goals ({{transparency}}).

Services implementing this interface SHOULD wait until batch state is fully propagated to all servers before updating the latest batch number. That is, if any server returns a latest batch number of N in either of the first two HTTP endpoints, batch numbers N and below SHOULD be available under the last three batch-number-specific HTTP endpoints in all servers. If this property does not hold at any time, it is considered a service unavailability.

Individual servers in a service MAY return different latest batch numbers. Individual servers MAY also differ on whether a batch number has a response available or return a 404 error. Provided the above consistency property holds, these two inconsistencies do not constitute service unavailability.

{{batch-state-availability}} discusses service availability requirements.

[[TODO: Once a batch has expired, do we allow a CA to stop publishing it? A mirror can already log it for as long, or as little, as it wishes. We effectively have CT log temporal sharding built into the system. #2 ]]

[[TODO: If we have the validity window endpoint, do we still need to separate "info" and "assertions"? #12]]

# ACME Extensions {#acme-extensions}

[[TODO: This section hasn't been written yet. Instead, what follows is an informal discussion. #13 ]]

{{Section 6 of !I-D.ietf-tls-trust-anchor-ids}} defines the bulk of what's needed. The missing parts are:

* Some way to specify that the client supports BikeshedCertificate. At minimum a separate MIME type, but it likely needs to be known at order creation.

* Some way to accommodate MTC's long issuance time. ACME has the "processing" state, and the Retry-After header can tell the authenticating party when to query again. But the fallback certificate will issue much faster, so they cannot be issued together in the same ACME order, as {{!I-D.ietf-tls-trust-anchor-ids}} currently does.

* Use {{?I-D.ietf-acme-ari}} to move the renewal logic in {{rolling-renewal}} from the authenticating party to the ACME server.

We should also define a certificate request format, though it is broadly just reusing the Assertion structure. If the CA wishes to check possession of the private key, it'll need to come with a signature or do some online operation (e.g. if it's a KEM key). This is inherently protocol-specific, because the mechanism needs to coexist with the target protocol. (Signed CSRs implicitly assume the target protocol's signature payloads cannot overlap with that of a CSR.)

# Use in TLS {#tls-protocol}

## TLS Subjects {#tls-subject-info}

This section describes the SubjectType for use with TLS {{RFC8446}}. The SubjectType value is `tls`, and the `subject_info` field contains a TLSSubjectInfo structure, defined below:

~~~
enum { tls(0), (2^16-1) } SubjectType;

struct {
    SignatureScheme signature;
    opaque public_key<1..2^16-1>;
    /* TODO: Should there be an extension list? #38 */
} TLSSubjectInfo;
~~~

A TLSSubjectInfo describes a TLS signing key. The `signature` field is a SignatureScheme {{Section 4.2.3 of RFC8446}} value describing the key type and signature algorithm it uses for CertificateVerify.

The `public_key` field contains the authenticating party's public key. The encoding is determined by the `signature` field as follows:

RSASSA-PSS algorithms:
: The public key is an RSAPublicKey structure {{!RFC8017}} encoded in DER {{X.690}}. BER encodings which are not DER MUST be rejected.

ECDSA algorithms:
: The public key is a UncompressedPointRepresentation structure defined in {{Section 4.2.8.2 of !RFC8446}}, using the curve specified by the SignatureScheme.

EdDSA algorithms:
: The public key is the byte string encoding defined in {{!RFC8032}}

This document does not define the public key format for other algorithms. In order for a SignatureScheme to be usable with TLSSubjectInfo, this format must be defined in a corresponding document.

[[TODO: If other schemes get defined before this document is done, add them here. After that, it's on the other schemes to do it. #39 ]]

## The Bikeshed Certificate Type {#tls-certificate-type}

[[TODO: Bikeshed is a placeholder name until someone comes up with a better one. #15]]

This section defines the `Bikeshed` TLS certificate type, which may be negotiated with the `client_certificate_type`, `server_certificate_type` {{!RFC7250}}, or `cert_type` {{!RFC6091}} extensions. It can only be negotiated with TLS 1.3 or later. Servers MUST NOT negotiate it in TLS 1.2 or below. If the client receives a ServerHello that negotiates it in TLS 1.2 or below, it MUST abort the connection with an `illegal_parameter` alert.

[[TODO: None of these three extensions is quite right for client certificates because the negotiation isn't symmetric. See discussion in {{cert-type-problems}}. We may need to define another one. #18]]

When negotiated, the Certificate message MUST contain a single CertificateEntry structure.
CertificateEntry is updated as follows:

~~~
enum { Bikeshed(TBD), (255) } CertificateType;

struct {
    select (certificate_type) {
        /* Certificate type defined in this document */
        case Bikeshed:
            opaque bikeshed_cert_data<1..2^24-1>;

        /* From RFC 7250 */
        case RawPublicKey:
            opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

        case X509:
            opaque cert_data<1..2^24-1>;

        /* Additional certificate types based on the
          "TLS Certificate Types" registry */
    };
    Extension extensions<0..2^16-1>;
} CertificateEntry;
~~~

The `subject_type` field in the certificate MUST be of type `tls` ({{tls-subject-info}}). The CertificateVerify message is computed and processed as in {{RFC8446}}, with the following modifications:

* The signature is computed and verified with the key described in the TLSSubjectInfo. The relying party uses the key decoded from the `public_key` field, and the authenticating party uses the corresponding private key.

* The SignatureScheme in the CertificateVerify MUST match the `signature` field in the TLSSubjectInfo.

The second modification differs from {{RFC8446}}. Where {{RFC8446}} allowed an id-rsaEncryption key to sign both `rsa_pss_rsae_sha256` and `rsa_pss_rsae_sha384`, TLSSubjectInfo keys are specific to a single algorithm. Future documents MAY relax this restriction for a new SignatureScheme, provided it was designed to be used concurrently with the value in TLSSubjectInfo. In particular, the underlying signature algorithm MUST match, and there MUST be appropriate domain separation between the two modes. For example, {{?I-D.ietf-tls-batch-signing}} defines new SignatureSchemes, but the same keypair can be safely used with one of the new values and the corresponding base SignatureScheme.

If this certificate type is used for either the client or server certificate, the ALPN {{!RFC7301}} extension MUST be negotiated. If no application protocol is selected, endpoints MUST close the connection with a `no_application_protocol` alert.

[[TODO: Suppose we wanted to introduce a second SubjectType for TLS, either to add new fields or capture a new kind of key. That would need to be negotiated. We could use another extension, but defining a new certificate type seems most natural. That suggests this certificate type isn't about negotiating BikeshedCertificate in general, but specifically SubjectType.tls and TLSSubjectInfo. So perhaps the certificate type should be TLSSubjectInfo or BikeshedTLS. #7 ]]

## Certificate Negotiation

Merkle Tree certificates will only be accepted in up-to-date relying parties, and require a negotiation mechanism to use. Merkle Tree certificate implementations SHOULD use the `trust_anchors` extension {{!I-D.ietf-tls-trust-anchor-ids}} as described below:

For each Merkle Tree CA trusted by the relying party, the batches in the validity window each determine a trust anchor, as described in {{relying-parties}}. The trust anchor's identifier is the batch identifier, as described in {{identifying}}. Future mechanisms using the BikeshedCertificate format (see {{proofs}}) MUST similarly define how relying parties determine trust anchor identifiers.

As even a single validity window results in `validity_window_size` trust anchors, sending all trust anchors in the `trust_anchors` extension would be prohitively large in most cases. Instead, relying parties SHOULD use the retry mechanism described in {{Section 4.3 of !I-D.ietf-tls-trust-anchor-ids}} and the DNS hint described in {{Section 5 of !I-D.ietf-tls-trust-anchor-ids}}.

[[TODO: We could reduce the reliance on DNS by adding https://github.com/davidben/tls-trust-expressions/issues/62, either in this draft or the main trust anchor IDs draft.]]

The authenticating party's list of candidate certification paths (see {{Section 3.3 of !I-D.ietf-tls-trust-anchor-ids}}) is extended to carry both X.509 and BikeshedCertificate credentials. The two types of credentials MAY appear in any relative preference order, based on the authenticating party's policies. Like an X.509 credential, a BikeshedCertificate credential also has a CertificatePropertyList (see {{Section 3.1 of !I-D.ietf-tls-trust-anchor-ids}}).

For each of the authenticating party's BikeshedCertificate credentials, the corresponding trust anchor identifier is the `trust_anchor` field in the BikeshedCertificate structure. This differs from X.509 credentials, which require an out-of-band value in the CertificatePropertyList. It is an error for a BikeshedCertificate credential's CertificatePropertyList to contain the `trust_anchor_identifier` property.

The authenticating party then selects certificates as described in {{Section 4.2 of !I-D.ietf-tls-trust-anchor-ids}}. In doing so, it SHOULD incorporate trust anchor negotiation and certificate type negotiation (see {{tls-certificate-type}}) into the selection criteria for BikeshedCertificate-based credentials.

[[TODO: Certificate type negotiation doesn't work right for client certificates. See {{cert-type-problems}}]]

# Deployment Considerations {#deployment-considerations}

## Fallback Mechanisms {#fallback-mechanisms}

Authenticating parties using Merkle Tree certificates SHOULD additionally provision certificates from another PKI mechanism, such as X.509. This ensures the service remains available to relying parties that have not, or are unable to, fetch a sufficiently new validity window.

If the pipeline of updates from the CA to mirrors to relying parties is interrupted, certificate issuance may halt, or newly issued certificates may no longer be usable. When this happens, the optimization in this document may fail, but fallback mechanisms ensure services remain available.

## Rolling Renewal {#rolling-renewal}

When an authenticating party requests a certificate, the CA cannot fulfill the request until the next batch is ready. Once published, the certificate will not be accepted by relying parties until the batch state is mirrored by their respective trusted mirrors, then pushed to relying parties.

To account for this, authenticating parties SHOULD request a new Merkle Tree certificate significantly before the previous Merkle Tree certificate expires. Renewing halfway into the previous certificate's lifetime is RECOMMENDED. Authenticating parties additionally SHOULD retain both the new and old certificates in the certificate set until the old certificate expires. As the new tree hash is delivered to relying parties, certificate negotiation will transition relying parties to the new certificate, while retaining the old certificate for clients that are not yet updated.

## Deploying New Keys {#new-keys}

Merkle Tree certificates' issuance delays make them unsuitable when rapidly deploying a new service and reacting to key compromise.

When a new service is provisioned with a brand new Merkle Tree certificate, relying parties cannot validate the certificate until they have received a validity window containing said certificate. The authenticating party SHOULD, in parallel, also provision a certificate using another PKI mechanism (e.g. X.509). Certificate negotiation will then switch over to serving the Merkle Tree certificate as relying parties are updated.

If the service is performing a routine key rotation, and not in response to a known compromise, the authenticating party MAY use the process described in {{rolling-renewal}}, allowing certificate negotiation to also switch the private key used. This slightly increases the lifetime of the old key but maintains the size optimization continuously.

If the service is rotating keys in response to a key compromise, this option is not available. Instead, the service SHOULD immediately discard the old key and request a more immediate issuance mechanism. As in the initial deployment case, it SHOULD request a Merkle Tree certificate in parallel, which will restore the size optimization over time.

## Batch State Availability {#batch-state-availability}

CAs and mirrors serve an HTTP interface defined in {{publishing}}. This service may be temporarily unavailable, either from service outage or if the service does not meet the consistency condition mid-update. Exact availability requirements for these services are out of scope for this document, but this section provides some general guidance.

If the CA's interface becomes unavailable, mirrors will be unavailable to update. This will prevent relying parties from accepting new certificates, so authenticating parties will need to use fallback mechanisms per {{fallback-mechanisms}}. This does not compromise transparency goals per {{misbehaving-ca}}. However, a CA which is persistently unavailable may not offer sufficient benefit to be used by authenticating parties or trusted by relying parties.

However, if a mirror's interface becomes unavailable, monitors may be unable to check for unauthorized certificates, if the certificates are not available in another mirror. This does compromise transparency goals. This can be partially mitigated by a combination of state being replicated in additional mirrors, a relying party requiring multiple mirrors log a batch (see {{relying-party-policy}}), or a relying party requiring a sufficiently trusted and reliable mirror log a batch.

# Privacy Considerations

The Privacy Considerations described in {{Section 9 of !I-D.ietf-tls-trust-anchor-ids}} apply to its use with Merkle Tree Certificates.

In particular, relying parties that share an update process will fetch the same stream of updates. However, updates may reach different users at different times, resulting in some variation across users. This variation may contribute to a fingerprinting attack {{?RFC6973}}. If the Merkle Tree CA trust anchors are sent unconditionally in `trust_anchors`, this variation will be passively observable. If they are sent conditionally, e.g. with the DNS-mechanism, the trust anchor list will require active probing.

# Security Considerations

## Authenticity {#authenticity}

A key security requirement of any PKI scheme is that relying parties only accept assertions that were certified by a trusted certification authority. This is achieved by the following two properties:

* The relying party MUST NOT accept any validity window that was not authenticated as coming from the CA.

* For any tree head computed from a list of assertions as in {{building-tree}}, it is computationally infeasible to construct an assertion not this list, and some inclusion proof, such that the procedure in {{verifying}} succeeds.

{{relying-party-policy}} discusses achieving the first property.

The second property is achieved by using a collision-resistant hash in the Merkle Tree construction. The `HashEmpty`, `HashNode`, and `HashAssertion` functions use distinct initial bytes when calling the hash function, to achieve domain separation.

## Cross-protocol attacks {#cross-protocol}

Using the same key material in different, incompatible ways risks cross-protocol attacks when the two uses overlap. To avoid this, {{parameters}} forbids the reuse of Merkle Tree CA private keys in another protocol.  A CA MUST NOT generate signatures with its private key, except as defined in {{signing}}, or an extension of this protocol. Any valid signature of a CA's `public_key` that does not meet these requirements indicates misuse of the private key by the CA.

To reduce the risk of attacks if this guidance is not followed, the LabeledValidityWindow structure defined in {{signing}} includes a label string, and the CA's `issuer_id`. Extensions of this protocol MAY be defined which reuse the keys, but any that do MUST use a different label string and analyze the security of the two uses concurrently.

Likewise, key material included in an assertion ({{assertions}}) MUST NOT be used in another protocol, unless that protocol was designed to be used concurrently with the original purpose. The Assertion structure is designed to facilitate this. Where X.509 uses an optional key usage extension (see {{Section 4.2.1.3 of RFC5280}}) and extended key usage extension (see {{Section 4.2.1.12 of RFC5280}}) to specify key usage, an Assertion is always defined first by a SubjectType value. Subjects cannot be constructed without first specifying the type, and subjects of different types cannot be accidentally interpreted as each other.

The TLSSubjectInfo structure additionally protects against cross-protocol attacks in two further ways:

* A TLSSubjectInfo specifies the key type not with a SubjectPublicKeyInfo {{Section 4.1.2.7 of RFC5280}} object identifier, but with a SignatureScheme structure. Where {{RFC8446}} allows an id-rsaEncryption key to sign both `rsa_pss_rsae_sha256` and `rsa_pss_rsae_sha384`, this protocol specifies the full signature algorithm parameters.

* To mitigate cross-protocol attacks at the application protocol {{ALPACA}}, this document requires connections using it to negotiate the ALPN {{!RFC7301}} extension.

## Revocation {#revocation}

Merkle Tree certificates avoid sending an additional signature for OCSP responses by using a short-lived certificates model. Per {{parameters}},  Merkle Tree CA's certificate lifetime MUST be set such that certificate expiration replaces revocation. Existing revocation mechanisms like CRLs and OCSP are themselves short-lived, signed messages, so a low enough certificate lifetime provides equivalent revocation capability.

Relying parties with additional sources of revocation such as {{CRLite}} or {{CRLSets}} SHOULD provide a mechanism to express revoked assertions in such systems, in order to opportunistically revoke assertions in up-to-date relying parties sooner. It is expected that, in most deployments, relying parties can fetch this revocation data and Merkle Tree CA validity windows from the same service.

[[TODO: Is it worth defining an API for Merkle Tree CAs to publish a revocation list? That would allow automatically populating CRLite and CRLSets. Maybe that's a separate document. #41]]

## Transparency

The mechanisms described in {{transparency-ecosystem}} do not prevent unauthorized certificates, but they aim to provide comparable security properties to Certificate Transparency {{?RFC6962}}. Before the relying party accepts a Merkle Tree Certificate, the relying party should have assurance the certificate was published in some form that monitors and, in particular, the subject of the certificate will be able to notice.

### Unauthorized Certificates

If a CA issues an unauthorized Merkle Tree certificate, the certificate will be rejected by the relying party, publicly logged among the relying party's trusted mirrors, or both:

The relying party will only accept the certificate if has been configured with the corresponding tree head (see {{relying-parties}}). For this to happen, the tree head must be in some validity window that satisfied the relying party's policy (see {{relying-party-policy}}), which is expected to only accept validity windows whose contents are publicly logged. For example, if the relying party requires a quorum of trusted mirrors, the certificate will be visible as long as sufficiently many trusted mirrors are correctly operated.

If the certificate did not meet relying party policy because, e.g., the CA withheld publishing the certificate or mirrors could not reach the CA, the certificate may not be publicly visible. However, in that case, the relying party will not trust the corresponding tree head and thus reject the certificate.

This is analogous to Certificate Transparency, but has some differences:

Unlike Certificate Transparency, the mechanisms in this document do not provide the preimages for `subject_info_hash`, only the hashed values. This is intended to reduce serving costs, particularly with large post-quantum keys. As a result, monitors look for unrecognized hashes instead of unrecognized keys. Any unrecognized hash, even if the preimage is unknown, indicates an unauthorized certificate.

This optimization complicates studies of weak public keys, e.g. {{SharedFactors}}. Such studies will have to retrieve the public keys separately, such as by connecting to the TLS servers, or fetching from the CA if it retains the unabridged assertion. This document does not define a mechanism for doing this.

Additionally, accepted Merkle Tree certificates are expected to be immediately publicly visible, rather than after a Maximum Merge Delay (see {{Section 3 of ?RFC6962}}). Relying party policies SHOULD require that certificates be fully mirrored before accepting a tree head. Merkle Tree certificates do not aim to support immediate issuance, as described in {{deployment-considerations}}.

### Misbehaving Certification Authority {#misbehaving-ca}

Although CAs in this document publish structures similar to a Certificate Transparency log, they do not need to function correctly to provide transparency.

A CA could violate the append-only property of its batch state, and present differing views to different parties. Unlike a misbehaving Certificate Transparency log, this would not compromise transparency. Whichever view is presented to the relying party's trusted mirrors at the time of updates determines the canonical batch state for both relying parties and monitors. Certificates that are inconsistent with that view will be rejected by relying parties. If a mirror observes multiple views, the procedure in {{updating-a-mirror}} will prevent conflicting views from overwriting the originally saved view. Instead, the update process will fail and further certificates will not be accepted.

A CA could also sign a validity window containing an unauthorized certificate and feign an outage when asked to serve the corresponding assertions. However, if the assertion list was never mirrored, the tree head will never be pushed to relying parties, so the relying party will reject the certificate. If the assertion list was mirrored, the unauthorized certificate continues to be available to monitors.

As a consequence, when looking for unauthorized certificates that some relying party may accept, monitors SHOULD use tree heads from each of the relying party's trusted mirrors. A monitor MAY skip downloading the contents of a batch if an identical tree head was already checked from another source. Monitors MAY also monitor the CA directly, but this alone is not sufficient to avoid missing certificates if the CA misbehaves.

### Misbehaving Mirror

This document divides CA and mirror responsibilities differently from how {{?RFC6962}} divides CA and Certificate Transparency log responsibilities. The previous section describes the implications of a failure to meet the log-like responsibilities of a CA, provided trusted mirrors are operating correctly.

For the remainder of log-like responsibilities, a relying party's policy (see {{relying-party-policy}}) trusts its choice of mirrors to, together, ensure the validity windows it uses are consistent with what monitors observe. If untrustworthy, a malicious mirror and CA could collude to cause a relying party to accept an unauthorized certificate not visible to monitors. If the relying party requires a quorum of trusted mirrors, all or most of the mirrors must collude to succeed in this attack.

## Security of Fallback Mechanisms

Merkle Tree certificates are intended to be used as an optimization over other PKI mechanisms. More generally, certificate negotiation allows relying parties to support many kinds of certificates, to meet different goals. This document discusses the security properties of Merkle Tree certificates, but the overall system's security properties depend on all of a relying party's trust anchors.

In particular, in relying parties that require a publicly auditable PKI, the supported fallback mechanisms must also provide a transparency property, either with Certificate Transparency {{RFC6962}} or another mechanism.

# IANA Considerations

IANA is requested to create the following entry in the TLS Certificate Types registry {{!RFC8447}}. The "Reference" column should be set to this document.

| Value | Name       | Recommended |
|-------|------------|-------------|
| TBD   | `Bikeshed` | TBD         |
{: title="Additions to the TLS Certificate Types Registry"}

[[ TODO: Define registries for the enums introduced in this document. #42]]

* SubjectType

* ClaimType

--- back

# Examples

## (Abridged)Assertions

The following is an Assertion claiming `example.com` for
a TLS subject with Ed25519 public key
`c5d2080fa9a489a226b58166dad00be8120931a769c9c6f1f8eefafc38af9065`.

~~~
00000024 08070020 c5d2080f a9a489a2 26b58166 dad00be8 120931a7 69c9c6f1
f8eefafc 38af9065 00120000 000e000c 0b657861 6d706c65 2e636f6d
~~~

The corresponding AbridgedAssertion:

~~~
00000022 0807d8e2 c44fc82e 175e5698 b1c25324 6c9a996f c37bad29 fd59b6aa
838b0a93 0b000012 0000000e 000c0b65 78616d70 6c652e63 6f6d
~~~

Next, we have an Assertion claiming `*.example.com`, `192.0.2.37`,
`192.0.12.0`, `198.51.100.60` and `203.0.113.0` for
a TLS subject with RSASSA-PSS public key with modulus `264851…51544459`
and exponent 65537.

~~~
00000112 0804010e 3082010a 02820101 00d1cd9c d613c050 929e6418 14b4957c
40f30d07 0927f653 bde7054c 06d53a89 36228b70 72fad4db a186c379 7e00300b
a5b6de8e 7ab3fed4 cb5a537e 7674916a 130a0435 664428a9 7f1983b7 e028b9ab
f24700de 1d6478c9 ae361176 daa64c2f 89b42ec0 270add68 85323401 35d22724
c7bd8f65 075b25b8 96a89ab8 2a2b2194 49b029b8 97e130dc dc96fce1 37351f2b
7a28f1d0 7b710afb 2c796211 d9ba1feb 43d30810 63f19afd b7ba2ab0 e19fd008
e719491d d10ed235 5d4790f0 3039e3a3 31aa2644 2d656716 ebe710f2 4260599a
2d082db1 eccfaa8f f51cfb8e 3dfca0eb e1af59c2 f007b35e 02b0582f 50090018
b78a6b06 c0188ab3 514d60d6 6243e017 8b020301 00010028 0001000e 000c0b65
78616d70 6c652e63 6f6d0002 00120010 c0000225 c0000c00 c633643c cb007100
~~~

The corresponding AbridgedAssertion:

~~~
00000022 08049a04 087a4d52 033a0a20 04333359 ccf29703 25684c5f a96f1ca1
35cb2ab1 f2670028 0001000e 000c0b65 78616d70 6c652e63 6f6d0002 00120010
c0000225 c0000c00 c633643c cb007100
~~~

# TLS Certificate Type Negotiation Challenges {#cert-type-problems}

[[TODO: We may need a new TLS certificate types extension, either in this document or a separate one. For now, this section just informally describes the problem. #18 ]]

The server certificate type is negotiated as follows:

* The client sends `server_certificate_type` in ClientHello with accepted certificate types.

* The server selects a certificate type to use, It sends it in `server_certificate_type` in EncryptedExtensions.

* The server sends a certificate of the server-selected type in Certificate.

This model allows the server to select its certificate type based on not just `server_certificate_type`, but also other ClientHello extensions like `certificate_authorities` or `trust_anchors` ({{!I-D.ietf-tls-trust-anchor-ids}}). In particular, if there is no match in `trust_anchors`, it can fallback to X.509, rather than staying within the realm of BikeshedCertificate.

However, the client certificate type is negotiated differently:

* The client sends `client_certificate_type` in ClientHello with certificates it can send

* The server selects a certificate type to request. It sends it in `client_certificate_type` in EncryptedExtensions.

* The server requests a client certificate in CertificateRequest

* The client sends a certificate of the server-selected type in Certificate.

Here, the client (authenticating party) does not select the certificate type. The server (relying party) does. Moreover, this selection is made before the client can see the server's `certificate_authorities` or `trust_anchors` value, in CertificateRequest. There is no opportunity for the client to fallback to X.509.

The `cert_types` extension behaves similarly, but additionally forces the client and server types to match. These extensions were defined when TLS 1.2 was current, but TLS 1.3 aligns the client and server certificate negotiation. Most certificate negotiation extensions, such as `certificate_authorities` or `compress_certificate` {{?RFC8879}} can be offered in either direction, in ClientHello or CertificateRequest. They are then symmetrically accepted in the Certificate message.

A more corresponding TLS 1.3 negotiation would be to defer the client certificate type negotiation to CertificateRequest, with the server offering the supported certificate types. The client can then make its selection, taking other CertificateRequest extensions into account, and indicate its selection in the Certificate message.

Two possible design sketches:

### Indicate in First CertificateEntry

We can have the authenticating party indicate the certificate type in an extension of the first CertificateEntry. One challenge is the extensions come after the certificate, so the relying party must seek to the `extensions` field independent of the certificate type. Thus all certificate types must be updated to use a consistent `opaque cert_data<0..2^24>` syntax, with any type-specific structures embedded inside.

RawPublicKey and X509 already meet this requirement. OpenPGP and Bikeshed need an extra length prefix.

### Change Certificate Syntax

Alternatively, we can negotiate an extension that changes the syntax to Certificate to:

~~~
struct {
    CertificateType certificate_type;
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
~~~

The negotiation can be:

* Client sends its accepted certificate types in ClientHello. Offering this new extension also signatures it is willing to accept the new message format. Unlike the existing extensions, an X.509-only client still sends the extension with just X509 in the list.

* Server, if it implements the new syntax, acknowledges the syntax change with an empty extension in EncryptedExtensions. (It doesn't indicate its selection yet.)

* If both of the above happen, Certificate's syntax has changed. Server indicates its selection with the `certificate_type` field

* Server can also send this extension in CertificateRequest to offer non-X.509 certificate types

* Client likewise indicates its selection with the `certificate_type` field.

This is a bit cleaner to parse, but the negotiation is more complex.

# Acknowledgements
{:numbered="false"}

This document stands on the shoulders of giants and builds upon decades of work in TLS authentication and X.509. The authors would like to thank all those who have contributed over the history of these protocols.

The authors additionally thank Bob Beck, Ryan Dickson, Nick Harper, Dennis Jackson, Ryan Sleevi, and Emily Stark for many valuable discussions and insights which led to this document. We wish to thank Mia Celeste in particular, whose implementation of an earlier draft revealed several pitfalls.

# Change log
{:numbered="false"}

> **RFC Editor's Note:** Please remove this section prior to publication of a
> final version of this document.

## Since draft-davidben-tls-merkle-tree-certs-00
{:numbered="false"}

- Simpify hashing by removing the internal padding to align with block size. #72

- Avoid the temptation of floating points. #66

- Require `lifetime` to be a multiple of `batch_duration`. #65

- Rename window to validity window. #21

- Split Assertion into Assertion and AbridgedAssertion. The latter is used in the Merkle Tree and HTTP interface. It replaces `subject_info` by a hash, to save space by not serving large post-quantum public keys. The original Assertion is used everywhere else, including BikeshedCertificate. #6

- Add proper context to every node in the Merkle tree. #32

- Clarify we use a single `CertificateEntry`. #11

- Clarify we use POSIX time. #1

- Elaborate on CA public key and signature format. #27

- Miscellaneous changes.

- Replace the negotiation mechanism with TLS Trust Anchor Identifiers.

- Switch terminology from "subscriber" to "authenticating party".

- Use <1..2^24-1> encoding for all certificate types in the CertificateEntry TLS message

- Clarify discussion and roles in transparency ecosystem

- Update references
