# MSC45XX: Quantum-secure server key exchange and revised federation semantics

Matrix federation authentication currently uses `ed25519`. Quantum computers can
theoretically reverse engineer private keys using Shor's algorithm, breaking
elliptic-curve and RSA schemes. A sufficiently capable attacker might eventually
intercept, decrypt, and manipulate these requests as if they were insecure HTTP.
They could broadly misrepresent themselves across the network as another entity.

This MSC is the first step of the post-quantum migration: it defines the Falcon
post-quantum signature primitive for Matrix, establishes a provisional mechanism
of distributing post-quantum server signing keys across the federation, and
provides the onboarding ramp for upgrading server-to-server HTTP authentication
to quantum-resistant standards. It deliberately makes **no changes to events,
PDUs, or room versions.** Every mechanism in this proposal can be deployed
immediately by any server — zero impact on rooms, clients, or legacy federation.

This MSC is also the compatibility anchor for Matrix's first deployed
post-quantum signing keys: it pins the exact FIPS 206 revision, encodings, and
signing operation that every subsequent post-quantum MSC builds on by reference,
and it sets the implementation-quality bar below which production FN-DSA keys
must not be published. The associated normative requirements are specified in
[Implementation conformance](#implementation-conformance). Where relevant, this
MSC incorporates cleanup from MSC4499, including FN-DSA short IDs being
hash-derived and notaries indexing keys by their canonical fingerprints.

PQC PDU signing and the co-requisite room version upgrade will be addressed in a
companion proposal (working draft: MSC 45YY) that builds on the primitives
defined here. E2EE device and cross-signing key management and migration can
likewise be addressed in follow-up MSCs (working draft: MSC 0F00).

## Proposal

<!-- Read marker.  -->

This MSC introduces `fn-dsa-512`, a 128-bit secure lattice-based signature
scheme specified by the
[NIST FIPS 206 initial public draft](https://csrc.nist.gov/pubs/fips/206/ipd)[^1],
as the post-quantum signature scheme for Matrix. FN-DSA (Falcon)[^3] was
selected by NIST for small signatures and fast verification — both critical for
high-throughput federation.

### Algorithm (`fn-dsa-512`)

This MSC proposes a single, unified signature scheme. Offering ML-DSA
(Dilithium) as a parallel or negotiable alternative would forfeit the reason for
choosing Falcon in the first place — small signatures and keys — because every
verifier would have to implement, audit, and accept the larger scheme anyway,
and algorithm negotiation itself may create a downgrade surface. One mandatory
scheme; alternatives are discussed in [Alternatives](#alternatives).

| Algorithm    | NIST Level  | PubKey    | Signature  | Performance/Timing                                                    | Use Case                                            |
| ------------ | ----------- | --------- | ---------- | --------------------------------------------------------------------- | --------------------------------------------------- |
| `fn-dsa-512` | I (128-bit) | 897 bytes | ~666 bytes | Keygen: ~10 ms<br>Sign: ~5 ms<br>Verify: ~0.1 ms<br>PoW verify: ~1 ms | HTTP transport (this MSC); PDU signing (future MSC) |

**Why NIST Level I.** Matrix event IDs and content hashes use SHA-256, whose
classical collision resistance (Birthday Paradox) caps out around ~128 bits
regardless of signature strength. Carrying a higher-category signature (e.g.
Level III/V ML-DSA or SLH-DSA) over identifiers that already bottom out at ~128
bits buys the system as a whole little: the weaker link sets the ceiling. Note
that hash collision resistance and signature unforgeability are distinct
security properties — this is a deployment tradeoff, not a formal security
reduction, and it is scoped to identity/event-integrity parity, not to this
MSC's transport signatures specifically. For `X-Matrix-PQC` itself, the
independent and sufficient justification is size and speed: FN-DSA-512's
897-byte keys and ~666-byte signatures are attached to every federation request,
where a Level III/V scheme's larger keys and signatures would add material
bandwidth cost for no corresponding gain given the identifier ceiling above.
Should Level I confidence erode, the
[Compatibility and upgrade classes](#compatibility-and-upgrade-classes) section
already provides the escape hatch: a higher-level scheme ships as a Major change
under a new algorithm identifier.

FN-DSA is a signature scheme. Cuckoo Cycle is proof-of-work network gate. The
proof-of-work binding is defined separately below, where verification is
intentionally cheap relative to proof generation.

Homeservers that support this MSC MUST support `fn-dsa-512` for server signing
key publication, self-signing, and federation transport authentication. They
MUST further conform to the exact confirmation scheme or verification list
defined in this proposal (the same checklist every other server will use).

#### Implementation conformance

Implementations MUST generate FN-DSA keys, perform discrete Gaussian sampling,
and produce FN-DSA signatures using side-channel-resistant, constant-time
techniques[^4]<sup>,</sup>[^5]. Implementations MUST NOT publish production
FN-DSA keys generated by variable-time, unaudited, or non-conformant FN-DSA
implementations — key generation and signing are where Falcon's known
implementation weaknesses lie[^6]<sup>,</sup>[^7]. Verification involves no
secret data and carries no side-channel risk and no constant-time requirement.

Different libraries may interoperate, but only if they implement the exact FIPS
206 revision, encodings, and signing operation specified by this MSC (see
[Pre-finalization deployment guidance](#pre-finalization-deployment-guidance)).
Subtle differences in implementation detail an lead to network divergence, so
implementations SHOULD coalesce around a common, agreed standard.

> **Note:** For readability, this proposal uses the intended stable identifier
> `fn-dsa-512` throughout the main text and examples. Unless or until this MSC
> is accepted and merged into the Matrix specification however, implementations
> MUST use the unstable identifier `tk.nutra.msc45xx.fn-dsa-512` in all protocol
> fields (key IDs, signature entries, algorithm names, and meta-data). See
> [Unstable Prefix](#unstable-prefix) for the full mapping.

### Key ID format

Matrix currently identifies keys using the format `algorithm:key_id` (e.g.,
`ed25519:abc123`). This MSC extends the set of recognized algorithm identifiers.
For `fn-dsa-512`, the `key_id` component is a hash-derived short ID:

| Key Algorithm | Description                  | Key Reference Format (stable) |
| ------------- | ---------------------------- | ----------------------------- |
| `ed25519`     | Existing Ed25519 (unchanged) | `ed25519:<key_id>`            |
| `fn-dsa-512`  | FN-DSA at NIST Level I       | `fn-dsa-512:<short_id>`       |

For `fn-dsa-512`, the `short_id` component MUST be the first 16 base64url
characters of the canonical full key ID digest `key_id_sha256`, without padding.
The canonical full key ID digest is:

```text
key_id_sha256 = SHA-256(
    len16("matrix:fn-dsa-512:key-id:v1") ||
    "matrix:fn-dsa-512:key-id:v1" ||
    raw_fn_dsa_512_public_key_bytes
)
```

where `len16(x)` is the two-byte big-endian length of the UTF-8 byte string `x`,
followed immediately by `x`, and the public key bytes are the raw FN-DSA-512
public key byte string as defined by FIPS 206. The context string is the exact
ASCII byte sequence shown above. It exists for hash-domain separation only, so
this digest cannot collide semantically with an unrelated protocol's SHA-256
over the same raw key bytes.

The `short_id` is therefore a pure function of the public key body: it does not
depend on `server_name`. Name-binding for FN-DSA keys comes from the
self-signature, not the `short_id`: the signed `/_matrix/key/v2/server` object
includes `server_name`, so a self-signature is bound to one claimed Matrix
server name rather than being reusable across names (see
[Server signing keys](#server-signing-keys) for the exact-match requirement on
`server_name`). This binds the key to the claimed name within the signed object;
it does not, by itself, prove control of that name's DNS, origin, or TLS
endpoint.

The `short_id` component MUST contain exactly 16 characters from the base64url
alphabet of RFC 4648 §5 (`A-Z`, `a-z`, `0-9`, `-`, and `_`), encoding the first
96 bits of `key_id_sha256`. When processing an FN-DSA public key from
`verify_keys` or `old_verify_keys`, implementations MUST recompute
`key_id_sha256` and the expected hash-derived `short_id` from the advertised
public key bytes. If the advertised `short_id` does not exactly match the
recomputed value, the key response MUST be rejected as malformed. Signature
entries, `X-Matrix-PQC` headers, and PDU signatures that reference a malformed
FN-DSA `short_id` MUST fail verification.

In the exceedingly unlikely event that a server advertises multiple distinct
FN-DSA public key bodies whose tagged digests share the same first 16 base64url
characters, each advertised key body is well-formed for the same derived
`short_id`. This is a hash-prefix collision, not a malformed identifier. A
receiving server MUST retain each colliding key body under its full SHA-256
fingerprint and, when verifying a signature that references the shared
`short_id`, MUST attempt verification against each non-expired candidate key
body for that server and `short_id`. The signature is valid if exactly one
candidate verifies. If no candidate verifies, or if more than one candidate
verifies, verification MUST fail — two distinct advertised key bodies validating
the same signature is cryptographically anomalous and indicates malformed or
adversarial key material, so the rule fails closed. Receiving servers SHOULD
bound the number of colliding key bodies retained per `short_id` (a limit of 4
is RECOMMENDED); key bodies advertised beyond that bound MUST NOT be added to
the candidate set, so that a server cannot inflate its peers' verification work
by advertising manufactured collisions. Note that only the key's owner (or an
attacker holding its signing keys) can introduce such collisions, since key
responses are self-signed; see
[Security considerations](#security-considerations) for the collision cost
analysis.

Except for verified FN-DSA hash-prefix collisions as described above, `short_id`
values MUST be unique within each algorithm namespace on a given server.

For FN-DSA specifically, notaries and caches SHOULD retain `key_id_sha256` (the
full SHA-256 digest above) as the canonical full ID and fingerprint of the key
body. The derived `short_id` is used in on-wire key references and lookup;
`key_id_sha256` is used for collision forensics, deduplication, and canonical
body comparison.

Notaries and caches SHOULD also retain the SHA-256 digest of the raw FN-DSA-512
public key bytes (untagged) as a transfer-detection fingerprint, distinct from
the tagged key-ID fingerprint above. A notary or receiving server that observes
a previously-associated raw FN-DSA public key fingerprint under a second,
different `server_name` MUST NOT attest to that second observation and SHOULD
alert the operator, but MUST NOT evict or invalidate the original association
solely because of the second observation — otherwise an attacker who has stolen
a server's FN-DSA private key could race a forged publication to notaries and
turn key theft into a denial of service against the legitimate owner's key.
Intentional domain migration MUST publish a distinct FN-DSA key for the new
`server_name`; any relationship to the old server name belongs in an explicit
cross-signing or delegation mechanism, not in key reuse.

This `short_id` derivation intentionally uses unpadded base64url because FN-DSA
key references appear in protocol identifiers and may be embedded in URLs or
routing paths. FN-DSA public keys and signatures themselves continue to use
unpadded standard base64 as specified below.

### FN-DSA encoding and signing

This MSC targets FN-DSA-512 (n=512, q=12289) as specified by the FIPS 206
initial public draft. Implementations MUST track the exact FIPS 206 revision
named by this MSC; if the final standard changes encodings or parameters, a
follow-up MSC will reconcile.

**Public key encoding.** The public key is the raw FN-DSA-512 public key byte
string as defined by FIPS 206. It is encoded as unpadded base64 using the
standard RFC 4648 alphabet.

**Signature encoding.** The signature is the raw FN-DSA-512 signature byte
string as defined by FIPS 206. Unlike the original Falcon submission which used
variable-length signatures, FIPS 206 mandates a fixed-length encoding (padded
with zeros). For FN-DSA-512, the signature is exactly 666 bytes. Implementations
MUST reject signatures of any other length. Signatures are encoded as unpadded
base64 using the standard RFC 4648 alphabet.

**Signing operation.** The message signed is the UTF-8 byte sequence of the
Matrix Canonical JSON representation of the object after removing `signatures`
and `unsigned`, consistent with existing Matrix signing conventions. FN-DSA is
invoked in pure (non-prehash) mode with an empty context string. Implementations
MUST reject non-canonical public key and signature encodings.

These encoding and signing rules are the normative definition of `fn-dsa-512`
for the entire Matrix protocol; MSC 45YY (PDU signing) and MSC 0F00 (E2EE) build
on them by reference.

### Server signing keys

The `GET /_matrix/key/v2/server` response includes both key types:

```json
{
    "server_name": "example.com",
    "verify_keys": {
        "ed25519:auto": {
            "key": "<unpadded-base64-ed25519-pubkey>"
        },
        "fn-dsa-512:5FQ2xg4sWqj3Kp9N": {
            "key": "<unpadded-base64-fn-dsa-512-pubkey>",
            "fips_206_revision": "ipd-2025-08",
            "claims": ["constant-time-keygen", "constant-time-signing"]
        }
    },
    "old_verify_keys": {
        "fn-dsa-512:Rd3x2U9cQK8mV4sA": {
            "key": "<unpadded-base64-fn-dsa-512-pubkey>",
            "expired_ts": 1798761600000,
            "fips_206_revision": "ipd-2025-08",
            "claims": ["constant-time-keygen", "constant-time-signing"]
        }
    },
    "signatures": {
        "example.com": {
            "ed25519:auto": "<base64-ed25519-signature>",
            "fn-dsa-512:5FQ2xg4sWqj3Kp9N": "<base64-fn-dsa-512-signature>"
        }
    },
    "valid_until_ts": 1798848000000
}
```

FN-DSA public keys are encoded as unpadded base64. Servers SHOULD begin
publishing FN-DSA keys immediately, to pre-distribute public keys across the
federation ahead of any downstream use (transport authentication in this MSC;
PDU signing in MSC 45YY). Every such publication, including the very first one,
requires a valid proof-of-work as specified in
[Key publication Proof-of-Work](#key-publication-proof-of-work); this is
unconditional and applies before any of the trust-model discussion below.
Pre-distribution narrows the TOFU exposure window described in
[Server key trust model](#server-key-trust-model): a server whose FN-DSA key is
observed, verified, and cached _before_ a quantum adversary exists is protected
for as long as that specific key stays in use and uncompromised. That protection
does not automatically survive a key _replacement_ — see
[Security considerations](#security-considerations).

FN-DSA keys are distributed as self-signed key objects: the server signs the
`/_matrix/key/v2/server` object containing both `server_name` and its own public
key in the `signatures` field, and receivers verify that self-signature before
trusting the key. A self-signature made for one `server_name` MUST NOT be
accepted for any other `server_name`; implementations MUST use the exact Matrix
`server_name` for this comparison, and MUST NOT accept parent-domain,
registrable-domain, wildcard, or suffix-equivalent matches. This exact-match
self-signature check binds the key to one claimed Matrix server name (see
[Key ID format](#key-id-format)); it does not, by itself, prove current control
of that name's DNS, origin, or TLS endpoint.

FN-DSA key objects MAY include implementation metadata. The `fips_206_revision`
field SHOULD be present before FIPS 206 finalization. The `claims` field is a
list of auditable implementation claims such as `constant-time-keygen` and
`constant-time-signing`. Because Matrix signatures cover the server-key response
after removing only `signatures` and `unsigned`, this metadata is covered by the
FN-DSA self-signature when present. Verifiers and notaries MUST treat these
fields as policy metadata only; they are not cryptographic proof that key
generation or signing was constant-time. Implementations SHOULD NOT publish
exact library names, versions, host details, CPU features, or build fingerprints
unless the operator explicitly opts in.

#### Server key trust model

Once a server publishes an FN-DSA signing key, the `/_matrix/key/v2/server`
response MUST include an FN-DSA self-signature in the `signatures` field
alongside the existing Ed25519 signature. The `key_id` component of that
signature entry MUST be an FN-DSA `short_id` derived from the FN-DSA public key
body as specified in [Key ID format](#key-id-format). Receiving servers MUST
verify this self-signature before trusting the FN-DSA key.

Initial FN-DSA key discovery is trust-on-first-use (TOFU): it is authenticated
by the existing Matrix server-key trust model (Ed25519 signatures and/or notary
attestation). The FN-DSA self-signature proves possession of the FN-DSA private
key for the published public key and binds that key to the claimed `server_name`
inside the signed object; it does not independently prove domain, origin, or TLS
control. Those properties remain exactly those supplied by the existing Matrix
server-key trust model at fetch time. First-use discovery is not post-quantum
secure against an attacker who has already compromised or quantum-derived the
server's Ed25519 signing key before the FN-DSA key was observed. Post-quantum
protection for server identity applies to traffic authenticated under a cached
FN-DSA key for as long as that key stays in use and uncompromised; it does not
extend across a key _replacement_, since replacement publication in this MSC is
authenticated solely by the existing Ed25519 trust model — see
[Security considerations](#security-considerations) for the resulting
limitation.

FN-DSA key publication does not require a post-quantum-secure HTTP transport
layer. This is intentional: requiring PQC transport before FN-DSA keys are
distributed would make the migration circular. In typical deployments, the
`/_matrix/key/v2/server` response may still traverse ordinary TLS termination
such as nginx using classical certificate authentication and classical key
agreement; such transport is not post-quantum secure. The security property of
this MSC therefore comes from Matrix-layer self-signatures and post-first-use
FN-DSA caching, not from assuming that the first HTTP fetch was PQ-secure.
Servers SHOULD use PQC-capable TLS and `X-Matrix-PQC` authentication for key
refreshes when available, but transport protection is not a substitute for
verifying FN-DSA self-signatures and enforcing the hash-derived `short_id` rules
below.

Replacement key publication follows the normal Matrix server-key model: a key
response MUST include an FN-DSA self-signature in `signatures`, the receiving
server MUST verify that self-signature, a valid proof-of-work MUST accompany the
publication as specified in
[Key publication Proof-of-Work](#key-publication-proof-of-work), and the
advertised `short_id` MUST match the hash-derived `short_id` computed from the
public key body. If the response is well-formed and authenticates under the
existing Matrix server-key trust model (Ed25519 signatures and/or notary
attestation), the receiving server caches the new key body. This MSC does not
add any requirement that a replacement key be signed by a prior FN-DSA key.

#### Key publication Proof-of-Work

Homeservers and notaries that support this MSC MUST require a valid
proof-of-work proof for every FN-DSA key publication event — the initial
publication of a server's first FN-DSA key and every subsequent rotation —
before accepting or attesting to that key. This requirement is unconditional:
there is no exemption for TOFU, notary-sourced, or otherwise-trusted
publications, and no implementation-level opt-out. A receiving server or notary
MUST reject an FN-DSA key publication that lacks a valid proof for the
`fn-dsa-key-publication` resource below, regardless of whether the accompanying
Ed25519/notary authentication is otherwise valid.

```json
{
    "algorithm": "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256",
    "challenge": "<unpadded-base64url-random>",
    "expires_ts": 1798848000000,
    "resource": {
        "action": "fn-dsa-key-publication",
        "server_name": "example.com",
        "key_id_sha256": "<unpadded-base64url-sha256>",
        "key_metadata_sha256": "<unpadded-base64url-sha256>",
        "claims": ["constant-time-keygen", "constant-time-signing"],
        "fips_206_revision": "ipd-2025-08"
    }
}
```

The `challenge` value MUST contain at least 128 bits of entropy from a
cryptographically secure source. The `resource.key_id_sha256` field MUST
correspond to the advertised FN-DSA public key body, and the enclosing key's
advertised `short_id` MUST equal the first 16 base64url characters of
`resource.key_id_sha256`. `resource.server_name` MUST correspond to the
`server_name` of the enclosing key response. If any value does not match, the
proof MUST be rejected without evaluating the puzzle.

The optional `resource.key_metadata_sha256` field is the SHA-256 digest of the
Canonical JSON representation of the corresponding FN-DSA key object from
`verify_keys` or `old_verify_keys`, including its implementation metadata. The
optional `resource.claims` and `resource.fips_206_revision` fields mirror
selected metadata into the proof-of-work resource for notary policy and operator
diagnostics. These fields can be bound into the proof-of-work challenge, but
they do not cryptographically prove that the FN-DSA key was generated or used
with constant-time code, nor do they prove domain, origin, or TLS ownership at
the time the work was performed. Verifiers and notaries MUST treat them as
policy metadata only.

**Graph derivation.** A given challenge graph contains a 42-cycle only with some
probability, so the prover iterates a nonce:

```text
graph_seed(nonce) = SHA-256(
    canonical_json(challenge_object) || uint64_le(nonce)
)
```

where `canonical_json` is Matrix Canonical JSON serialization,
`uint64_le(nonce)` is the prover-chosen nonce (`0 ≤ nonce < 2^64`) as 8
little-endian bytes, and `||` is byte-string concatenation. The 32-byte
`graph_seed` is interpreted as four little-endian 64-bit words `k0..k3` forming
the SipHash-2-4 key. The bipartite graph has `2^29` edges and `2^29` nodes in
each partition. Edge `i` (for `0 ≤ i < 2^29`) connects:

```text
u(i) = siphash-2-4(k0..k3, 2i)     mod 2^29   (partition U)
v(i) = siphash-2-4(k0..k3, 2i + 1) mod 2^29   (partition V)
```

A valid proof is a set of 42 edge indices whose edges form a single cycle of
length 42 in this graph (alternating between partitions, visiting 21 distinct
nodes in each, with no repeated edges).

**Timing target.** The `42-29` parameterization targets roughly 10-15 seconds of
_expected_ (average) solve time on the reference implementation described in
[Implementation guidance](#implementation-guidance), running on commodity server
hardware. This is a target for parameter selection, not a guarantee on
individual attempts: because a randomly seeded graph contains a 42-cycle only
with some probability, realized solve time is stochastic — the prover retries
with new nonces until a solvable graph is found, so any single attempt may
finish well under or well over the target. Verifiers MUST NOT reject a proof for
arriving unusually quickly or slowly; the only time bound enforced is
`expires_ts`. Implementations calibrating a different deployment's expected
solve time MUST NOT do so by changing `edge_bits` without minting a new,
explicitly identified algorithm profile (see
[Compatibility and upgrade classes](#compatibility-and-upgrade-classes)) —
`tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256` names one fixed
parameterization so that all conforming implementations impose the same cost.

The proof response is:

```json
{
    "algorithm": "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256",
    "challenge": "<unpadded-base64url-random>",
    "nonce": 8137226,
    "solution": [123, 456, 789, "..."]
}
```

(The example `solution` is truncated for illustration.) The `solution` array
MUST contain exactly 42 unsigned integer edge indices in strictly increasing
order (the canonical form of the edge set). Each edge index MUST be less than
`2^29`, and `nonce` MUST be an integer in `[0, 2^64)`. Verification MUST reject
duplicate, unsorted, out-of-range, or non-integer entries before evaluating the
Cuckoo Cycle proof; it then recomputes `graph_seed(nonce)`, derives the 84
endpoints of the 42 supplied edges, and checks that they form a single 42-cycle.
The challenge MUST be rejected if `expires_ts` has passed or if the `challenge`
value was not issued by the verifier.

#### Notary expectations and key validity

Key notaries (`/_matrix/key/v2/query`) MUST include FN-DSA keys and their
corresponding signatures in responses when present on the queried server.
Notaries MUST validate the remote server's FN-DSA self-signature for the queried
`server_name` — and MUST recompute and validate the hash-derived `short_id`
against the advertised key body, and MUST verify a valid proof-of-work as
specified in [Key publication Proof-of-Work](#key-publication-proof-of-work) —
before attesting to the key; if any check fails, the notary MUST NOT include
that FN-DSA key in its response. Notary responses are themselves signed objects;
notaries that support this MSC MUST include FN-DSA signatures on their
responses.

##### Notary observations

Notaries MAY include `notary_observations` records describing how they observed
an FN-DSA key. These records are signed provenance metadata: they let operators
and later auditors verify that a named notary claims to have fetched a specific
server key over HTTPS at a specific time and under a specific TLS certificate
context.

Notary observations are strictly advisory. They are not a substitute for Matrix
server-key validation and MUST NOT change acceptance semantics.

```json
{
    "notary_observations": [
        {
            "notary_server_name": "notary.example",
            "observed_server_name": "example.com",
            "observed_at": 1798848000000,
            "fetch_uri": "https://example.com/_matrix/key/v2/server",
            "transport": "https",
            "tls": {
                "leaf_spki_sha256": "<unpadded-base64url-sha256>",
                "leaf_cert_sha256": "<unpadded-base64url-sha256>",
                "tls_13_provenance": {
                    "transcript_hash_algorithm": "sha256",
                    "handshake_transcript_hash": "<unpadded-base64url-hash>",
                    "certificate_verify_signature_scheme": "ecdsa_secp256r1_sha256",
                    "server_certificate_verify_signature": "<unpadded-base64url-signature>"
                }
            },
            "key_id_sha256": "<unpadded-base64url-sha256>",
            "valid_until_ts": 1798848000000,
            "signatures": {
                "notary.example": {
                    "ed25519:auto": "<base64-ed25519-signature>",
                    "fn-dsa-512:<short_id>": "<base64-fn-dsa-signature>"
                }
            }
        }
    ]
}
```

The observation signature input is the following byte string:

```text
len16("matrix:notary-key-observation:v1") ||
"matrix:notary-key-observation:v1" ||
len16(notary_server_name) ||
notary_server_name ||
len16(observed_server_name) ||
observed_server_name ||
uint64_be(observed_at) ||
len16(fetch_uri) ||
fetch_uri ||
len16(transport) ||
transport ||
len16(leaf_spki_sha256) ||
leaf_spki_sha256 ||
len16(leaf_cert_sha256) ||
leaf_cert_sha256 ||
uint8(tls_13_provenance_present) ||
if tls_13_provenance_present:
    len16(tls_13_provenance_sha256) ||
    tls_13_provenance_sha256 ||
len16(key_id_sha256) ||
key_id_sha256 ||
uint64_be(valid_until_ts)
```

Formatting definitions:

- `len16(x)` is the two-byte big-endian length of the UTF-8 byte string `x`,
  followed immediately by `x`.
- `uint64_be(ts)` is an unsigned 64-bit big-endian millisecond timestamp.
- `leaf_spki_sha256` is the unpadded base64url-encoded SHA-256 digest of the TLS
  leaf certificate's SubjectPublicKeyInfo DER.
- `leaf_cert_sha256` is the unpadded base64url-encoded SHA-256 digest of the
  full TLS leaf certificate DER observed by the notary during its HTTPS fetch.

Notary and verifier constraints:

- A notary MUST NOT emit an observation unless it performed the described fetch
  itself.
- Verifiers MAY validate and store these records for diagnostics, audits, and
  operator review.
- When validating an observation, a verifier MUST verify the notary's signature
  using the notary's Matrix server signing key.
- When validating an observation, a verifier MUST check that
  `observed_server_name` matches the queried `server_name`.
- When validating an observation, a verifier MUST check that `key_id_sha256` and
  `valid_until_ts` match the observed key response described by the record.

##### TLS 1.3 compact provenance

When `tls_13_provenance` is present, `tls_13_provenance_sha256` is the unpadded
base64url-encoded SHA-256 digest of the following byte string:

```text
len16("matrix:tls13-provenance:v1") ||
"matrix:tls13-provenance:v1" ||
len16(transcript_hash_algorithm) ||
transcript_hash_algorithm ||
len16(handshake_transcript_hash) ||
handshake_transcript_hash ||
len16(certificate_verify_signature_scheme) ||
certificate_verify_signature_scheme ||
len32(server_certificate_verify_signature) ||
server_certificate_verify_signature
```

Formatting definitions:

- `len32(x)` is the four-byte big-endian length of the byte string `x`, followed
  immediately by `x`.
- `handshake_transcript_hash` is the literal cryptographic hash of the TLS 1.3
  Handshake Context up to but excluding the server `CertificateVerify` message,
  as defined by RFC 8446 Section 4.4.1.
- The `handshake_transcript_hash` calculation uses raw TLS Handshake messages
  and excludes TLS record-layer headers.
- This compact construction intentionally does not carry the full handshake
  transcript.

Validation requirements:

- A verifier or auditor validating compact `tls_13_provenance` MUST obtain a TLS
  leaf certificate matching `leaf_cert_sha256` and `leaf_spki_sha256`, for
  example from Certificate Transparency logs, out-of-band certificate evidence,
  or a retained notary audit bundle.
- The verifier MUST verify `server_certificate_verify_signature` according to
  the TLS 1.3 `CertificateVerify` construction for the server context, using the
  obtained leaf certificate's public key, the stated
  `handshake_transcript_hash`, `transcript_hash_algorithm`, and
  `certificate_verify_signature_scheme`.
- Verifiers SHOULD validate that the obtained leaf certificate chains to the
  WebPKI and was valid for `observed_server_name` at `observed_at`, including
  Certificate Transparency evidence where available.

Trust and enforcement boundaries:

- Compact TLS 1.3 provenance proves only that the notary presents evidence that
  the holder of the obtained TLS certificate private key produced a valid
  `CertificateVerify` signature over the stated transcript hash.
- Compact TLS 1.3 provenance does not prove that the HTTP response body was
  faithfully reported by the notary; proving payload fidelity without trusting
  the notary requires a separate TLS transcript-verification system such as
  TLSNotary or DECO.
- Because the compact form carries only the transcript hash, it does not by
  itself let a later auditor inspect or recompute the handshake transcript,
  confirm the SNI value, confirm a notary challenge, or confirm other handshake
  contents.
- A notary that wants independently auditable transcript contents MAY retain or
  publish the full TLS Handshake messages, or equivalent transcript evidence, in
  an out-of-band audit bundle. Such transcript evidence MUST use the same RFC
  8446 Section 4.4.1 Handshake Context definition and MUST exclude TLS
  record-layer headers.
- `tls_13_provenance` remains advisory provenance metadata and MUST NOT affect
  automated key acceptance, event acceptance, or state resolution.
- Non-normatively, compact TLS 1.3 provenance is intended as low-cost forensic
  evidence attached to a signed notary observation. The notary's own signature
  binds the observation timestamp, observed server name, certificate
  fingerprints, key fingerprint, and TLS provenance digest to that notary's
  identity; the TLS evidence then helps distinguish an actual TLS-origin
  observation from a purely invented certificate claim. It is not intended to
  make homeservers parse TLS handshakes, enforce freshness automatically, or
  treat the notary observation as machine-verifiable proof of HTTP payload
  fidelity.

FN-DSA keys follow identical validity semantics to Ed25519 keys: a signature
made by `fn-dsa-512:<short_id>` is valid if the key was valid at the time of the
signed operation. Retired FN-DSA keys appear in `old_verify_keys` with an
`expired_ts`. The `valid_until_ts` field governs cache lifetime for the entire
key response, identically to existing behavior.

Any third-party attestation metadata a server or notary chooses to additionally
track (e.g. historic corroboration records, reputation signals) is advisory
only. Servers MUST NOT reject events, keys, or state based solely on missing,
false, suspicious, flimsy, or otherwise invalid attestation metadata. Such
metadata MUST NOT affect automated verification, acceptance, or state
resolution. If it is to influence behavior at all, that MUST occur only through
explicit admin override or manual operator intervention. Automated state
resolution MUST continue to operate normally, remain backwards compatible with
legacy federation traffic, and converge according to the established network
rules.

Because a server's very first FN-DSA key observation is TOFU and authenticates
only via the existing Ed25519 trust model (see
[Server key trust model](#server-key-trust-model)), it is vulnerable to an
attacker positioned on that specific fetch path — a targeted, localized
man-in-the-middle rather than a global compromise. Implementations MUST NOT
treat contradictory notary observations, by themselves, as sufficient to reject
or invalidate an otherwise valid first observation: doing so would let any
false, compromised, or stale notary create a denial-of-service condition against
legitimate bootstrap. This MSC therefore leaves first-observation acceptance
semantics aligned with the existing Matrix server-key trust model; it does not
define any cross-source consensus or conflict-resolution mechanism for FN-DSA
bootstrap.

### Federation HTTP authentication

Sending servers that support this MSC MUST include the `X-Matrix-PQC` header on
all outgoing federation requests. Unknown HTTP headers are safely ignored per
RFC 9110, so no capability discovery is needed for legacy servers.

```http
Authorization: X-Matrix origin="example.com",destination="matrix.org",key="ed25519:auto",sig="<base64-ed25519-signature>"
X-Matrix-PQC: origin="example.com",destination="matrix.org",key="fn-dsa-512:5FQ2xg4sWqj3Kp9N",sig="<base64-fn-dsa-signature>"
```

The FN-DSA signature MUST be computed over the same JSON signing object used for
existing Matrix federation request authentication (containing `method`, `uri`,
`origin`, `destination`, and `content` when present).

#### Header syntax

`X-Matrix-PQC` uses the same parameter syntax and parsing rules as the existing
`Authorization: X-Matrix` header. Required parameters are `origin`,
`destination`, `key`, and `sig`. Unknown parameters MUST be ignored. Duplicate
parameters or multiple `X-Matrix-PQC` headers render the request authentication
invalid. The `sig` parameter value is the unpadded base64-encoded FN-DSA
signature. Malformed headers (invalid base64, missing required parameters,
unparsable syntax) MUST be treated as absent for enforcement purposes and SHOULD
be logged.

#### Verification and enforcement rules

This MSC introduces the header with **advisory-but-verified** semantics, so that
it can be deployed federation-wide without any flag day:

- Receiving servers that support this MSC MUST verify the `X-Matrix-PQC` header
  whenever it is present and the sending server has a published FN-DSA key.
- A verification failure SHOULD be logged as a warning but MUST NOT cause
  request rejection, provided the Ed25519 `Authorization` header is valid.
- If a receiving server has already cached an FN-DSA key for the sending server
  (see [Server key trust model](#server-key-trust-model)), the absence of the
  `X-Matrix-PQC` header on requests from that server SHOULD be logged as a
  potential downgrade indicator.
- Legacy servers that do not support this MSC ignore the `X-Matrix-PQC` header
  entirely.

Mandatory enforcement is intentionally out of scope here: it is defined by MSC
45YY, which requires a valid `X-Matrix-PQC` header for federation traffic scoped
to PQC-required rooms. Splitting the mechanism (this MSC) from the enforcement
trigger (MSC 45YY) means the header can reach wide deployment before anything
depends on it.

The Ed25519 `Authorization` header remains required on all federation requests
as long as any legacy room version exists in the federation.

### Upgraded connections: PQ session negotiation (future MSC)

The per-request `X-Matrix-PQC` header adds ~888 bytes (base64) of bandwidth
overhead to every federation request. This section defines an OPTIONAL mechanism
for a pair of servers to negotiate a symmetric session key via a post-quantum
KEM (ML-KEM-768, [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) and
amortize that cost by replacing per-request asymmetric signatures with
session-based HMAC authentication — an "upgraded" HTTP connection between two
PQC-capable servers.

Per-request `X-Matrix-PQC` remains the baseline; servers MUST NOT assume peer
support for session negotiation, and MUST fall back to per-request headers when
negotiation is unavailable or a session is rejected. A follow-up MSC will
formally define this standard for ecosystem consistency.

#### Endpoint

```http
POST /_matrix/federation/unstable/tk.nutra.msc45xx/key_exchange
```

**Authentication.** The negotiation request MUST carry a valid Ed25519
`Authorization: X-Matrix` header AND a valid `X-Matrix-PQC` header. Both MUST
verify; otherwise the receiving server MUST reject the request with
`401 M_FORBIDDEN`. Authenticating the initialization request with existing
server signing keys prevents origin spoofing of the KEM handshake.

**Rate limiting.** This endpoint SHOULD be rate-limited. Servers MUST return
`429 M_LIMIT_EXCEEDED` when rate limits are exceeded. Guest access is not
applicable (server-to-server API).

**Request body:**

```json
{
    "algorithm": "ml-kem-768",
    "encapsulation_key": "<unpadded-base64-ml-kem-768-ek>"
}
```

The `encapsulation_key` is an ephemeral ML-KEM-768 encapsulation key generated
by the initiating server for this session only. Ephemeral keys MUST NOT be
reused across sessions. The responder MUST perform the encapsulation-key input
validation required by FIPS 203[^8] (length and modulus checks) before
encapsulating, rejecting invalid keys with `400 M_INVALID_PARAM`.

**Response body (`200 OK`):**

```json
{
    "session_id": "<opaque-string>",
    "ciphertext": "<unpadded-base64-ml-kem-768-ciphertext>",
    "expires_ts": 1798848000000
}
```

The `session_id` is an opaque string of 1–128 characters from the base64url
alphabet, generated by the responder with at least 128 bits of entropy from a
cryptographically secure source. Sessions SHOULD be short-lived (an `expires_ts`
no more than 24 hours in the future is RECOMMENDED); initiators SHOULD
renegotiate before expiry to avoid falling back mid-traffic.

The responder encapsulates against the initiator's ephemeral key, producing the
ciphertext and the 32-byte shared secret `ss` defined by ML-KEM. Both sides
derive the session key using HKDF[^10]:

```text
session_info =
    len16("tk.nutra.msc45xx.session.v1") ||
    len16(origin) ||
    len16(destination) ||
    len16(session_id)

session_key = HKDF-SHA-256(
    IKM = ss,
    salt = "",
    info = session_info,
    L = 32
)
```

Here `||` denotes byte-string concatenation. `len16(x)` is the two-byte
big-endian length of the UTF-8 byte string `x`, followed by `x` itself.
Implementations MUST reject fields whose UTF-8 byte length exceeds 65535 bytes.
The `salt` input to HKDF is the zero-length byte string. The `origin` and
`destination` inputs are exactly the values authenticated in the negotiation
request's `Authorization` and `X-Matrix-PQC` headers (which MUST agree with each
other); a mismatch anywhere yields divergent session keys and a session that
simply never verifies.

**Error responses:**

- `404 M_UNRECOGNIZED` — the receiving server does not support this endpoint.
  The initiator falls back to per-request `X-Matrix-PQC` headers.
- `400 M_INVALID_PARAM` — unsupported `algorithm` or malformed
  `encapsulation_key`.
- `401 M_FORBIDDEN` — transport authentication failed.
- `429 M_LIMIT_EXCEEDED` — rate limited.

#### Session-authenticated requests

While a session is live, the initiating server MAY replace the `X-Matrix-PQC`
header on requests to the responder with:

```http
X-Matrix-PQC-Session: origin="example.com",destination="matrix.org",session="<session_id>",mac="<unpadded-base64-hmac>"
```

where `mac` is `HMAC-SHA-256(session_key, canonical_json(signing_object))` over
the same JSON signing object used for `X-Matrix-PQC`. The Ed25519
`Authorization` header remains required as usual. Verifiers MUST compare MAC
values in constant time. Sessions are unidirectional: only the initiator uses
the session to authenticate requests _to_ the responder. A responder MUST NOT
accept its own issued `session_id` on requests it originates, and the swapped
`origin`/`destination` fields in the signing object make reflected MACs fail
verification in any case.

Sessions are soft state. Either side MAY discard a session at any time (e.g. on
restart, cache pressure, or expiry). If the receiving server does not recognize
or no longer holds the `session_id`, it MUST treat the header as absent for
enforcement purposes; the sender then falls back to per-request `X-Matrix-PQC`
and MAY renegotiate. A valid `X-Matrix-PQC-Session` MAC is equivalent to a valid
`X-Matrix-PQC` signature for all verification and (future) enforcement purposes.

Note that this mechanism provides _authentication amortization only_ — it does
not provide confidentiality (TLS continues to provide transport encryption) and
symmetric MACs do not provide non-repudiation, which transport authentication
does not require. Anti-replay properties are inherited from TLS, identically to
the existing `X-Matrix` scheme.

### Migration

**Phase 1 — Transport & Key Distribution (Immediate, this MSC)** Servers begin
publishing FN-DSA keys via `/_matrix/key/v2/server` and transmitting the
`X-Matrix-PQC` header for server-to-server HTTP authentication, optionally
negotiating upgraded session-authenticated connections. PDUs continue to be
signed exclusively with Ed25519 according to legacy room versions. No room,
event, or client behavior changes.

**Phase 2 — PQC Room Version (MSC 45YY)** A new room version makes `fn-dsa-512`
the sole, authoritative PDU signature scheme and turns `X-Matrix-PQC` transport
verification into a hard requirement for traffic scoped to PQC rooms.

## Potential issues

- **FIPS 206 not yet finalized.** FIPS 206 is in final stages but unpublished as
  of May 2026[^2]. Unstable prefixes allow parameter updates without breaking
  stable identifiers. FIPS 203/204/205 were finalized in August 2024; FIPS 206
  is expected to follow.

- **Falcon's implementation complexity.** FN-DSA key generation and signing
  require side-channel-resistant discrete Gaussian sampling — non-constant-time
  implementations can leak private keys through timing, cache, or power side
  channels. Implementations MUST use an audited FN-DSA library that provides
  constant-time Gaussian sampling and signing. The libraries listed under
  [Implementation guidance](#implementation-guidance) are non-normative
  examples.

- **Key rotation complexity.** Servers must now manage and rotate two
  independent key types. However, Matrix already supports key rotation via
  `old_verify_keys`, and the mechanics are identical for FN-DSA keys.

- **Public key size.** FN-DSA-512 public keys are 897 bytes (vs 32 for Ed25519),
  adding ~1.2 KB per key to `/_matrix/key/v2/server` responses. A modest
  increase in response size.

- **Per-request header overhead.** The `X-Matrix-PQC` header adds ~888 bytes of
  bandwidth per federation request. The optional
  [session negotiation extension](#upgraded-connections-pq-session-negotiation-future-msc)
  amortizes this to a 32-byte-key HMAC per request between supporting peers.

- **Advisory enforcement window.** Until MSC 45YY (or an operator strict mode)
  makes verification mandatory, `X-Matrix-PQC` failures only produce warnings.
  This is deliberate — see [Security considerations](#security-considerations)
  on downgrade.

- **Mandatory proof-of-work latency.** Every FN-DSA key publication — initial
  publication and every rotation — now requires solving a
  [proof-of-work puzzle](#key-publication-proof-of-work) that targets ~10-15
  seconds of expected solve time before the key is accepted or attested to. This
  is a deliberate, unconditional friction cost (see
  [Security considerations](#security-considerations)), not an incidental one;
  operators and automated key-management tooling SHOULD account for this latency
  when scripting key rotation.

## Alternatives

- **ML-DSA (FIPS 204 / Dilithium).** Integer-only arithmetic eliminates FN-DSA's
  side-channel concerns, but ML-DSA-44 signatures exceed 2.4 KB vs FN-DSA's ~666
  bytes. The bandwidth cost materially increases per-request federation
  overhead, and downstream per-event costs in MSC 45YY.

- **SLH-DSA (FIPS 205 / SPHINCS+).** Most conservative (hash-based, no lattice
  assumptions), but 17,088-byte signatures are impractical for per-request
  transport authentication. Potentially useful for long-lived trust anchors in a
  future MSC.

- **Waiting for FIPS 206 finalization.** Delaying extends the vulnerability
  window. Unstable prefixes allow early adoption without committing to final
  identifiers.

- **PQC TLS instead of application-layer auth.** Post-quantum TLS (X25519 +
  ML-KEM hybrid key exchange) is being deployed by CDNs and browsers and
  protects channel confidentiality, but Matrix federation identity is
  authenticated at the application layer via server signing keys, not client TLS
  certificates. Relying on TLS alone would leave server identity —
  `/_matrix/key/v2/server` responses, notary attestations, request origin —
  authenticated only by Ed25519. Application-layer FN-DSA is required
  regardless; PQC TLS is complementary and encouraged.

- **Distributed Symmetric Key Establishment (DSKE).** Information-theoretically
  secure protocols based on pre-shared random data (PSRD) and one-time pads
  eliminate asymmetric cryptography entirely. However, DSKE is catastrophically
  unsuitable for open federation: (1) PSRD is _consumable_ — each authentication
  operation permanently erases key material, requiring gigabytes of pre-shared
  state per server pair vs. FN-DSA's static ~1 KB public key that authenticates
  unlimited requests; (2) symmetric cryptography cannot provide
  _non-repudiation_ — required downstream for PDU signing, where any server must
  independently verify any historical event's authorship; (3) PSRD replenishment
  requires physical delivery (armored USB drives or dedicated QKD fiber), which
  is incompatible with permissionless internet-scale federation. DSKE is
  designed for closed, classified networks; FN-DSA provides the ultimate
  compression — ~1 KB of static text proves a server's identity to the entire
  world with zero consumable state.

## Implementation guidance

FN-DSA libraries (status as of May 2026; FIPS 206 draft submitted August 2025,
final standard expected late 2026–2027[^2]):

| Library                                                                                                                        | Language          | FFI                                | FN-DSA Status                                                | Maturity                                                    | Notes                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------ | ----------------- | ---------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [liboqs](https://github.com/open-quantum-safe/liboqs)                                                                          | C                 | Yes (Python, Rust, Go, Java, .NET) | Round 3 Falcon; FIPS 206 update tracked in issue 2271        | Mature (OQS reference); targets draft, not final FIPS 206   | Reference PQC library. Compiles to WASM via Emscripten. Broadest algorithm coverage.           |
| [liboqs-go](https://github.com/open-quantum-safe/liboqs-go)                                                                    | Go (cgo FFI to C) | Yes (wraps liboqs)                 | Tracks liboqs                                                | Stable; follows liboqs releases                             | Go bindings for liboqs via cgo — the practical path for a Go homeserver implementation.        |
| [oqs](https://crates.io/crates/oqs) / [liboqs-rust](https://github.com/open-quantum-safe/liboqs-rust)                          | Rust (FFI to C)   | Yes (wraps liboqs)                 | Tracks liboqs; v0.11.0 (May 2025)                            | Stable; follows liboqs releases                             | Rust bindings for liboqs. Suitable for conduwuit and Synapse-via-PyO3.                         |
| [pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon)                                                                    | Rust              | No (wraps PQClean C)               | Round 3 Falcon (PQClean); v0.4.1 (Aug 2025)                  | Usable today; FIPS 206 update pending PQClean upstream      | Pure-Rust build wrapper. No system C dependency — simplifies cross-compilation.                |
| [oqs-provider](https://github.com/open-quantum-safe/oqs-provider)                                                              | C (OpenSSL 3.x)   | N/A                                | Experimental Falcon via liboqs; not natively in OpenSSL 3.5+ | Research/testing; not audited for production signing        | OpenSSL provider. Useful for TLS experimentation, not directly for Matrix JSON signing.        |
| [falcon-crypto](https://www.npmjs.com/package/falcon-crypto) / [@btq-js/falcon-wasm](https://github.com/nickthecook/falcon-js) | JavaScript/WASM   | No                                 | Round 3 Falcon (Emscripten of reference C)                   | Community; requires audit for constant-time WASM guarantees | Browser/Node.js. Must verify FIPS 206 alignment and side-channel resistance before production. |

All implementations MUST use side-channel-resistant, constant-time key
generation, Gaussian sampling, and signing operations; constant-time Falcon
techniques are well documented[^4]<sup>,</sup>[^5], and both classical
implementation pitfalls[^6] and recent single-trace power-analysis attacks[^7]
demonstrate why this is a hard requirement rather than a best practice.
Server-side deployments SHOULD prefer native (C/Rust) implementations.
ML-KEM-768 (for the optional session extension) is available in liboqs and,
increasingly, in mainstream TLS libraries following FIPS 203 finalization.

## Security considerations

- **Real-time impersonation.** The primary real-time quantum threat is an
  attacker deriving a server's Ed25519 private key to spoof federation traffic
  and server-key responses. This MSC mitigates the transport half of that vector
  for as long as a server's FN-DSA key itself remains uncompromised:
  `X-Matrix-PQC` requests are signed with FN-DSA, so an attacker who has only
  derived a server's Ed25519 private key — with no other capability — cannot
  forge live federation traffic or get a forged key response accepted. Key
  publication and replacement in this MSC authenticate the same way initial
  publication does: a valid self-signature plus the existing Matrix server-key
  trust model (fetched from the origin over TLS, or via a notary who did) — see
  [Server key trust model](#server-key-trust-model). That combination proves
  only "whoever currently controls this domain's origin, as observed over this
  fetch, produced this key," identical in strength to what web PKI already
  provides for TLS certificates; it does not, and is not intended to, prove
  continuity with any previously-observed key. Consequently, merely deriving a
  private key is not sufficient to hijack a server's identity: the attacker
  additionally needs an active position on a verifier's fetch path (a real-time
  MITM) or control of a notary a verifier relies on — i.e., exactly the
  additional capability already required to impersonate a server under Matrix's
  existing Ed25519-only model. This MSC does not add a new identity-continuity
  guarantee the classical layer never had; it upgrades the signature algorithm
  used within the same trust model. Forged _events_ are addressed by MSC 45YY.

- **TOFU bootstrap window.** Initial FN-DSA key discovery is authenticated by
  Ed25519 and the existing server-key trust model, and is therefore only as
  post-quantum secure as that model's real-time guarantees (see **Real-time
  impersonation** above). This is still an argument for deploying this MSC as
  early and widely as possible: pre-distributing FN-DSA keys means
  `X-Matrix-PQC` traffic is quantum-resistant against passive interception and
  against an attacker who lacks an active fetch-path position, from the moment a
  key is cached. Ordinary TLS termination, including common nginx deployments
  using classical TLS certificates and classical key agreement, does not remove
  this TOFU bootstrap window.

- **Self-signatures and PoW do not prove origin ownership.** The FN-DSA
  self-signature proves possession of the FN-DSA private key and binds the key
  to the claimed `server_name` within the signed object. The mandatory
  proof-of-work binds work to the advertised key material and selected metadata.
  Neither mechanism, by itself, proves current control of the domain's DNS,
  origin, or TLS endpoint at any particular time. Those properties remain those
  of the underlying Matrix server-key trust model used to fetch or attest to the
  key.

- **Downgrade attacks.** During the advisory period, an attacker who can strip
  HTTP headers (i.e. who controls TLS termination or a private key) could
  suppress `X-Matrix-PQC` without causing rejection. Absence-logging narrows
  this; room-scoped mandatory enforcement arrives with MSC 45YY. Ed25519
  `Authorization` remains the floor, so this MSC never _weakens_ existing
  authentication.

- **Timing and power side-channels.** FN-DSA's discrete Gaussian sampler leaks
  private keys via timing analysis if implemented incorrectly, and single-trace
  power analysis of Falcon signing has been demonstrated[^7]. All
  implementations MUST use audited, constant-time libraries (see
  [Implementation guidance](#implementation-guidance)).

- **Hash-derived short ID collisions.** The `short_id` commits to 96 bits of the
  key body's SHA-256 digest (see [Key ID format](#key-id-format)). A second
  preimage against a _specific_ existing `short_id` costs ~2^96 hash evaluations
  (infeasible), but a birthday collision between two freshly generated keys
  costs only ~2^48 — feasible for a motivated party with commodity GPUs.
  Crucially, key responses are self-signed and served by the origin server, so
  only the key's owner (or an attacker already holding its signing keys) can
  place colliding key bodies into circulation: the attack is self-targeting. Its
  worst-case impact is bounded ambiguity handled by the exactly-one-verifies
  rule and the RECOMMENDED candidate cap in [Key ID Format](#key-id-format); it
  cannot make a signature verify under a key the signer does not hold.

- **Proof-of-work is a throttle, not trust.** A valid Cuckoo Cycle[^9] proof
  only spends the prover's resources; it says nothing about the prover's
  legitimacy. The publication gate therefore MUST NOT convert a valid proof into
  key trust. Trust transitions remain governed exclusively by the key validity
  rules above and operator action. This MSC requires the proof unconditionally
  for every FN-DSA key publication (see
  [Key publication Proof-of-Work](#key-publication-proof-of-work)) precisely
  because it does not attempt to distinguish legitimate from illegitimate
  publishers by any other means: the cost is imposed uniformly rather than
  targeted at suspected abuse.

- **Session key hygiene (optional extension).** Session keys are derived from
  ephemeral ML-KEM keys and MUST NOT outlive `expires_ts`. Compromise of a
  session key permits transport-level impersonation toward one peer until expiry
  — bounded by short session lifetimes and by the requirement that negotiation
  itself is FN-DSA-authenticated.

- **Algorithm agility.** The `algorithm:key_id` format provides syntactic
  extensibility for future PQC standards. Deploying a new algorithm still
  requires specification of its identifier, encodings, and verification rules,
  but does not require structural changes to the key formats. If FN-DSA is
  compromised, the unstable prefix can be deprecated and a replacement
  introduced via a follow-up MSC.

- **Key compromise recovery.** Identical to Ed25519: rotate the key, publish the
  old key in `old_verify_keys` with `expired_ts`. This MSC follows the normal
  Matrix server-key model and does not require replacement keys to be signed by
  a previously trusted FN-DSA key. Operators SHOULD still keep offline backups
  of signing keys to support ordinary rotation and incident response.

## Unstable prefix

While this MSC is in development, the following unstable prefixes are used:

| Stable Identifier                                | Unstable Identifier                                          |
| ------------------------------------------------ | ------------------------------------------------------------ |
| `fn-dsa-512` (key algorithm)                     | `tk.nutra.msc45xx.fn-dsa-512`                                |
| `X-Matrix-PQC` (HTTP header)                     | `X-Matrix-PQC` (no prefix needed, custom header)             |
| `X-Matrix-PQC-Session` (HTTP header)             | `X-Matrix-PQC-Session` (no prefix needed, custom header)     |
| `/_matrix/federation/v1/key_exchange` (endpoint) | `/_matrix/federation/unstable/tk.nutra.msc45xx/key_exchange` |

The unstable algorithm prefix is used in `verify_keys` key references,
`signatures` entries, and `X-Matrix-PQC` header `key` parameters. For example,
the `/_matrix/key/v2/server` response would use the unstable algorithm
identifier in FN-DSA key references:

```json
{
    "verify_keys": {
        "tk.nutra.msc45xx.fn-dsa-512:5FQ2xg4sWqj3Kp9N": {
            "key": "<base64-fn-dsa-512-pubkey>"
        }
    }
}
```

Once this MSC is accepted but not yet merged into a released spec version,
implementations SHOULD support both the unstable prefix and the stable
identifier, accepting either.

### Pre-finalization deployment guidance

FIPS 206 has not been finalized as of May 2026. Implementations deploying FN-DSA
before finalization MUST observe the following constraints:

- **All keys are temporary.** FN-DSA keys published under unstable identifiers
  (`tk.nutra.msc45xx.fn-dsa-512`) MUST be treated as provisional. Operators
  SHOULD expect mandatory key rotation if FIPS 206 final changes encodings,
  parameters, or the signing algorithm relative to the draft revision used.
- **Pin a specific draft revision.** Implementations MUST document which FIPS
  206 draft revision they target. Interoperability between implementations
  targeting different draft revisions is not guaranteed.
- **Use unstable algorithm prefixes with hash-derived short IDs.** During the
  draft period, `/_matrix/key/v2/server` key entries and `X-Matrix-PQC` header
  `key` parameters MUST use the unstable algorithm identifier
  (`tk.nutra.msc45xx.fn-dsa-512`) as the prefix, but the suffix MUST still be
  the hash-derived `short_id` derived from the FN-DSA public key body. This
  keeps draft-era key references separate from finalized key references without
  changing how the referenced key body is identified.
- **Rotation on parameter change.** If a subsequent FIPS 206 draft or the final
  standard changes the public key encoding, signature encoding, or algorithm
  semantics, all previously published unstable FN-DSA keys MUST be retired to
  `old_verify_keys` and replaced with keys conforming to the updated
  specification.
- **No production trust assumptions.** During the unstable period, FN-DSA
  signatures provide defence-in-depth but MUST NOT be the sole basis for
  production security decisions. Ed25519 signatures and transport authentication
  remain the authoritative trust anchors until FIPS 206 is finalized and stable
  identifiers are adopted.

### Compatibility and upgrade classes

Future changes to this mechanism MUST use the narrowest compatible rollout class
that preserves verifier safety:

- **Patch changes** add optional metadata or clarify validation without changing
  key ID derivation, signature inputs, encodings, or required verification
  behavior. Examples include adding optional FN-DSA key-object metadata fields
  or additional policy claims. Patch fields MUST be safely ignored by
  implementations that do not understand them.
- **Minor changes** add a compatible extension that requires explicit support by
  both peers, while preserving the baseline behavior in this MSC. Examples
  include a new proof-of-work profile, a new metadata commitment format, or an
  optional session-authentication variant. Minor extensions MUST use distinct
  identifiers and MUST fall back to the mandatory baseline when unsupported.
- **Major changes** alter cryptographic interpretation or break existing
  verification. Examples include changing FN-DSA encodings, signature sizes,
  signing inputs, key ID derivation, or mandatory verification rules. Major
  changes MUST use a new algorithm or profile identifier, publish separate keys
  during migration, and rely on a follow-up MSC or room version before becoming
  mandatory.

## Test vectors

The following vectors are normative for interoperability. They are intended to
eliminate ambiguity in `key_id_sha256` derivation, FN-DSA encoding/signing, and
the Cuckoo Cycle helper functions used by this MSC.

They are generated by `tools/msc45xx-vectors/` in this repository, which emits
the same values from the sibling `gomatrixlib` implementation.

### `key_id_sha256` / `short_id` vector

This vector uses the exact ASCII context string `matrix:fn-dsa-512:key-id:v1`,
prefixed with `len16(context) = 0x001b`, and the public key from the FN-DSA
vector below.

```text
context_ascii = "matrix:fn-dsa-512:key-id:v1"
context_len16_be = 001b
key_id_sha256_hex = 20fd21bc319285ffbbd0fc54ba6c8581d952ac62e671e90f4184a8b425d2db38
key_id_sha256_base64url = IP0hvDGShf-70PxUumyFgdlSrGLmcekPQYSotCXS2zg
short_id = IP0hvDGShf-70PxU
```

### Deterministic FN-DSA-512 sign/verify vector

This vector uses a deterministic entropy stream for reproducibility only. It is
generated by feeding the ASCII seeds below into `SHAKE256` and using the output
as the byte stream for key generation and signing:

```text
keygen_rng_seed_ascii = "msc45xx-fndsa-keygen-seed-v1"
sign_rng_seed_ascii = "msc45xx-fndsa-sign-seed-v1"
message_ascii = "matrix federation post-quantum test vector"
```

Verification of the signature below against the public key and message above
MUST succeed. Verification against the message `tampered` MUST fail.

```json
{
    "private_key_base64": "Wf+vvfAe//AQfuwggPuw/AQQjQdPwBOwe/QQRuwA/vAQPww+/xBQBPQ+x/wfiQBRQg//uQgw+xPR/hgggfQRPfQve+/Qx/hPPAv+gfhAgffRgvBQufAhSPv/x/ABPPhPPugQgRvhfvvRxP/OffQPvAPevQggwPePAAPgvAQwQAPBQA+/vAgBghA/vBfvgBfu/wBPRf/Qxv/RvgRPxvfOgQfgyffyfARgAuwQxQBw/wRvxQhvxPQQPxQgOwfxPNQQAhdwgf//+/xOSBwAgBQPewuhf/fBBgQQg/AxA/hBNgRQgQP/vgPhPwAAPfeAwwgCPvPxA/hw/Phgu/vwBexQOBfBAdwQfAfggfOfv/QvthA/wfw/whgBPBfAiRg/ufRPhiugvffuvuuwvPevfxSPggQQSBCt/QgARwvxRQ//QPAQg/ifAgRBPfPvuwwfvCARAuvdfAewSNgvxg/QvBQvwuuPegvfgQf++BuxvQuQBQi+vyufQ//vf/QAwegQAQgwxPxOgQNvAAAQgBRuQx+ggf/hPPv///AuvvPuwP/vuvfQP/gQP+wyPfQfPwfPg/vvuQwPxvBfffQOhvgvAgfwAQA+vex+wehfyid+xg+xPBvPQOgQQhvAfROhQvfQBPggARfvBfANgxQQOxAPvwQvihPwwAvwPvQQ/QgePxAPvQAO/SAfR/hO/w/QOwgQPROgQvfehevQ/+xxPgP/hBiOgfPNxvfhgOfdgAQOv/PvvgRwPAQf/RN+/fvAQQvQgAxhw+wPhdQ//www/wcuA+QvPQ//+wPwxxBOQvAggSNvAufvxPffO/gAQ/Peu+v//AQ/Pv/h/QPv+gQP/fPPBgAtwQQCvwvQQeu/exARAAQ/eSPwABBfgwQBQwPPP/ee//wv+whwevvvhffhxBPBwP+whf+/BgQfAfQgBgAgP/QP/wfAPgwuvgQQgufQfQw/vQwOvwB/ANvCBQAA+//9/uAfg/fhhQ+QAxghAiAwPgO/xPRAuAv/vwBBQPfO//xwvgOwhf8QGxClDCsZ8BsF7BH8BtwD9PcBLOQXG/rkHSIF2RP8HuhD+hgFD98bxO/w7/r3AtMOBQMn7db68h0K8/70FCvd8eYH+vT9KwDo+wEhCAT68gfl+98D4eYM9e/9FwetDfT0Bu3px/0l7AsMB/oiJfLnFyQEOlEj+vbtBhQu8QI3FwjzCfLqEgva/tglGxQ9Be3v7eHSO9jRG9oYDg4p8Cza/fDxIxTuHAIWzuf++QMI59DY5vz/Ch/p2Q/Pvurs5SMw994AAA/WDA3V8wcP/QAQ/S0DHdf4/OQSQdAB+9wOD/sa7A4C/PD7+/cG87n6+OMH7C7d+QQKz/MRJ+katRL08/gALQT8DgH8EfsBBucf+RMCJDvXKBQB5PAIEfwvFwkR5AkC+x3ezvDa9xUX+/YB2eHlIyEQIh0jCgkgGhX7PgQY9PQNEvn+Ixgd89f1Frr29+X548UOtiPq8AfcAwLK1/ohHP8GDCH8JC0PCfoPAAM9QP8GByQON/sDFP799ggn/QH/Byz98tsFCBgEJMEV8h/n/gES7ikO+CXlGQgCBfnwGQgcDQsM88z86xr14wss9MjjItki0uXw2NADGwvs3eMEyPf99OIX1Sjn6jv1ABQuOR8DHwcC2yMF5PT7Oe3b+uLu8zj3+fEy/inuIf8kGg3uEAsh+xkw/AMIDi0N",
    "public_key_base64": "CUMlDwB0VzdvaT1nEeaTr21DtluYBSy6dktakGJh1K6o/yrYfthHeoRcG1gCURulT9CUkULCZYQvt2SM20hlAVUB7ehqZjN5fpAFoCtera1xaV8PdqnkbRJwXdtUQf770KVQWPjL9Z4ZwVVyVRpC1P41SehABNsDII0eBcJK65yGHKvnVL+RGBS15oG2oNjQazrWx1S6PZkAVMtq1RIoYJcsAeq6tMOvAW8ML3DXpw2mkYQZKYyxIHBOeDULD1dyO/FAQIRYpdsQumjBHCqiypHdSDu1GLOajB9hxNmAaepGnzWyK24RYgn4p+vd4WI6uhnHlJRJQqq6iOwoD38mIZtHqUIsbAn1xJrkAlRQEHUObZ4O5RNuhRIvuSBa5290pigmdeXhwY+VBjCrJ/mrBS5SOE+njyKqc7fVAYntsGoCrA2AVsOqMwCQpoi7tbLP3lBOzbhFLsWnWJTUkpT5MOqPAWvaSp5+5YEIJiRHteTjm8iVsIF4UWDJ7pNk5HaTCXaoslCgq0cZS4JLGXWS60I2RPL5nzaY/obiT543b5H+CdXXKjUgn0rrwRd+ndzpDpABfu4QMvda/jTV9/TJDZmy/ojyBdUPX1J9sruaTl2pkTkwL11asfrGoRSZt77Cl8FqcgOoXcJEGAeE8SUSmOkdICTVEWesNm9CVJUTJxVOttDjLM4Mvd6SyA/sO1KufVlLIwlH4Z7gH6KPPtJnwsEbSaB0OuWbTntY6K4xTghWvr62Md2TkqQ0CzsTS5y/LqHDcayOc85dcA6ENKMiLLb25cEXegc3uSSegmgKISdfzjeEt1ffK/JGLO16a1luUth6Al5Kv0pRuHXf7uKMWFF3jQQ+ojVyU0dhnD6kvlE8IL5zuYoIFqBAT8ruIw1scmmo+YjK4dJhtWXjOgd8JoHYiJ9GFYkJu3n266KjzQioHQTAPCZzNEFq62hkVSvDWnYJsD5QWRJIKzjLadUYmF0pOUUoq46rQMJi6EiyI6KoNuHj461IbUp726whYgOlZ61xmsgGsFpWDZby/iHN0CVhTQTQROz7fA415ozfIUEi8EU2GkwJcY40mG7ORfF7ixnUzIeC56RSmKtvAnK1n9fDB6CEAAkP7GDlMlRm7UVUnXpHr5jKqOlxMkbcvLytN8sdE/8+WGKwBYhkq13XdNhayVl9W1Ko3m9BxoF5pQZq",
    "signature_base64": "OR1ILU+zEfglTjfS36YPtmYURnEMjBDlviLlO0yq214jygBVxOcAfTuezSWGIw8sjyKw0bij/Wsi86tqFERfCDQErvbK16xY+izE6Y2BI93lmrJ3s84z1adTn5uhN1L91AbGY4R1JN7szM/KV3jYNNua1xLmrrL3TGRAXlcHRPfkYY3Wk1TzS1kL7SLhCbEq01qqbcY/+RkyMbfXNYzAlylx5wp0z0bO9CxQ1cttgwMwa8jgjaNvaya96FTmuKskCuuLtHAqfAXrJIH4GRdNUmUrve3YiinS9ufe4sd6WkVDA6VITfYVONrk88nNWu+QSA/LYRwxCc8hL2aYZTK0fOkx/6rHdylSyiR9LnYZdT6YsMfVI5tommGdhPJcvKgnRwIyrISylC98SmMfq6OyeexBScItzMLt6to+2MO41dUaqOpXBS15NXpB/Fsx8oYzt4NdZ5VGs33PscfUARf9RDoKBWmIfnN47yX/HcbEcbrpCszaFagOc1PBRxujMxUWrlGW+EkQHc0yetPJqDsUR5lGWaXqRZPUjTCvCgk403LgjURzR0rFm8cRy5XbtyRSLnFTjGkQ2FTq5AR+ulI3pZvT74YNYqxREbNWWKTi4zr2U5BnlwUveCKK41fmiBPOT8WPQOmYs11IpKxHiaQ8D4N9Esmz+/6b1VJgXU0E/UxvY7HNZgrR1qjBr3VfXsnLN5mFotf5Rwp1thUGjT3e1jMnJUKuKzednTIxgpTjLOO6im3XnMRnErNjWXSiEGFYolDcylQmXfLVeBvB+DWjY5UwnIWeF2euSXMxy04rGVyH6+Rn443VwrEQRTWavqHdSdprJpRJEz2DNJOu1whd35Zz3JgyeeOaywnaXYMqpDsegAAAAAAAAAAA"
}
```

### Cuckoo `graph_seed` vector

This vector fixes the helper used by the PoW profile before any graph search is
performed.

```text
challenge_bytes_ascii = "challenge"
nonce = 3
graph_seed_hex = 60ab7795bdc7d1e1952d08eb04ce99aeedf0969b4b6ae11faabf6e9c254679c7
```

### Reduced-work Cuckoo proof vector

This vector is for interoperability testing of edge derivation and proof
verification only. It is **not** the production `42-29` profile. Production
deployments MUST still implement and enforce
`tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256`.

```text
config.edge_bits = 8
config.proof_size = 4
challenge_bytes_ascii = "tiny-cuckoo-test"
nonce = 0
graph_seed_hex = cc53bbfaea7f82519d68c626b808a991decdad0af34fff068d5b506fa45b6bc9
proof = [0, 48, 289, 3503]
edge(0) = (49, 116)
edge(48) = (8, 116)
edge(289) = (8, 3)
edge(3503) = (49, 3)
```

### PoW challenge-object `graph_seed` vector

This vector fixes the canonical JSON bytes and the resulting `graph_seed` for a
sample production-profile challenge object.

```json
{
    "challenge_object": {
        "algorithm": "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256",
        "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
        "expires_ts": 1798848000000,
        "resource": {
            "action": "fn-dsa-key-publication",
            "server_name": "example.com",
            "key_id_sha256": "IP0hvDGShf-70PxUumyFgdlSrGLmcekPQYSotCXS2zg"
        }
    },
    "canonical_json_utf8": "{\"algorithm\":\"tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"expires_ts\":1798848000000,\"resource\":{\"action\":\"fn-dsa-key-publication\",\"server_name\":\"example.com\",\"key_id_sha256\":\"IP0hvDGShf-70PxUumyFgdlSrGLmcekPQYSotCXS2zg\"}}",
    "nonce": 8137226,
    "graph_seed_hex": "284e0a6686aef81a82f8b44a4c8026966058f3973dc958fbecb28361082a7107"
}
```

## Dependencies

- **NIST FIPS 206 (FN-DSA):** This MSC targets the FIPS 206 initial public
  draft. Unstable prefixes and the deployment guidance above buffer against
  pre-finalization changes. Once FIPS 206 is finalized, this MSC will be updated
  to reference the final standard, and stable identifiers (`fn-dsa-512`) will
  replace unstable prefixes.
- **NIST FIPS 203 (ML-KEM):** Required only by the optional session negotiation
  extension. FIPS 203 was finalized in August 2024.

This MSC has no dependency on MSC 45YY or MSC 0F00; they depend on it.

## Backwards compatibility

This proposal is fully backwards-compatible:

- **Key distribution** is additive — new entries in `verify_keys`,
  `old_verify_keys`, and `signatures`. Legacy servers ignore unknown key
  algorithms.
- **Transport auth** is additive — `X-Matrix-PQC` and `X-Matrix-PQC-Session` are
  ignored by legacy servers per RFC 9110, and the Ed25519 `Authorization` header
  remains present and authoritative.
- **One new endpoint**, which is OPTIONAL, discoverable by its `404`, and has a
  mandatory fallback path.
- **Zero impact on events, PDUs, room versions, or clients.**

## References

[^1]:
    **National Institute of Standards and Technology.** _FIPS 206 Initial Public
    Draft: FN-DSA._ Computer Security Resource Center. Available at:
    <https://csrc.nist.gov/pubs/fips/206/ipd>

[^2]:
    **Perlner, R. (2025).** _FIPS 206 Status Update._ 6th NIST PQC
    Standardization Conference. Available at:
    <https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf>

[^3]:
    **Fouque, P.-A., Hoffstein, J., Kirchner, P., Lyubashevsky, V., Pornin, T.,
    Prest, T., Ricosset, T., Seiler, G., Whyte, W., & Zhang, Z.** _Falcon:
    Fast-Fourier Lattice-based Compact Signatures over NTRU._ Specification and
    reference implementation. Available at: <https://falcon-sign.info/>

[^4]:
    **Pornin, T. (2019).** _New Efficient, Constant-Time Implementations of
    Falcon._ IACR Cryptology ePrint Archive, 2019/893. Available at:
    <https://eprint.iacr.org/2019/893>

[^5]:
    **Howe, J., Prest, T., Ricosset, T., & Rossi, M. (2019).** _Isochronous
    Gaussian Sampling: From Inception to Implementation With Applications to the
    Falcon Signature Scheme._ IACR Cryptology ePrint Archive, 2019/1411.
    Available at: <https://eprint.iacr.org/2019/1411>

[^6]:
    **Fouque, P.-A., Kirchner, P., Tibouchi, M., Wallet, A., & Yu, Y. (2024).**
    _Do Not Disturb a Sleeping Falcon._ IACR Cryptology ePrint Archive,
    2024/1709. Available at: <https://eprint.iacr.org/2024/1709>

[^7]:
    **Qiu, J., & Aysu, A. (2025).** _SHIFT SNARE: Uncovering Secret Keys in
    FALCON via Single-Trace Analysis._ arXiv:2504.00320. Available at:
    <https://arxiv.org/abs/2504.00320>

[^8]:
    **National Institute of Standards and Technology. (2024).** _FIPS 203:
    Module-Lattice-Based Key-Encapsulation Mechanism Standard._ Computer
    Security Resource Center. Available at:
    <https://csrc.nist.gov/pubs/fips/203/final>

[^9]:
    **Tromp, J.** _Cuckoo Cycle: a memory-bound graph-theoretic proof-of-work
    system._ Available at: <https://github.com/tromp/cuckoo>

[^10]:
    **Krawczyk, H., & Eronen, P. (2010).** _HMAC-based Extract-and-Expand Key
    Derivation Function (HKDF)._ RFC 5869. Available at:
    <https://datatracker.ietf.org/doc/html/rfc5869>

---

## MSC Checklist

- [ ] Are
      [appropriate implementation(s)](https://spec.matrix.org/proposals/#implementing-a-proposal)
      specified in the MSC's PR description?
- [x] Are all MSCs that this MSC depends on already accepted? (No MSC
      dependencies.)
- [x] For each endpoint that is introduced or modified:
    - [x] Have authentication requirements been specified? (Ed25519
          `Authorization` + `X-Matrix-PQC`, both required.)
    - [x] Have rate-limiting requirements been specified?
          (`429 M_LIMIT_EXCEEDED`.)
    - [x] Have guest access requirements been specified? (N/A — server-to-server
          API.)
    - [x] Are error responses specified?
        - [x] Does each error case have a specified `errcode` (i.e.
              `M_FORBIDDEN`) and HTTP status code?
            - [x] If a new `errcode` is introduced, is it clear that it is new?
                  (No new errcodes.)
    - [x] Are the
          [endpoint conventions](https://spec.matrix.org/latest/appendices/#conventions-for-matrix-apis)
          honoured?
        - [x] Do HTTP endpoints `use_underscores_like_this`?
        - [x] Will the endpoint return unbounded data? If so, has pagination
              been considered? (Fixed-size response; no pagination needed.)
        - [x] If the endpoint utilises pagination, is it consistent with
              [the appendices](https://spec.matrix.org/latest/appendices/#pagination)?
              (N/A.)
- [x] Will the MSC require a new room version, and if so, has that been made
      clear? (No new room version — deliberately. Room version changes are
      scoped to the companion PDU-signing proposal.)
- [x] Are backwards-compatibility concerns appropriately addressed?
- [x] An introduction exists and clearly outlines the problem being solved.
      Ideally, the first paragraph should be understandable by a non-technical
      audience.
- [ ] All outstanding threads are resolved
    - [ ] All feedback is incorporated into the proposal text itself, either as
          a fix or noted as an alternative
- [x] There is a dedicated "Security Considerations" section which details any
      possible attacks/vulnerabilities this proposal may introduce, even if this
      is "None.". See [RFC3552](https://datatracker.ietf.org/doc/html/rfc3552)
      for things to think about, but in particular pay attention to the
      [OWASP Top Ten](https://owasp.org/www-project-top-ten/).
- [x] The other section headings in the template are optional, but even if they
      are omitted, the relevant details should still be considered somewhere in
      the text of the proposal. Those section headings are:
    - [x] Introduction
    - [x] Proposal text
    - [x] Potential issues
    - [x] Alternatives
    - [x] Unstable prefix
    - [x] Dependencies
- [x] Stable identifiers are used throughout the proposal, except for the
      unstable prefix section
    - [x] Unstable prefixes
          [consider](https://github.com/matrix-org/matrix-spec-proposals/blob/main/README.md#unstable-prefixes)
          the awkward accepted-but-not-merged state
    - [x] Chosen unstable prefixes do not pollute any global namespace (use
          "tk.nutra.msc45xx", not "tk.nutra").
- [ ] Changes have applicable
      [Sign Off](https://github.com/matrix-org/matrix-spec-proposals/blob/main/CONTRIBUTING.md#sign-off)
      from all authors/editors/contributors
