# MSC 00EA: Post-Quantum Digital Signatures for E2EE

Matrix device and cross-signing keys currently use `ed25519`. Quantum computers
can theoretically reverse engineer private keys using Shor's algorithm, breaking
elliptic-curve and RSA schemes.

This MSC extends the post-quantum migration to E2EE device signing keys and
cross-signing keys. The cryptographic primitives (`fn-dsa-512`), encoding rules,
and server-side federation changes are defined in
[MSC 00E4: Notary provenance for post-quantum server keys](./00E4-quantum-sigs-notary-provenance.md)
and companion federation PQC drafts.

## Proposal

This MSC uses **FN-DSA-512** (`fn-dsa-512`) as defined by MSC 00E4. All encoding
rules (public key encoding, signature encoding, signing operation) are identical
to those specified by the server-key profile. Refer to MSC 00E4 for algorithm
parameters, NIST security level rationale, and FIPS 206 dependency details.

> **Note:** For readability, this proposal uses the intended stable identifier
> `fn-dsa-512` throughout the main text and examples. Until both this MSC and
> MSC 00E4 are accepted and merged into the Matrix specification,
> implementations MUST use the unstable identifier `tk.nutra.msc45xx.fn-dsa-512`
> — the canonical prefix defined by the Federation MSC where the algorithm is
> specified — in all protocol fields, including E2EE device key IDs,
> cross-signing key IDs, and signature entries. See
> [Unstable Prefix](#unstable-prefix) for the full mapping.

### Device Signing Keys

The `/keys/upload` endpoint is extended to accept FN-DSA device signing keys:

```json
{
    "device_keys": {
        "user_id": "@alice:example.com",
        "device_id": "JLAFKJWSCS",
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": {
            "curve25519:JLAFKJWSCS": "<base64-curve25519-key>",
            "ed25519:JLAFKJWSCS": "<base64-ed25519-key>",
            "fn-dsa-512:JLAFKJWSCS": "<base64-fn-dsa-512-key>"
        },
        "signatures": {
            "@alice:example.com": {
                "ed25519:JLAFKJWSCS": "<base64-ed25519-self-signature>",
                "fn-dsa-512:JLAFKJWSCS": "<base64-fn-dsa-512-self-signature>"
            }
        }
    }
}
```

Clients SHOULD upload FN-DSA device keys alongside Ed25519 keys.

### One-Time Keys and Fallback Keys

When a client uploads One-Time Keys (OTKs) or Fallback Keys to the
`/keys/upload` endpoint, the keys are packaged in a `signatures` dictionary.
Clients supporting this MSC MUST sign their uploaded OTKs and Fallback Keys with
both their `ed25519` and `fn-dsa-512` device signing keys. Verifying clients
fetching these keys via `/keys/claim` MUST verify the `fn-dsa-512` signature if
present, falling back to `ed25519` only if the FN-DSA signature is absent.

### Cross-Signing Keys

Cross-signing master, self-signing, and user-signing keys SHOULD also support
FN-DSA:

```json
{
    "master_key": {
        "user_id": "@alice:example.com",
        "usage": ["master"],
        "keys": {
            "ed25519:base64+master+key": "<base64-ed25519-master-key>",
            "fn-dsa-512:<base64url-sha256-of-pubkey>": "<base64-fn-dsa-512-master-key>"
        }
    }
}
```

**Key ID Format.** Existing `ed25519` cross-signing keys use the unpadded base64
of the public key as their `<key_id>` (e.g., `ed25519:<base64-key>`). Because
FN-DSA-512 public keys are 897 bytes, using the full base64-encoded key would
produce a 1,196-character identifier that exceeds practical storage and
URL-safety constraints.

For `fn-dsa-512` cross-signing keys, the `<key_id>` MUST be the **unpadded
base64url encoding of the SHA-256 hash** of the raw public key bytes. This
guarantees a unique, URL-safe, 43-character identifier. Device keys are
unaffected — they continue to use the device ID as their `<key_id>` (e.g.,
`fn-dsa-512:JLAFKJWSCS`).

This E2EE cross-signing `<key_id>` construction is intentionally separate from
the server-key `key_id` defined by MSC 00E4. Server keys use the minting-bound
Keccak-derived identifier from MSC 00E4 because their identifier participates in
server-key publication, notary observation, and First Seen Wins collision
handling. E2EE cross-signing keys do not use that server-key minting flow.

When cross-signing a device key, the signing client SHOULD produce both an
Ed25519 and an FN-DSA signature. Verifying clients that support this MSC MUST
verify the FN-DSA cross-signature if present, and SHOULD treat it as the
authoritative trust anchor. If an FN-DSA cross-signature is present but fails
verification, clients MUST treat that relationship as untrusted and MUST NOT
fall back to Ed25519 for the same relationship. Ed25519-only evaluation is
permitted only when no FN-DSA cross-signature exists.

**E2EE Downgrade Risk:** A compromised homeserver could strip FN-DSA keys from
`/keys/query` responses to force Ed25519 fallback. The Ed25519 fallback above
applies only when the FN-DSA signature is absent, not when it is present but
invalid. Strict protection against stripping requires client-side key pinning
(TOFU) or constrained room membership (MSC3917), both deferred to a follow-up
MSC.

### Client Implementation Requirements

**Key Generation.** Clients that support this MSC MUST generate FN-DSA keypairs
locally for:

- Device signing keys (`fn-dsa-512`) — uploaded via `/keys/upload`
- Cross-signing keys (`fn-dsa-512`) — uploaded via `/keys/device_signing/upload`

Client implementations MUST use a side-channel-resistant FN-DSA library. See MSC
00E4 for the server-side implementation guidance and Falcon implementation
complexity notes.

**Device ID Constraints.** Because FN-DSA-512 public keys are extremely large
(897 bytes), client implementations MUST NOT use the raw base64-encoded FN-DSA
public key as the `device_id`. Clients SHOULD generate short, high-entropy
random strings for Device IDs to respect standard homeserver database column
limits (typically 255 characters).

**Signing.** Clients MUST sign their own device keys with both their Ed25519 and
FN-DSA device signing keys (self-signatures). When cross-signing another device
or user, the signing client SHOULD produce both an Ed25519 and an FN-DSA
cross-signature. **All FN-DSA signatures MUST be computed over the exact same
Matrix Canonical JSON representation of the object as the legacy Ed25519
signatures** (i.e., after stripping the `signatures` and `unsigned` fields).

**Verification.** Clients MUST verify FN-DSA signatures in the E2EE trust chain:

- Device key self-signatures (when evaluating a device's authenticity)
- Cross-signing signatures (master -> self-signing -> device key chain)

Clients do **not** verify PDU signatures or federation HTTP authentication —
these are exclusively homeserver responsibilities and are specified in the
federation PQC drafts.

**Hash-to-Key Validation.** When verifying `fn-dsa-512` cross-signing keys,
clients MUST NOT blindly trust the `<key_id>`. The client MUST decode the raw
public key bytes from the base64 payload, compute the unpadded base64url SHA-256
hash of those bytes, and ensure it strictly matches the `<key_id>` string. If
the hash does not match, the key MUST be rejected as malformed.

**Downgrade Protection (Local Cache).** If a client has previously observed and
successfully verified an `fn-dsa-512` device key or cross-signature for a
specific user/device, and a subsequent `/keys/query` response omits the FN-DSA
key but retains a valid Ed25519 key, the client SHOULD warn the user of a
potential downgrade attack and SHOULD NOT automatically trust the Ed25519
fallback.

**What clients do NOT need to do:**

- Verify or inspect the `signatures` object on timeline events (homeserver-only,
  see MSC 00E2)
- Process `X-Matrix-PQC` headers (server-to-server transport, see MSC 00E4)
- Implement FN-DSA for Olm/Megolm key agreement (deferred to a separate MSC)

### Key Agreement (Informational)

This MSC does **not** change Olm/Megolm key agreement (Curve25519/X25519).
Migration to ML-KEM (FIPS 203) is deferred to a separate MSC. MLS (RFC 9420) and
its TreeKEM key schedule provide logarithmic key distribution (network
bandwidth) overhead, making PQC key agreement scalable; see
[MSC3918](https://github.com/matrix-org/matrix-spec-proposals/pull/3918).

## Potential Issues

- **Public key size.** FN-DSA-512 public keys are 897 bytes (vs 32 for Ed25519),
  increasing `/keys/query` response sizes. For a user with 5 devices, this adds
  ~4.5 KB per query. A modest increase.

- **Signature size in cross-signing.** FN-DSA-512 cross-signatures are ~666
  bytes vs Ed25519's 64 bytes. The cross-signing chain (master -> self-signing
  -> device) adds ~2 KB of signatures per device. This is well within reasonable
  payload sizes.

- **Falcon's implementation complexity.** FN-DSA key generation and signing
  require side-channel-resistant discrete Gaussian sampling — non-constant-time
  implementations can leak private keys through timing, cache, or power side
  channels. Client implementations MUST use an audited FN-DSA library.
  Browser-targeted WASM builds require particular scrutiny. See MSC 00E4 for
  server-side implementation guidance.

- **FIPS 206 not yet finalized.** See MSC 00E4 for full pre-finalization
  deployment guidance. E2EE keys published under unstable identifiers MUST be
  treated as provisional.

## Alternatives

- **Waiting for MSC 00E4 to be accepted first.** This MSC could be deferred
  until the federation MSC is merged. However, E2EE key distribution is
  independent of federation PDU signing and can proceed in parallel. Early
  adoption provides defence-in-depth for device verification even before PQC
  room versions exist.

- **Hybrid-only cross-signing (no FN-DSA-only mode).** This MSC already
  specifies hybrid behavior: Ed25519 cross-signatures remain alongside FN-DSA. A
  future MSC could define an FN-DSA-only mode for cross-signing once Ed25519 is
  deprecated, but that is premature today.

## Security Considerations

- **Downgrade attacks (E2EE).** A compromised homeserver could strip FN-DSA keys
  from `/keys/query` responses, forcing clients to fall back to Ed25519-only
  verification. This MSC mitigates this by requiring clients to reject
  relationships where an FN-DSA cross-signature is present but invalid
  (preventing downgrade from hybrid to Ed25519). Full protection against key
  stripping requires client-side TOFU key pinning or constrained room membership
  (MSC3917), both deferred to follow-up MSCs.

- **Timing side-channels.** FN-DSA's discrete Gaussian sampler leaks private
  keys via timing analysis if implemented incorrectly. All client
  implementations MUST use audited, constant-time libraries. See MSC 00E4
  implementation guidance.

- **Key compromise recovery.** If a client's FN-DSA device signing key is
  compromised, the device key should be replaced (new device or re-upload).
  Cross-signing key compromise follows the existing cross-signing reset flow.

## Unstable Prefix

The `fn-dsa-512` algorithm is canonically defined in
[MSC 00E4](./00E4-quantum-sigs-notary-provenance.md). This MSC reuses the same
unstable identifier to ensure that servers and clients use a single, consistent
algorithm name across federation PDU signatures, device keys, and cross-signing
keys.

| Stable Identifier            | Unstable Identifier           | Defined In |
| ---------------------------- | ----------------------------- | ---------- |
| `fn-dsa-512` (key algorithm) | `tk.nutra.msc45xx.fn-dsa-512` | MSC 00E4   |

The unstable prefix is used in device key IDs, cross-signing key IDs, and
signature entries within `/keys/upload` and `/keys/device_signing/upload`
requests and `/keys/query` responses.

```json
{
    "device_keys": {
        "keys": {
            "tk.nutra.msc45xx.fn-dsa-512:JLAFKJWSCS": "<base64-fn-dsa-512-key>"
        },
        "signatures": {
            "@alice:example.com": {
                "tk.nutra.msc45xx.fn-dsa-512:JLAFKJWSCS": "<base64-fn-dsa-512-self-signature>"
            }
        }
    }
}
```

Once both MSCs are accepted but not yet merged into a released spec version,
implementations SHOULD support both the unstable prefix and the stable
identifier, accepting either.

## Dependencies

- **[MSC 00E4](./00E4-quantum-sigs-notary-provenance.md):** This MSC depends on
  MSC 00E4 for the definition of `fn-dsa-512` algorithm parameters, encoding
  rules, and signing operation semantics.
- **NIST FIPS 206 (FN-DSA):** Transitively via MSC 00E4. See MSC 00E4 for
  pre-finalization deployment guidance.

## Backwards Compatibility

This proposal is fully backwards-compatible:

- **Cross-signing continues with Ed25519.** FN-DSA cross-signatures are
  additive. Clients that do not support this MSC will see (and ignore) the
  additional `fn-dsa-512` key and signature entries in `/keys/query` responses.
- **No new endpoints.** Existing key upload and query endpoints are extended
  with new key types.
- **No breaking changes to Olm/Megolm.** Key agreement is unchanged.

---

## MSC Checklist

- [ ] Are
      [appropriate implementation(s)](https://spec.matrix.org/proposals/#implementing-a-proposal)
      specified in the MSC's PR description?
- [ ] Are all MSCs that this MSC depends on already accepted?
- [ ] For each endpoint that is introduced or modified:
    - [ ] Have authentication requirements been specified?
    - [ ] Have rate-limiting requirements been specified?
    - [ ] Have guest access requirements been specified?
    - [ ] Are error responses specified?
        - [ ] Does each error case have a specified `errcode` (i.e.
              `M_FORBIDDEN`) and HTTP status code?
            - [ ] If a new `errcode` is introduced, is it clear that it is new?
    - [x] Are the
          [endpoint conventions](https://spec.matrix.org/latest/appendices/#conventions-for-matrix-apis)
          honoured?
        - [x] Do HTTP endpoints `use_underscores_like_this`?
        - [x] Will the endpoint return unbounded data? If so, has pagination
              been considered?
        - [ ] If the endpoint utilises pagination, is it consistent with
              [the appendices](https://spec.matrix.org/latest/appendices/#pagination)?
- [ ] Will the MSC require a new room version, and if so, has that been made
      clear?
- [x] Are backwards-compatibility concerns appropriately addressed?
- [x] An introduction exists and clearly outlines the problem being solved.
      Ideally, the first paragraph should be understandable by a non-technical
      audience.
- [ ] All outstanding threads are resolved
    - [ ] All feedback is incorporated into the proposal text itself, either as
          a fix or noted as an alternative
- [x] There is a dedicated "Security Considerations" section which detail any
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
    - [x] Chosen unstable prefixes do not pollute any global namespace (reuses
          `tk.nutra.msc45xx` from the defining MSC).
- [ ] Changes have applicable
      [Sign Off](https://github.com/matrix-org/matrix-spec-proposals/blob/main/CONTRIBUTING.md#sign-off)
      from all authors/editors/contributors
