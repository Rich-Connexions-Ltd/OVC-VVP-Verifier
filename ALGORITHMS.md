# VVP Verifier Algorithms

This document describes the cryptographic formats, algorithms, and data structures used by the VVP verifier.

## VVP-Identity Header Format

The VVP-Identity header is a base64url-encoded JSON object carried in SIP signalling. It binds the PASSporT JWT to the ACDC evidence dossier.

### Structure

```
VVP-Identity: <base64url(JSON)>
```

Decoded JSON:

```json
{
  "ppt": "vvp",
  "kid": "Bk3E...c44Q",
  "evd": "https://issuer.example.com/dossier/SAID.cesr",
  "iat": 1706000000,
  "exp": 1706000300
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ppt` | string | Yes | PASSporT type. Must be `"vvp"`. |
| `kid` | string | Yes | Key identifier (KERI AID of the signer). |
| `evd` | string | Yes | Evidence URL pointing to the ACDC dossier. |
| `iat` | integer | Yes | Issued-at timestamp (UNIX epoch seconds). |
| `exp` | integer | No | Expiry timestamp. Defaults to `iat + 300`. |

### Validation Rules

1. All required fields must be present and non-empty strings (or integers for timestamps).
2. `iat` must not be more than `CLOCK_SKEW_SECONDS` (default 300) in the future.
3. Boolean values are rejected even for integer fields (Python's `bool` is a subclass of `int`).
4. When `exp` is absent, the verifier defaults it to `iat + MAX_TOKEN_AGE_SECONDS`.

## PASSporT JWT Structure

The PASSporT is a compact-serialised JWT with three dot-separated base64url segments:

```
<header>.<payload>.<signature>
```

### JOSE Header

```json
{
  "alg": "EdDSA",
  "ppt": "vvp",
  "kid": "Bk3E...c44Q",
  "typ": "passport"
}
```

| Claim | Required | Value |
|-------|----------|-------|
| `alg` | Yes | Must be `"EdDSA"`. Forbidden: `ES256`, `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `none`. |
| `ppt` | Yes | Must be `"vvp"`. |
| `kid` | Yes | KERI AID of the signing key. |
| `typ` | No | Typically `"passport"`. |

### Payload

```json
{
  "iat": 1706000000,
  "orig": { "tn": ["+15551234567"] },
  "dest": { "tn": ["+15559876543"] },
  "evd": "https://issuer.example.com/dossier/SAID.cesr",
  "exp": 1706000300,
  "card": ["FN:Acme Corp", "TEL:+12025551234", "LOGO:https://issuer.example.com/brand/logo.png"],
  "call-id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6@example.com",
  "cseq": "314 INVITE"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `iat` | Yes | Issued-at timestamp (UNIX epoch seconds). |
| `orig` | Yes | Originating identity. Must contain `tn` array with exactly one E.164 number. |
| `dest` | Yes | Destination identity. Must contain `tn` array with one or more E.164 numbers. |
| `evd` | No | Evidence URL. Also extracted from `attest.creds[0]` if prefixed with `"evd:"`. |
| `exp` | No | Expiry timestamp. |
| `card` | No | RFC 6350 vCard property string array (e.g. `["FN:Acme Corp", "TEL:+12025551234"]`). Old dict format is ignored for backwards compatibility. |
| `call-id` | No | SIP Call-ID value (max 256 chars). |
| `cseq` | No | SIP CSeq value (max 64 chars). |

### Binding Rules (§5.2-§5.4)

The PASSporT and VVP-Identity headers must be bound:

1. **ppt match**: `passport.header.ppt == identity.ppt`
2. **kid match**: `passport.header.kid == identity.kid` (strict string equality)
3. **iat drift**: `|passport.iat - identity.iat| <= 5` seconds (normative, non-configurable)
4. **exp > iat**: When `exp` is present, it must be greater than `iat`.
5. **exp consistency**: When both headers provide `exp`, drift must be within 5 seconds.
6. **exp omission**: If the PASSporT omits `exp` but the identity provides it, the request is rejected (unless `ALLOW_PASSPORT_EXP_OMISSION` is set).
7. **Validity window**: `exp - iat` must not exceed `MAX_PASSPORT_VALIDITY_SECONDS`.
8. **Expiry check**: `now <= exp + CLOCK_SKEW_SECONDS`.

## Ed25519 Signature Verification

The VVP specification mandates EdDSA with Ed25519 exclusively (§5.0, §5.1).

### Process

1. **Extract the verification key** from the `kid` (KERI AID):
   - For `B`-prefix (non-transferable): Decode the 43-character base64url suffix to obtain the 32-byte Ed25519 public key.
   - For `D`-prefix (transferable): Requires KEL resolution (not supported in Tier 1).

2. **Reconstruct the signing input**:
   ```
   signing_input = ascii_bytes(base64url_header + "." + base64url_payload)
   ```

3. **Verify the detached signature**:
   ```python
   pysodium.crypto_sign_verify_detached(signature_bytes, signing_input, public_key)
   ```

### Key Derivation from KERI AID

A non-transferable Ed25519 AID (B-prefix) encodes the public key directly:

```
AID = "B" + base64url(public_key_32_bytes)[0:43]
```

Total length: 44 characters (1 prefix + 43 base64url characters = 32 raw bytes + 1 code byte).

The CESR decoding reverses this: strip the `B` prefix, pad to 44 base64url characters, decode to 33 bytes, and discard the leading code byte to obtain the 32-byte Ed25519 public key.

## Tier 2 KEL Resolution (Transferable AIDs)

Transferable AIDs (D-prefix, E-prefix) do not directly encode the verification key. Instead, the current key state must be resolved from the Key Event Log (KEL).

### AID Routing

The verifier routes signature verification based on AID prefix:

| Prefix | Type | Verification |
|--------|------|-------------|
| `B` | Non-transferable | Tier 1: Direct key decode from AID |
| `D` | Ed25519 transferable | Tier 2: KEL resolution required |
| `E` | Blake3-256 self-addressing | Tier 2: KEL resolution required |

### KEL Resolution Process

1. **OOBI Dereference**: Fetch the identifier's KEL from a known OOBI URL. The OOBI URL is derived from the `kid` field (AID) and the configured witness URLs.

2. **KEL Parsing**: Parse the event stream (JSON or CESR) into ordered events:
   - `icp` (inception) — establishes the identifier with initial keys
   - `rot` (rotation) — updates signing keys, next key commitments
   - `ixn` (interaction) — non-establishment events (anchors, seals)
   - `dip` (delegated inception) — like `icp` but with delegator
   - `drt` (delegated rotation) — like `rot` but with delegator

3. **Chain Validation**:
   - First event must be `icp` or `dip` (inception)
   - Sequence numbers must be contiguous (0, 1, 2, ...)
   - Prior digest chain: each event's `p` field must match the SAID of the preceding event
   - SAID self-verification: each event's `d` field must match the computed SAID
   - Inception self-signature: the first event's signature must verify against its own `k` (signing keys)

4. **Temporal Key State**: Find the signing keys in effect at reference time T by walking the KEL and finding the most recent establishment event (icp/rot/dip/drt) whose timestamp is ≤ T.

5. **Signature Verification**: Verify the PASSporT signature against the resolved key state.

### Key State Cache

Resolved key states are cached with a range-based validity model:

- Each cache entry has a validity window `[valid_from, valid_until)`
- Entries older than `VVP_KEY_STATE_FRESHNESS_SECONDS` (default 120s) trigger a re-fetch
- Time-indexed lookup finds the cache entry whose validity window contains the query time
- LRU eviction with configurable max entries

### Delegation Chain Resolution

Delegated identifiers (dip/drt events) require authorization from their delegator. The verifier resolves delegation chains recursively:

1. Extract delegator AID from inception event's `di` field
2. Resolve delegator's KEL via OOBI
3. Validate delegator authorized the delegation (anchor seal in `ixn` event)
4. If delegator is also delegated, recurse (max depth: 5)
5. Terminate when a non-delegated root is found

Cycle detection prevents infinite recursion. The chain is validated from leaf to root.

## SAID Computation (Blake3-256)

Self-Addressing Identifiers (SAIDs) provide content-addressable integrity for ACDC credentials.

### Algorithm

1. Serialize the credential to canonical JSON (deterministic key ordering, no whitespace).
2. Replace the `d` (digest) field with a placeholder of `#` characters matching the expected output length.
3. Compute Blake3-256 hash of the serialized bytes.
4. Encode the hash as a CESR primitive with the `E` prefix code.
5. Replace the placeholder with the computed SAID.

### CESR Encoding

The SAID uses CESR (Composable Event Streaming Representation) encoding:

```
E + base64url(blake3_256_hash)[0:43]
```

This produces a 44-character string: 1 code character + 43 base64url characters (32 bytes of hash).

### ACDC Canonical Field Ordering

ACDC credentials use a different field ordering from KERI Key Event Log (KEL) events.  The ACDC-specific ordering, derived from keripy `SerderACDC` v1.0 `FieldDom`, is:

```
v, d, u, i, ri, s, a, A, e, r
```

Fields present in the credential but not in this ordering are appended in their original order after the canonical fields.  The version string size field (`v`) is updated to reflect the actual serialized byte length before hashing.

This ordering differs from the alphabetical fallback used for unknown KERI event types, and must be applied specifically when serializing ACDC credentials (those without a `t` field) for SAID computation.  Using the wrong ordering produces a different hash and will cause SAID verification failures.

## CESR Encoding Basics

CESR is a dual-domain encoding that works in both text (base64url) and binary. Key properties:

- **Self-framing**: Each primitive carries its own type and length information.
- **Composable**: Primitives can be concatenated without delimiters.
- **Dual-domain**: The same logical value has both a text and binary representation.

### Common CESR Codes

| Code | Meaning | Text Length |
|------|---------|-------------|
| `B` | Ed25519 non-transferable prefix (verkey) | 44 |
| `D` | Ed25519 transferable prefix (verkey) | 44 |
| `E` | Blake3-256 digest (SAID) | 44 |
| `0B` | Ed25519 signature | 88 |
| `1AAB` | Ed25519 non-transferable (long form) | 48 |

## ACDC Structure

An Authentic Chained Data Container (ACDC) is a verifiable credential in the KERI ecosystem.

### Minimal ACDC

```json
{
  "v": "ACDC10JSON000000_",
  "d": "ESAID_of_this_credential",
  "i": "Bissuer_aid_000000000000000000000000000",
  "s": "Eschema_said_00000000000000000000000000",
  "a": {
    "d": "ESAID_of_attributes",
    "i": "Bsubject_aid_00000000000000000000000000",
    "dt": "2024-01-01T00:00:00.000000+00:00",
    ...
  },
  "e": {
    "d": "ESAID_of_edges",
    ...
  }
}
```

| Field | Description |
|-------|-------------|
| `v` | Version string (protocol, encoding, size) |
| `d` | SAID of this credential (self-referential hash) |
| `i` | Issuer AID |
| `s` | Schema SAID (identifies the credential type) |
| `a` | Attributes block (claims about the subject) |
| `e` | Edges block (links to other credentials in the chain) |

### Edge Resolution

Edges link credentials into a DAG (Directed Acyclic Graph). Each edge references another credential by its SAID:

```json
{
  "e": {
    "d": "ESAID_of_edges",
    "le": {
      "n": "ESAID_of_parent_credential",
      "s": "Eschema_said_of_expected_type"
    }
  }
}
```

The verifier walks edges from the signing credential up to a trusted root AID, verifying each link.

## Claim Tree Propagation Rules

The verification result is structured as a tree of claims, where each claim has a status (`VALID`, `INVALID`, `INDETERMINATE`) and optional children.

### Status Propagation

Overall status is derived by the "worst wins" rule (§3.3A):

```
INVALID > INDETERMINATE > VALID
```

1. If any non-recoverable error exists: **INVALID**.
2. If any recoverable error exists (but no non-recoverable): **INDETERMINATE**.
3. If all claims are VALID and no errors: **VALID**.

### Child Links

Each child link carries a `required` flag:

- **Required children**: If a required child is INVALID, the parent is INVALID.
- **Optional children**: If an optional child is INVALID, the parent may still be VALID (the child is informational).

## Schema Registry

The verifier maintains a static registry mapping credential type names to governance-approved schema SAIDs.

### Supported Credential Types

| Type | Description | Authority-bearing |
|------|-------------|-------------------|
| `QVI` | Qualified vLEI Issuer | Yes |
| `LE` | Legal Entity vLEI | Yes |
| `OOR_AUTH` | Official Organizational Role Authorization | Yes |
| `OOR` | Official Organizational Role | Yes |
| `ECR_AUTH` | Engagement Context Role Authorization | Yes |
| `ECR` | Engagement Context Role | Yes |
| `APE` | Authorized Person for Engagement (pending governance) | Yes |
| `DE` | Delegated Entity | Yes |
| `TNAlloc` | Telephone Number Allocation (base and extended) | Yes |
| `BrandOwner` | Brand-owner credential (Provenant vCard array + logo hash format) | No (display-only) |
| `ExtendedBrand` | Extended brand credential (legacy scalar-field, deprecated) | No (display-only) |
| `VetterCert` | VVP VetterCert credential | Yes |
| `VetterGov` | VVP VetterGov credential | Yes |

### Brand Credentials

`BrandOwner` and `ExtendedBrand` credentials are **display-only leaf nodes** in the credential chain.  They carry brand identity information (name, logo, etc.) for rich call display, but are not authority-bearing and do not participate in the authorization chain.  When encountered during chain validation, they are marked `VALID` with `required=False` and skipped for authorization purposes.
