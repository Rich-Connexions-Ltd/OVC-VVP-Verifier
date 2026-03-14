# VVP Verifier

Open-source reference implementation of the **Verified Voice Protocol (VVP)** verification service.

VVP uses [KERI](https://keri.one) autonomous identifiers and [ACDC](https://trustoverip.github.io/tswg-acdc-specification/) verifiable credentials to authenticate caller identity in SIP telephony, providing cryptographic proof of who is calling and their authorisation to use specific telephone numbers.

## Subset Compliance

This is a **subset implementation** of the VVP specification. Every `VerifyResponse` includes a mandatory `capabilities` dictionary declaring which verification phases are implemented, rejected, or not yet implemented. Consumers **MUST** check `capabilities` to understand the scope of verification performed.

| Capability | Status |
|-----------|--------|
| `signature_tier1_nontransferable` | `implemented` — Ed25519 non-transferable AIDs |
| `signature_tier1_transferable` | `tier2_required` — requires Tier 2 KEL resolution |
| `signature_tier2` | `implemented` — KEL resolution for transferable AIDs |
| `dossier_validation` | `implemented` |
| `acdc_chain` | `implemented` |
| `revocation` | `implemented` |
| `authorization` | `implemented` |
| `brand_verification` | `not_implemented` |
| `goal_verification` | `not_implemented` |
| `vetter_constraints` | `not_implemented` |
| `sip_context` | `not_implemented` |
| `callee_verification` | `not_implemented` |

## Quick Start

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Start the verifier
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Docker

```bash
docker build -t vvp-verifier .
docker run -p 8000:8000 -p 5060:5060/udp vvp-verifier
```

## API

### POST /verify

Submit a VVP-signed PASSporT for verification:

```bash
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "passport_jwt": "<JWT>",
    "vvp_identity": "<base64url-encoded VVP-Identity>",
    "dossier_url": "https://issuer.example.com/dossier/<SAID>"
  }'
```

Response:

```json
{
  "request_id": "abc123",
  "overall_status": "VALID",
  "claims": [...],
  "errors": null,
  "capabilities": {"signature_tier1_nontransferable": "implemented", ...},
  "signer_aid": "BAbcdef...",
  "brand_name": "Example Corp",
  "cache_hit": false
}
```

### GET /healthz

Returns service health, capabilities, and cache statistics.

### SIP Interface (UDP :5060)

The verifier also accepts SIP INVITE messages on UDP port 5060. It extracts VVP headers (`X-VVP-Identity`, `P-VVP-Identity`), performs verification, and returns a SIP 302 redirect with verification results in custom headers.

## Architecture

The verifier implements a **9-phase verification pipeline**:

1. **Parse VVP-Identity** — Decode and validate the identity header
2. **Parse PASSporT** — Parse and validate the JWT structure
3. **Bind** — Cross-validate identity ↔ PASSporT fields
4. **Verify Signature** — Ed25519 (Tier 1 non-transferable + Tier 2 transferable via KEL)
5. **Fetch Dossier** — Retrieve the ACDC credential dossier
6. **Validate DAG** — Verify the credential graph structure
7. **Verify ACDC Chain** — Validate each credential (SAID, signatures)
8. **Check Revocation** — Query TEL for credential status
9. **Validate Authorization** — Verify party authorization and TN rights

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_CLOCK_SKEW_SECONDS` | `300` | Allowed clock skew for token validation |
| `VVP_MAX_TOKEN_AGE_SECONDS` | `300` | Maximum token age |
| `VVP_MAX_PASSPORT_VALIDITY_SECONDS` | `300` | Maximum PASSporT validity period |
| `VVP_DOSSIER_FETCH_TIMEOUT` | `5` | HTTP timeout for dossier fetch (seconds) |
| `VVP_DOSSIER_MAX_SIZE` | `1048576` | Maximum dossier size (bytes) |
| `VVP_HTTP_HOST` | `0.0.0.0` | HTTP API bind address |
| `VVP_HTTP_PORT` | `8000` | HTTP API port |
| `VVP_SIP_HOST` | `0.0.0.0` | SIP UDP bind address |
| `VVP_SIP_PORT` | `5060` | SIP UDP port |
| `VVP_CACHE_TTL` | `300` | Verification result cache TTL (seconds) |
| `VVP_CACHE_MAX_SIZE` | `1000` | Verification result cache max entries |
| `VVP_DOSSIER_CACHE_TTL` | `600` | Dossier cache TTL (seconds) |
| `VVP_DOSSIER_CACHE_MAX_SIZE` | `500` | Dossier cache max entries |
| `VVP_TRUSTED_ROOT_AIDS` | | Comma-separated list of trusted root AIDs |
| `VVP_WITNESS_URLS` | | Comma-separated witness URLs for TEL queries |
| `VVP_TIER2_KEL_ENABLED` | `true` | Enable Tier 2 transferable AID verification |
| `VVP_KEY_STATE_FRESHNESS_SECONDS` | `120` | Key state cache freshness window |
| `VVP_OOBI_TIMEOUT_SECONDS` | `5` | OOBI fetch timeout |
| `VVP_ALLOWED_FETCH_ORIGINS` | | Comma-separated `host:port` allowlist for outbound fetches |
| `VVP_ADMIN_ENABLED` | `false` | Enable admin UI and endpoints (fail-closed) |

## Algorithms

See [ALGORITHMS.md](ALGORITHMS.md) for detailed descriptions of the cryptographic algorithms, SAID computation, canonical serialisation, and TEL parsing.

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2024-2026 Rich Connexions Ltd.
