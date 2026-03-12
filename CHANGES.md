# Changelog

## v0.2.0 — 2026-03-12

### Bug Fixes
- **SAID computation**: ACDC credentials now use ACDC canonical field ordering (`v, d, u, i, ri, s, a, A, e, r`) matching keripy's `SerderACDC` serialization, fixing SAID verification failures for Provenant and other keripy-issued credentials.
- **TEL `bis` events**: Backerless issuance events (`bis`) are now recognized alongside `iss`, `rev`, and `brv`, fixing false UNKNOWN revocation status for backer-independent registries.
- **Brand credentials**: BrandOwner and ExtendedBrand credentials are now treated as display-only leaf nodes (not authority-bearing), matching the VVP specification.

### Protocol
- **`card` claim**: PASSporT `card` field is now an RFC 6350 vCard property string array (e.g. `["FN:Acme Corp"]`), not a dict.  Old dict-format tokens are gracefully ignored.
- **`call-id` and `cseq` claims**: New optional PASSporT payload fields `call-id` and `cseq` parsed from the JWT.
- **Schema registry**: Added BrandOwner, ExtendedBrand, VetterCert, VetterGov schema SAIDs; extended TNAlloc with second SAID.

### Performance
- **Common fetch layer** (`app/vvp/fetch.py`): All external HTTP requests now go through a single SSRF-safe fetch layer with HTTPS enforcement, no proxy injection, and a 10 MB size cap.
- **Config vars**: `VVP_ALLOW_HTTP`, `VVP_FETCH_MAX_SIZE_BYTES`, `VVP_FETCH_TIMEOUT`, `VVP_TEL_SOURCE` environment variables added.

### Attribution
- All source files now attribute **Open Verifiable Calling Alliance** as copyright holder.
