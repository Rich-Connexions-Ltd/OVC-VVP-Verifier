# Changelog

## Sprint 84: Dossier TEL Event Filtering & INDETERMINATE Brand Policy — 2026-03-13

### Bug Fixes
- **KERI TEL events in dossier no longer cause INVALID**: Mixed CESR streams containing both ACDC10 credentials and KERI10 TEL `iss` events are now handled correctly. Previously, TEL events failed SAID validation when passed to `parse_acdc`, causing the call to be marked INVALID. TEL events are now classified via positive markers (`"t"` key or `"v"` starting with `"KERI10"`) and routed to a separate `tel_events` track in `DossierParseResult`.

### New Features
- **`certainty` field**: `VerifyResponse` now includes `certainty: Literal["full","partial","none"]` — `"full"` when VALID, `"partial"` when INDETERMINATE, `"none"` when INVALID.
- **`X-VVP-Certainty` SIP header**: New SIP extension header emitted alongside `X-VVP-Status`.
- **SIP header sanitization**: `X-VVP-Brand-Name` is now sanitized before emission — all ASCII control characters (0x00–0x1F, 0x7F) are stripped and values are truncated to 256 characters to prevent header injection.
- **TEL event retention**: Parsed KERI TEL events are retained in `DossierParseResult.tel_events` for future inline revocation evaluation.

### Files Changed
- `app/vvp/dossier.py` — `DossierParseResult` dataclass; `_is_keri_event()` classifier; Strategy 1/2/3 updated to return `DossierParseResult`; Strategy 3 TEL bifurcation
- `app/vvp/models.py` — `certainty: Literal[...]` field on `VerifyResponse`; `_status_to_certainty()` helper; `Literal` import
- `app/vvp/verify.py` — Unpack `DossierParseResult.acdcs`; populate `certainty`; import `_status_to_certainty`
- `app/sip/builder.py` — `_sanitize_sip_header_value()`; `X-VVP-Certainty` header; sanitized brand name emission
- `tests/test_dossier_tel_filtering.py` — New: 12 tests for `_is_keri_event()` and `parse_dossier` TEL filtering
- `tests/test_certainty.py` — New: 18 tests for `_status_to_certainty()`, `certainty` field, `X-VVP-Certainty` header, sanitization

**Commit:** *(pending)*

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
