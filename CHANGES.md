# Changelog

## Sprint 85: Tier 2 KEL Resolution + Cross-Verifier System Test — 2026-03-14

### New Features
- **Tier 2 KEL resolution**: Transferable AIDs (D-prefix, E-prefix) are now verified via OOBI fetch → KEL parsing → temporal key state resolution. Previously, transferable AIDs were rejected with INDETERMINATE.
- **KEL parser**: Full KEL event stream parsing (JSON and CESR) with SAID recomputation, prior digest chain validation, controller signature verification, and witness receipt threshold checking.
- **Key state cache**: Range-based validity cache with LRU eviction and time-indexed lookup for temporal key state resolution.
- **Delegation chain resolution**: Recursive delegation validation with cycle detection and max depth (5).
- **Destination allowlist**: `VVP_ALLOWED_FETCH_ORIGINS` environment variable gates all outbound OOBI/dossier fetches to operator-approved `host:port` origins (fail-closed).
- **SIP STIR parameter stripping**: RFC 8224 Identity header parameters (`;info=<...>;alg=ES256;ppt=shaken`) are now stripped before PASSporT extraction.
- **Admin gating**: `/admin/*` routes are disabled by default (fail-closed) via `VVP_ADMIN_ENABLED`.

### Configuration
- `VVP_TIER2_KEL_ENABLED` — Enable/disable Tier 2 (default: `true`)
- `VVP_KEY_STATE_FRESHNESS_SECONDS` — Key state cache freshness (default: `120`)
- `VVP_OOBI_TIMEOUT_SECONDS` — OOBI fetch timeout (default: `5`)
- `VVP_ALLOWED_FETCH_ORIGINS` — Outbound fetch destination allowlist (default: empty = fail-closed)
- `VVP_ADMIN_ENABLED` — Admin endpoints toggle (default: `false`)

### Files Changed
- `app/vvp/keri/kel_parser.py` — New: KEL parser with JSON/CESR support (~1060 LOC)
- `app/vvp/keri/oobi.py` — New: OOBI dereferencer with SSRF-safe fetch
- `app/vvp/keri/cache.py` — New: Range-based key state cache
- `app/vvp/keri/kel_resolver.py` — New: Key state resolver with feature gate
- `app/vvp/keri/delegation.py` — New: Delegation chain resolver
- `app/vvp/keri/signature.py` — New: Tier 2 signature verification
- `app/vvp/signature.py` — Modified: Added async Tier 2 routing for D/E-prefix AIDs
- `app/vvp/verify.py` — Modified: Phase 4 async with KERI exception handling
- `app/vvp/fetch.py` — Modified: Added `authorize_destination()` for fetch allowlist
- `app/config.py` — Modified: Added Tier 2 config + `VVP_ALLOWED_FETCH_ORIGINS`
- `app/main.py` — Modified: Admin router gated behind `VVP_ADMIN_ENABLED`
- `app/sip/handler.py` — Modified: STIR parameter stripping
- `tests/test_keri.py` — New: 51 tests for KERI subsystem
- `tests/test_fetch_allowlist.py` — New: 9 tests for destination allowlist

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

**Commit:** `89765f3`

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
