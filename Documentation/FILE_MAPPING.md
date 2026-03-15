# VVP Monorepo ↔ OSS Verifier File Mapping

This document maps file paths between the VVP monorepo verifier (`services/verifier/`) and the OSS OVC-VVP-Verifier repo. After Sprint 89 restructuring, shared modules use identical relative paths, enabling mechanical `diff`-based porting.

## How to Port Changes

```bash
# From VVP monorepo root, diff a shared file:
diff services/verifier/app/vvp/acdc/verifier.py ../OVC-VVP-Verifier/app/vvp/acdc/verifier.py

# For common/ package code that maps to OSS flat files:
diff common/common/vvp/schema/registry.py ../OVC-VVP-Verifier/app/vvp/schema.py
```

## Shared Modules (Identical Paths)

These files exist in both repos at the same relative path under `app/`. Changes can be ported via direct diff.

### Core

| VVP (`services/verifier/`) | OSS | Notes |
|----------------------------|-----|-------|
| `app/core/config.py` | `app/core/config.py` | VVP has more config vars |
| `app/main.py` | `app/main.py` | VVP ~3200 lines, OSS ~560 lines |

### ACDC Package

| VVP | OSS | Notes |
|-----|-----|-------|
| `app/vvp/acdc/__init__.py` | `app/vvp/acdc/__init__.py` | VVP exports more symbols |
| `app/vvp/acdc/models.py` | `app/vvp/acdc/models.py` | Identical structure |
| `app/vvp/acdc/parser.py` | `app/vvp/acdc/parser.py` | Identical structure |
| `app/vvp/acdc/verifier.py` | `app/vvp/acdc/verifier.py` | VVP has more validators |
| `app/vvp/acdc/graph.py` | `app/vvp/acdc/graph.py` | VVP has richer graph model |

### Dossier Package

| VVP | OSS | Notes |
|-----|-----|-------|
| `app/vvp/dossier/__init__.py` | `app/vvp/dossier/__init__.py` | Identical structure |
| `app/vvp/dossier/parser.py` | `app/vvp/dossier/parser.py` | Identical structure |
| `app/vvp/dossier/fetch.py` | `app/vvp/dossier/fetch.py` | Identical structure |
| `app/vvp/dossier/validator.py` | `app/vvp/dossier/validator.py` | VVP has CVD edge validation |
| `app/vvp/dossier/cache.py` | `app/vvp/dossier/cache.py` | Identical structure |

### KERI Package

| VVP | OSS | Notes |
|-----|-----|-------|
| `app/vvp/keri/__init__.py` | `app/vvp/keri/__init__.py` | |
| `app/vvp/keri/cache.py` | `app/vvp/keri/cache.py` | |
| `app/vvp/keri/cesr.py` | `app/vvp/keri/cesr.py` | |
| `app/vvp/keri/delegation.py` | `app/vvp/keri/delegation.py` | |
| `app/vvp/keri/exceptions.py` | `app/vvp/keri/exceptions.py` | |
| `app/vvp/keri/kel_parser.py` | `app/vvp/keri/kel_parser.py` | |
| `app/vvp/keri/kel_resolver.py` | `app/vvp/keri/kel_resolver.py` | |
| `app/vvp/keri/key_parser.py` | `app/vvp/keri/key_parser.py` | |
| `app/vvp/keri/oobi.py` | `app/vvp/keri/oobi.py` | |
| `app/vvp/keri/signature.py` | `app/vvp/keri/signature.py` | |

### Other Shared Files

| VVP | OSS | Notes |
|-----|-----|-------|
| `app/vvp/api_models.py` | `app/vvp/api_models.py` | VVP has more error codes |
| `app/vvp/authorization.py` | `app/vvp/authorization.py` | |
| `app/vvp/exceptions.py` | `app/vvp/exceptions.py` | |
| `app/vvp/header.py` | `app/vvp/header.py` | |
| `app/vvp/passport.py` | `app/vvp/passport.py` | |
| `app/vvp/revocation_checker.py` | `app/vvp/revocation_checker.py` | |
| `app/vvp/verification_cache.py` | `app/vvp/verification_cache.py` | |
| `app/vvp/verify.py` | `app/vvp/verify.py` | |

## Non-Shared: VVP Common Package → OSS Flat Files

The VVP monorepo uses a shared `common/` package. OSS has equivalent code in flat files under `app/vvp/`.

| VVP (`common/common/vvp/`) | OSS | Notes |
|-----------------------------|-----|-------|
| `schema/registry.py` | `app/vvp/schema.py` | Schema SAID → type mapping |
| `canonical/keri_canonical.py` | `app/vvp/canonical.py` | CESR canonical serialization |
| `canonical/cesr.py` | `app/vvp/cesr.py` | CESR stream parsing |
| `utils/fetch.py` | `app/vvp/fetch.py` | SSRF-safe HTTP fetch |
| `sip/` | `app/sip/` | SIP protocol handling |

## VVP-Only Modules (Not in OSS)

These exist only in VVP and are not ported to OSS:

| VVP Path | Purpose |
|----------|---------|
| `app/vvp/acdc/vlei_chain.py` | vLEI chain validation (qualifying links) |
| `app/vvp/acdc/schema_*.py` (6 files) | Schema resolution, caching, validation |
| `app/vvp/acdc/exceptions.py` | ACDC-specific exceptions |
| `app/vvp/dossier/models.py` | Dossier data models |
| `app/vvp/dossier/exceptions.py` | Dossier-specific exceptions |
| `app/vvp/keri/tel_client.py` | TEL client for revocation |
| `app/vvp/keri/witness_pool.py` | Witness pool management |
| `app/vvp/keri/credential_*.py` | Credential resolution/caching |
| `app/vvp/keri/identity_resolver.py` | Identity resolution |
| `app/vvp/vetter/` (4 files) | Vetter constraint enforcement |
| `app/vvp/ui/` | UI view models |
| `app/vvp/brand.py` | Brand identity display |
| `app/vvp/gleif.py` | GLEIF vLEI handling |
| `app/vvp/verify_callee.py` | Callee verification (SS5B) |
| `app/vvp/endpoint_health.py` | Health check logic |
| `app/logging_config.py` | Logging configuration |

## OSS-Only Files (Not in VVP Verifier)

| OSS Path | Purpose |
|----------|---------|
| `app/admin.py` | Admin endpoints (VVP integrates into main.py) |
| `app/vvp/signature.py` | Signature utilities |
| `app/vvp/tel.py` | TEL utilities |

## Test Files

VVP has 79 test files; OSS has 11. Shared test files use the same names:

| VVP | OSS |
|-----|-----|
| `tests/test_admin.py` | `tests/test_admin.py` |
| `tests/test_header.py` | `tests/test_header.py` |
| `tests/test_passport.py` | `tests/test_passport.py` |
| `tests/test_verify.py` | `tests/test_verify.py` |
| `tests/conftest.py` | `tests/conftest.py` |
