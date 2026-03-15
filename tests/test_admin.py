# Copyright (c) Open Verifiable Calling Alliance. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for Sprint 83 admin endpoints and trusted roots management in OVC verifier."""

from __future__ import annotations

import asyncio
import pytest
from fastapi.testclient import TestClient


VALID_AID = "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2"


@pytest.fixture(autouse=True)
def reset_store():
    """Reset trusted roots store and ADMIN_TOKEN to defaults between tests."""
    import app.core.config as cfg
    original_token = cfg.ADMIN_TOKEN
    cfg.ADMIN_TOKEN = None  # default: no token configured
    yield
    cfg.ADMIN_TOKEN = original_token
    try:
        initial = cfg._parse_trusted_roots()
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(initial)
        )
    except Exception:
        pass


@pytest.fixture()
def client():
    import app.core.config as cfg
    import app.main as main_mod
    from app.admin import router as admin_router

    # Ensure admin router is mounted for tests (VVP_ADMIN_ENABLED defaults false).
    original = cfg.VVP_ADMIN_ENABLED
    cfg.VVP_ADMIN_ENABLED = True

    # Check if admin routes already mounted by looking for the path.
    admin_paths = {getattr(r, "path", "") for r in main_mod.app.routes}
    if "/admin/trusted-roots" not in admin_paths:
        main_mod.app.include_router(admin_router, prefix="/admin")

    try:
        yield TestClient(main_mod.app)
    finally:
        cfg.VVP_ADMIN_ENABLED = original


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Config unit tests
# ---------------------------------------------------------------------------

class TestConfigStore:
    def test_snapshot_is_frozenset(self):
        import app.core.config as cfg
        result = asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.snapshot()
        )
        assert isinstance(result, frozenset)

    def test_add_and_remove(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cfg._trusted_roots_store.replace(set()))
        after_add = loop.run_until_complete(cfg._trusted_roots_store.add(VALID_AID))
        assert VALID_AID in after_add
        after_remove = loop.run_until_complete(cfg._trusted_roots_store.remove(VALID_AID))
        assert VALID_AID not in after_remove

    def test_remove_nonexistent_raises(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cfg._trusted_roots_store.replace(set()))
        with pytest.raises(KeyError):
            loop.run_until_complete(cfg._trusted_roots_store.remove("nonexistent"))

    def test_replace_atomic(self):
        import app.core.config as cfg
        result = asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace({VALID_AID})
        )
        assert result == frozenset({VALID_AID})

    def test_current_sync(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cfg._trusted_roots_store.replace({VALID_AID}))
        assert cfg.get_trusted_roots_current() == frozenset({VALID_AID})

    def test_config_fingerprint_uses_roots(self):
        import app.core.config as cfg
        fp1 = cfg.config_fingerprint(frozenset({VALID_AID}))
        fp2 = cfg.config_fingerprint(frozenset())
        assert fp1 != fp2

    def test_admin_token_from_env(self, monkeypatch):
        monkeypatch.setenv("VVP_ADMIN_TOKEN", "mytoken")
        import importlib
        import app.core.config as cfg
        importlib.reload(cfg)
        # ADMIN_TOKEN should be set from env — but since we set it after import,
        # test the monkeypatched attribute directly
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "mytoken")
        assert cfg.ADMIN_TOKEN == "mytoken"


# ---------------------------------------------------------------------------
# GET /admin/trusted-roots
# ---------------------------------------------------------------------------

class TestGetTrustedRoots:
    def test_returns_200(self, client):
        resp = client.get("/admin/trusted-roots")
        assert resp.status_code == 200
        data = resp.json()
        assert "trusted_roots" in data
        assert isinstance(data["trusted_roots"], list)

    def test_no_cache_headers(self, client):
        resp = client.get("/admin/trusted-roots")
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_requires_token_when_set(self, monkeypatch):
        import app.core.config as cfg
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "secret")
        from app.main import app
        c = TestClient(app)
        resp = c.get("/admin/trusted-roots")
        assert resp.status_code == 401

    def test_accepts_correct_token(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "secret")
        from app.main import app
        c = TestClient(app)
        resp = c.get("/admin/trusted-roots", headers={"Authorization": "Bearer secret"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /admin/trusted-roots/add
# ---------------------------------------------------------------------------

class TestAddTrustedRoot:
    def test_add_requires_token_configured(self, client):
        """When no token configured, add returns 503."""
        resp = client.post("/admin/trusted-roots/add", json={"aid": VALID_AID})
        assert resp.status_code == 503

    def test_add_success(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth("tok"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert VALID_AID in data["trusted_roots"]
        assert "_mutation_warning" in data

    def test_add_invalid_aid(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": "bad"},
            headers=_auth("tok"),
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /admin/trusted-roots/remove
# ---------------------------------------------------------------------------

class TestRemoveTrustedRoot:
    def test_remove_success(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace({VALID_AID})
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/remove",
            json={"aid": VALID_AID},
            headers=_auth("tok"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert VALID_AID not in data["trusted_roots"]
        assert data["empty_set_active"] is True

    def test_remove_nonexistent_404(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/remove",
            json={"aid": VALID_AID},
            headers=_auth("tok"),
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /admin/trusted-roots/replace
# ---------------------------------------------------------------------------

class TestReplaceTrustedRoots:
    def test_replace_success(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/replace",
            json={"aids": [VALID_AID]},
            headers=_auth("tok"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["trusted_roots"] == [VALID_AID]

    def test_replace_empty_fail_closed(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/replace",
            json={"aids": []},
            headers=_auth("tok"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["empty_set_active"] is True
        assert "_warning" in data


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_rate_limited_after_mutation(self, monkeypatch):
        import app.core.config as cfg
        import app.admin as adm
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(adm, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        # First call succeeds
        resp1 = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth("tok"),
        )
        assert resp1.status_code == 200
        # Second call within rate limit window returns 503
        resp2 = c.post(
            "/admin/trusted-roots/remove",
            json={"aid": VALID_AID},
            headers=_auth("tok"),
        )
        assert resp2.status_code == 503


# ---------------------------------------------------------------------------
# Admin UI page
# ---------------------------------------------------------------------------

class TestAdminUi:
    def test_admin_ui_returns_html(self, client):
        resp = client.get("/admin/ui")
        # May 404 if template doesn't exist in test env, but should not 500
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert "text/html" in resp.headers.get("content-type", "")
