"""Regression tests for P0-3 and P0-4.

P0-3: ``safe_path_check`` compared ``str(target).startswith(str(base))``, a
string prefix test rather than a path-containment test. A sibling directory
that merely shares a name prefix -- ``pages-evil`` next to ``pages`` -- was
therefore served by the static frontend.

P0-4: only ``server.main()`` called ``ensure_admin_password``. The
``tinypage serve`` CLI, which is what the README tells users to run, skipped
it, leaving ``admin_pass == ""`` -- and ``compare_digest("", "")`` succeeds.
"""

from __future__ import annotations

import pytest

from tinypage.bootstrap import prepare_config
from tinypage.config import Config
from tinypage.security import safe_path_check


class TestSafePathCheckContainment:
    def test_file_inside_root_allowed(self, tmp_path):
        (tmp_path / "ok.html").write_text("x", encoding="utf-8")
        ok, resolved = safe_path_check("/ok.html", tmp_path)
        assert ok and resolved is not None

    def test_sibling_directory_with_shared_prefix_rejected(self, tmp_path):
        """The actual vulnerability: base "pages", attacker path "pages-evil"."""
        base = tmp_path / "pages"
        base.mkdir()
        evil = tmp_path / "pages-evil"
        evil.mkdir()
        (evil / "secret.txt").write_text("secret", encoding="utf-8")

        ok, resolved = safe_path_check("/../pages-evil/secret.txt", base)
        assert ok is False
        assert resolved is None

    def test_sibling_with_underscore_suffix_rejected(self, tmp_path):
        base = tmp_path / "pages"
        base.mkdir()
        evil = tmp_path / "pages_backup"
        evil.mkdir()
        (evil / "x.txt").write_text("secret", encoding="utf-8")

        assert safe_path_check("/../pages_backup/x.txt", base)[0] is False

    def test_deep_traversal_rejected(self, tmp_path):
        assert safe_path_check("/../etc/passwd", tmp_path)[0] is False

    def test_parent_escape_rejected(self, tmp_path):
        base = tmp_path / "pages"
        base.mkdir()
        (tmp_path / "outside.txt").write_text("x", encoding="utf-8")
        assert safe_path_check("/../outside.txt", base)[0] is False

    def test_root_itself_allowed(self, tmp_path):
        ok, _ = safe_path_check("/", tmp_path)
        assert ok


class TestPrepareConfigNeverYieldsEmptyPassword:
    def test_password_is_generated_when_unset(self, monkeypatch, tmp_path):
        monkeypatch.delenv("ADMIN_PASS", raising=False)
        cfg = Config(admin_user="admin", admin_pass="")
        prepared = prepare_config(cfg)
        assert prepared.admin_pass
        assert len(prepared.admin_pass) >= 24

    def test_explicit_password_is_preserved(self):
        cfg = Config(admin_pass="a-very-long-explicit-password")
        assert prepare_config(cfg).admin_pass == "a-very-long-explicit-password"


class TestLoginRejectsEmptyPassword:
    def test_empty_configured_password_blocks_login(self):
        """Defense in depth: even if bootstrap is bypassed, no one gets in."""
        import io

        from tinypage import security
        from tinypage.admin import actions

        cfg = Config(admin_user="admin", admin_pass="")
        token = security.generate_csrf_token()
        env = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/login",
            "REMOTE_ADDR": "9.9.9.9",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
            "HTTP_COOKIE": f"csrf_token={token}",
            "HTTP_ORIGIN": "http://127.0.0.1:8081",
        }
        statuses = []
        actions.login_handler(
            env,
            lambda s, h: statuses.append(s),
            cfg,
            {"csrf_token": [token], "username": ["admin"], "password": [""]},
            security.SessionManager(),
            security.AuthFailureTracker(),
        )
        assert "503" in statuses[0]
