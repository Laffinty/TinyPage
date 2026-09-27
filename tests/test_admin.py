"""Regression tests for P0-1: every admin POST route must actually dispatch.

``admin/app.py`` called each handler as ``fn(environ, start_response, cfg,
post_data)`` while every handler in ``admin/actions.py`` was defined with three
parameters -- ``start_response`` was never a parameter. All 12 write actions
raised ``TypeError`` and the admin backend returned 500 for everything except
login and logout.
"""

from __future__ import annotations

import base64
import inspect
import io

import pytest

from tinypage import security
from tinypage.admin import AdminApp
from tinypage.admin.app import _verify_handler_arities


class TestHandlerArity:
    def test_router_contract_holds(self):
        """Import-time guard; re-run so a failure names the broken route."""
        _verify_handler_arities()

    @pytest.mark.parametrize(
        "route,handler",
        sorted(AdminApp._POST_HANDLERS.items()),
    )
    def test_body_handler_takes_four_args(self, route, handler):
        assert len(inspect.signature(handler).parameters) == 4, route

    @pytest.mark.parametrize(
        "route,handler",
        sorted(AdminApp._POST_HANDLERS_NO_BODY.items()),
    )
    def test_no_body_handler_takes_three_args(self, route, handler):
        assert len(inspect.signature(handler).parameters) == 3, route

    def test_every_post_route_has_a_handler(self):
        # /login and /logout are dispatched in __call__ before the session
        # check, so they are intentionally absent from the handler tables.
        pre_session = {"login_handler", "logout_handler"}
        for route in AdminApp._POST_ROUTES.values():
            if route in pre_session:
                continue
            assert (
                route in AdminApp._POST_HANDLERS
                or route in AdminApp._POST_HANDLERS_NO_BODY
            ), route


@pytest.fixture
def admin(site):
    app = AdminApp(site)
    token = security.generate_csrf_token()
    sid = app.session_manager.create_session("1.1.1.1")
    app._test_cookie = f"session_id={sid}; csrf_token={token}"
    return app


def call(app, path, body=b"", with_csrf=True):
    payload = body + (f"&csrf_token={app._test_cookie.split('csrf_token=')[1]}".encode()
                      if with_csrf else b"")
    env = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": path,
        "REMOTE_ADDR": "1.1.1.1",
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
        "HTTP_COOKIE": app._test_cookie if with_csrf or True else "",
    }
    statuses = []
    app(env, lambda s, h: statuses.append(s))
    return statuses[0]


PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 32).decode()


class TestAllActionsDispatch:
    """Every route must reach its handler instead of raising TypeError."""

    def test_create_article(self, admin):
        assert call(admin, "/create",
                    b"title=Hello+World&date=2026-01-01+00%3A00&content=%23+Hi") == "302 Found"

    def test_save_article(self, admin):
        call(admin, "/create",
             b"title=Hello+World&date=2026-01-01+00%3A00&content=%23+Hi")
        assert call(admin, "/save",
                    b"file=2026-01-01-hello-world.html&title=Hello+World"
                    b"&date=2026-01-01+00%3A00&content=%23+Hi2") == "302 Found"

    def test_regenerate(self, admin):
        assert call(admin, "/regen") == "302 Found"

    def test_upload_image(self, admin):
        assert call(admin, "/upload",
                    f"filename=a.png&data={PNG}".encode()) == "200 OK"

    def test_live_preview(self, admin):
        assert call(admin, "/preview", b"content=%23+Preview") == "200 OK"

    def test_set_theme(self, admin):
        assert call(admin, "/set-theme", b"theme=default") == "302 Found"

    def test_create_page(self, admin):
        assert call(admin, "/create-page",
                    b"title=About&slug=about&content=Hi") == "302 Found"

    def test_save_page(self, admin):
        call(admin, "/create-page", b"title=About&slug=about&content=Hi")
        assert call(admin, "/save-page",
                    b"file=about.html&title=About&slug=about&content=Hi2") == "302 Found"

    def test_ai_assist_without_key_returns_json_error(self, admin):
        assert call(admin, "/ai-assist", b"action=summarize&text=hello") == "200 OK"

    def test_delete_article(self, admin):
        call(admin, "/create",
             b"title=Hello+World&date=2026-01-01+00%3A00&content=%23+Hi")
        assert call(admin, "/delete", b"file=2026-01-01-hello-world.html") == "302 Found"

    def test_delete_page(self, admin):
        call(admin, "/create-page", b"title=About&slug=about&content=Hi")
        assert call(admin, "/delete-page", b"file=about.html") == "302 Found"


class TestGuardsStillHold:
    def test_csrf_required(self, admin):
        env = {
            "REQUEST_METHOD": "POST", "PATH_INFO": "/regen",
            "REMOTE_ADDR": "1.1.1.1", "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""), "HTTP_COOKIE": admin._test_cookie,
        }
        statuses = []
        admin(env, lambda s, h: statuses.append(s))
        assert "403" in statuses[0]

    def test_session_required(self, admin):
        env = {
            "REQUEST_METHOD": "POST", "PATH_INFO": "/regen",
            "REMOTE_ADDR": "1.1.1.1", "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""), "HTTP_COOKIE": "",
        }
        statuses = []
        admin(env, lambda s, h: statuses.append(s))
        assert "302" in statuses[0]
