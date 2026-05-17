"""Unit tests for tinypage.security module."""

import base64
import time
from pathlib import Path

import pytest

from tinypage.security import (
    escape_html,
    escape_attr,
    validate_filename,
    validate_date_format,
    validate_content,
    validate_url_protocol,
    safe_path_check,
    generate_csrf_token,
    validate_csrf_token,
    is_valid_csrf_format,
    get_csrf_cookie_header,
    check_basic_auth,
    get_real_ip,
    configure_trusted_proxies,
    get_security_headers,
    get_csp_header,
    slugify,
)


class TestEscapeHtml:
    def test_basic_chars(self):
        assert escape_html("<script>") == "&lt;script&gt;"

    def test_quotes(self):
        assert escape_html('"hello"') == "&quot;hello&quot;"

    def test_ampersand(self):
        assert escape_html("a&b") == "a&amp;b"

    def test_chinese_preserved(self):
        assert escape_html("你好世界") == "你好世界"

    def test_empty_string(self):
        assert escape_html("") == ""


class TestEscapeAttr:
    def test_double_quotes(self):
        result = escape_attr('value="x"')
        assert '"' not in result
        assert "&quot;" in result

    def test_xss_in_attr(self):
        result = escape_attr('"><script>alert(1)</script>')
        assert "<script>" not in result


class TestValidateFilename:
    def test_valid_filename(self):
        assert validate_filename("2026-05-16-my-article.html") is True

    def test_chinese_filename(self):
        assert validate_filename("2026-05-16-你好世界.html") is True

    def test_no_date_prefix(self):
        assert validate_filename("my-article.html") is False

    def test_path_traversal(self):
        assert validate_filename("../../etc/passwd") is False

    def test_empty(self):
        assert validate_filename("") is False

    def test_wrong_extension(self):
        assert validate_filename("2026-05-16-article.txt") is False

    def test_sql_injection(self):
        assert validate_filename("2026-05-16-'; DROP TABLE--.html") is False


class TestValidateDateFormat:
    def test_valid_date(self):
        assert validate_date_format("2026-05-16 12:00") is True

    def test_invalid_format(self):
        assert validate_date_format("2026/05/16") is False

    def test_invalid_time(self):
        assert validate_date_format("2026-05-16 25:00") is False

    def test_empty(self):
        assert validate_date_format("") is False


class TestValidateContent:
    def test_normal_content(self):
        assert validate_content("Hello, world!") is True

    def test_too_long(self):
        assert validate_content("x" * 50001) is False

    def test_binary_content(self):
        binary_like = "\x00\x01\x02" * 1000
        assert validate_content(binary_like) is False

    def test_not_string(self):
        assert validate_content(123) is False


class TestValidateUrlProtocol:
    def test_https(self):
        assert validate_url_protocol("https://example.com") is True

    def test_javascript_xss(self):
        assert validate_url_protocol("javascript:alert(1)") is False

    def test_data_uri(self):
        assert validate_url_protocol("data:text/html,<h1>hi</h1>") is False

    def test_protocol_relative(self):
        assert validate_url_protocol("//example.com/path") is True

    def test_empty(self):
        assert validate_url_protocol("") is False

    def test_mailto(self):
        assert validate_url_protocol("mailto:user@example.com") is True

    def test_relative_path(self):
        assert validate_url_protocol("/about.html") is True


class TestSafePathCheck:
    def test_valid_path(self, tmp_path):
        result, resolved = safe_path_check("test.html", tmp_path)
        assert result is True
        assert resolved is not None

    def test_path_traversal(self, tmp_path):
        result, resolved = safe_path_check("../../etc/passwd", tmp_path)
        assert result is False

    def test_absolute_path_escape(self, tmp_path):
        # On Windows, "/etc/passwd" resolves to current drive, so test with a
        # traversal that definitely escapes on all platforms
        result, resolved = safe_path_check("../outside.html", tmp_path)
        assert result is False


class TestCsrfToken:
    def test_generate_and_validate(self):
        token = generate_csrf_token()
        environ = {
            "HTTP_COOKIE": f"csrf_token={token}",
            "HTTP_ORIGIN": "http://127.0.0.1:8081",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert validate_csrf_token(environ, token, admin_port=8081) is True

    def test_invalid_token(self):
        environ = {"REMOTE_ADDR": "127.0.0.1"}
        assert validate_csrf_token(environ, "invalid_token", admin_port=8081) is False

    def test_cookie_mismatch(self):
        token = generate_csrf_token()
        environ = {
            "HTTP_COOKIE": "csrf_token=different_token",
            "HTTP_ORIGIN": "http://127.0.0.1:8081",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert validate_csrf_token(environ, token, admin_port=8081) is False

    def test_is_valid_csrf_format(self):
        token = generate_csrf_token()
        assert is_valid_csrf_format(token) is True
        assert is_valid_csrf_format("bad_token") is False

    def test_expired_token(self):
        # Create a token with an old timestamp manually
        import base64
        import hashlib
        import hmac
        import struct
        from tinypage.security import _CSRF_SECRET

        old_timestamp = int(time.time()) - 4000  # Way past 3600s expiry
        random_bytes = b"\x00" * 16
        token_data = random_bytes + struct.pack(">I", old_timestamp)
        signature = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
        expired_token = base64.urlsafe_b64encode(token_data + signature).decode("ascii")

        assert is_valid_csrf_format(expired_token) is False


class TestCsrfCookieHeader:
    def test_basic_header(self):
        header = get_csrf_cookie_header("test_token")
        assert header[0] == "Set-Cookie"
        assert "csrf_token=test_token" in header[1]
        assert "HttpOnly" in header[1]
        assert "SameSite=Strict" in header[1]

    def test_secure_flag(self):
        header = get_csrf_cookie_header("test_token", secure=True)
        assert "Secure" in header[1]


class TestBasicAuth:
    def test_valid_credentials(self):
        creds = base64.b64encode(b"admin:secret123").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {creds}"}
        assert check_basic_auth(environ, "admin", "secret123") is True

    def test_wrong_password(self):
        creds = base64.b64encode(b"admin:wrong").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {creds}"}
        assert check_basic_auth(environ, "admin", "secret123") is False

    def test_missing_header(self):
        assert check_basic_auth({}, "admin", "secret123") is False


class TestGetRealIp:
    def test_no_proxy(self):
        environ = {"REMOTE_ADDR": "192.168.1.1"}
        assert get_real_ip(environ) == "192.168.1.1"

    def test_with_trusted_proxy(self):
        configure_trusted_proxies({"127.0.0.1"})
        environ = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_FOR": "10.0.0.1, 10.0.0.2",
        }
        assert get_real_ip(environ) == "10.0.0.1"

    def test_untrusted_proxy_ignores_header(self):
        configure_trusted_proxies(set())
        environ = {
            "REMOTE_ADDR": "10.0.0.1",
            "HTTP_X_FORWARDED_FOR": "spoofed_ip",
        }
        assert get_real_ip(environ) == "10.0.0.1"


class TestSecurityHeaders:
    def test_security_headers_present(self):
        headers = get_security_headers()
        header_dict = dict(headers)
        assert "X-Content-Type-Options" in header_dict
        assert "X-Frame-Options" in header_dict
        assert "Referrer-Policy" in header_dict

    def test_csp_header(self):
        name, value = get_csp_header()
        assert name == "Content-Security-Policy"
        assert "default-src" in value


class TestSlugify:
    def test_basic_slug(self):
        assert slugify("Hello World") == "hello-world"

    def test_chinese_preserved(self):
        assert slugify("你好世界") == "你好世界"

    def test_special_chars(self):
        assert slugify("Hello & World!") == "hello-world"

    def test_max_length(self):
        result = slugify("a" * 100, max_length=10)
        assert len(result) <= 10

    def test_fallback(self):
        assert slugify("!!!", fallback="default") == "default"
