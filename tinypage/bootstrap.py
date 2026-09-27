"""Shared startup readiness logic.

Both entry points (``python -m tinypage`` and ``tinypage serve``) must go
through the same preparation sequence. Previously this logic lived only in
``server.main()``, so ``tinypage serve`` -- the path the README tells users to
run -- skipped password generation entirely and left ``admin_pass`` empty,
which made an empty password sufficient to log in.
"""

from __future__ import annotations

import logging
import secrets
import tempfile
from pathlib import Path

from .config import Config

logger = logging.getLogger(__name__)

_PASSWORD_CACHE_FILE = Path(tempfile.gettempdir()) / ".tinypage_admin_pass"

# Shortest password we will ever auto-generate.
_GENERATED_PASSWORD_LEN = 32


def ensure_admin_password(cfg: Config) -> str:
    """Get or generate the admin password. Persists generated ones to temp dir."""
    password = cfg.admin_pass
    if password:
        return password

    if _PASSWORD_CACHE_FILE.exists():
        try:
            cached = _PASSWORD_CACHE_FILE.read_text(encoding="utf-8").strip()
            if cached and len(cached) >= 24:
                logger.info("[INIT] Reusing cached admin password from temp file")
                return cached
        except (OSError, ValueError):
            pass

    base = secrets.token_urlsafe(24)
    suffix = secrets.choice(["#", "+", "%"])
    password = base[: _GENERATED_PASSWORD_LEN - 1] + suffix

    try:
        _PASSWORD_CACHE_FILE.write_text(password, encoding="utf-8")
        try:
            _PASSWORD_CACHE_FILE.chmod(0o600)  # Restrict permissions on Unix
        except OSError:
            # Windows doesn't fully support chmod, but write_text still works
            pass
    except OSError as e:
        logger.error(f"[INIT-FAILED] Cannot save password cache: {e}")

    print(f"\n{'=' * 70}")
    print("WARNING: ADMIN_PASS is not set!")
    print(f"Random password generated and cached to: {_PASSWORD_CACHE_FILE}")
    print("Set ADMIN_PASS environment variable for persistent authentication.")
    print(f"{'=' * 70}\n")
    logger.warning(f"[INIT] Random password cached to {_PASSWORD_CACHE_FILE}")
    return password


def prepare_config(cfg: Config) -> Config:
    """Return a config that is safe to serve with, plus log any warnings.

    Guarantees (regardless of which entry point called this):
      - ``admin_pass`` is never empty
      - trusted proxies are configured when behind a reverse proxy
    """
    password = ensure_admin_password(cfg)
    cfg = cfg.merge(admin_pass=password)

    if cfg.bind_domain:
        from .security import configure_trusted_proxies

        configure_trusted_proxies({"127.0.0.1", "::1", "172.17.0.1"})

    for warning in cfg.validate_startup():
        logger.warning(f"[CONFIG] {warning}")

    return cfg
