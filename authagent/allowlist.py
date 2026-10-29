"""The single allowlist gate. Call check_url() before touching any site."""
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .secrets import redact

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")


DOTENV = Path(__file__).resolve().parent.parent / ".env"


def localhost_only():
    """LOCALHOST_ONLY from .env (AUTHAGENT_DOTENV overrides the path). Anything but an explicit false fails closed."""
    try:
        for line in Path(os.environ.get("AUTHAGENT_DOTENV") or DOTENV).read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")  # shortcut: no quoting/export/inline-comment support
            if k.strip() == "LOCALHOST_ONLY":
                return v.strip().strip("\"'").lower() not in ("false", "0", "no")
    except OSError:
        pass
    return True


class HostRefused(Exception):
    """Raised when a URL's host is not on the allowlist (or cannot be verified)."""


def _norm(entry):
    """Validate one allowlist entry; return normalized form or raise."""
    if not isinstance(entry, str):
        raise HostRefused("allowlist entries must be strings")
    e = entry.strip().lower().rstrip(".")
    base = e[2:] if e.startswith("*.") else e
    if not _HOST.fullmatch(base):
        raise HostRefused(f"invalid allowlist entry: {redact(entry)!r}")
    if e.startswith("*.") and "." not in base and base != "test":
        raise HostRefused(f"wildcard too broad: {e!r}")  # blocks *.com
    return e


def _normalize_all(entries):
    if not isinstance(entries, (list, tuple)):
        raise HostRefused("allowlist must be a list of strings")
    return [_norm(e) for e in entries]


def load_allowlist(path=DEFAULT_PATH):
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("top level must be a mapping")
        lists = [data.get(k) or [] for k in ("defaults", "user_hosts")]
        if not all(isinstance(x, list) for x in lists):
            raise ValueError("defaults/user_hosts must be lists")
        return _normalize_all(lists[0] + lists[1])
    except HostRefused:
        raise
    except Exception as e:  # fail closed
        raise HostRefused(f"cannot load allowlist {path}: {e}") from None


def _matches(host, pattern):
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and len(host) > len(pattern) - 1
    return host == pattern


def check_url(url, allowlist=None):
    """Return the normalized host if allowed; raise HostRefused otherwise."""
    raw = str(url).strip()
    # Browsers treat \ as /, urlsplit doesn't: reject anything where parsers could disagree.
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F or c == "\\" for c in raw):
        raise HostRefused("refused: URL contains backslash, whitespace, control or non-ASCII characters")
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on invalid port
    except ValueError:
        raise HostRefused("refused: unparseable URL or invalid port") from None
    if parts.scheme not in ("http", "https") or not host:
        raise HostRefused("refused: not an http(s) URL with a host")
    if parts.username is not None or parts.password is not None:
        raise HostRefused("refused: URL contains userinfo")
    host = host.rstrip(".")
    if not _HOST.fullmatch(host):
        raise HostRefused(f"refused: invalid hostname {redact(host)!r}")
    if allowlist is None and not localhost_only():
        return host  # LOCALHOST_ONLY=false: host match skipped, every check above still applies
    patterns = load_allowlist() if allowlist is None else _normalize_all(allowlist)
    if not any(_matches(host, p) for p in patterns):
        raise HostRefused(f"refused: host {host!r} is not on the allowlist")
    return host
