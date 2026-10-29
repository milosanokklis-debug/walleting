"""Credential generation (written only to gitignored .env.test) and log redaction."""
import os
import re
import secrets as _s
from pathlib import Path

ENV_PATH = Path(os.environ.get("AUTHAGENT_ENV_FILE") or Path(__file__).resolve().parent.parent / ".env.test")  # override: tests
DOTENV = Path(__file__).resolve().parent.parent / ".env"
MASK = "[REDACTED]"
_known = set()
# key=value / JSON / header-style secrets; keyword may sit inside a longer name (TEST_PASSWORD)
_PATTERN = re.compile(
    r"(?i)([\w-]*(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|session(?:id)?)[\w-]*[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n,;}]*)"
)
_JWT = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*")


def register_secret(value):
    if value:
        _known.add(str(value))


def redact(text):
    """Mask registered secret values, key=value/JSON secrets, and JWTs."""
    text = str(text)
    for v in sorted(_known, key=len, reverse=True):
        text = text.replace(v, MASK)
    return _JWT.sub(MASK, _PATTERN.sub(lambda m: m.group(1) + MASK, text))


def safe_print(*args):
    print(redact(" ".join(map(str, args))))


def dotenv(key, default=None):
    """Value of key from .env (AUTHAGENT_DOTENV overrides the path); default if missing or unreadable."""
    try:
        for line in Path(os.environ.get("AUTHAGENT_DOTENV") or DOTENV).read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")  # shortcut: no export/inline-comment support
            if k.strip() == key:
                return v.strip().strip("\"'")
    except (OSError, ValueError):  # unreadable or undecodable .env
        pass
    return default


def generate_creds(domain="authagent.test"):
    return {"TEST_EMAIL": f"agent-{_s.token_hex(4)}@{domain}", "TEST_PASSWORD": _s.token_urlsafe(18)}


def load_env_seed(path=ENV_PATH):
    """Read .env.test and register every value for redaction. The way callers obtain creds."""
    creds = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        k, sep, v = line.partition("=")
        if sep and not line.startswith("#"):
            creds[k.strip()] = v.strip()
            if not k.strip().endswith("_SITE"):  # the site label is not a secret; masking it would corrupt output
                register_secret(v.strip())
    return creds


def write_env_seed(creds=None, path=ENV_PATH, overwrite=False):
    """Write creds to .env.test only (0600, never clobbers unless overwrite=True); registers them."""
    path = Path(path)
    if path.name != ".env.test":
        raise ValueError("credentials may only be written to .env.test")
    creds = creds or generate_creds()
    if any("\n" in str(v) or "\r" in str(v) for v in creds.values()):
        raise ValueError("credential values must be single-line")
    flags = os.O_CREAT | os.O_WRONLY | (os.O_TRUNC if overwrite else os.O_EXCL)
    # shortcut: does not verify the file is gitignored; .gitignore rule + stage1 secret-scan cover it
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as f:
        f.write("".join(f"{k}={v}\n" for k, v in creds.items()))
    for k, v in creds.items():
        if not k.endswith("_SITE"):  # a site label is not a secret
            register_secret(v)
    return path


_HTML_TOKEN = re.compile(r"""(?i)(<(?:meta|input)[^>]*(?:csrf|token|nonce|secret)[^>]*?(?:content|value)=)(["'])[^"']*\2""")


def redact_html(html):
    """Redaction for stored page HTML: registered secret values, JWTs, csrf/token meta/input values.
    shortcut: not the key=value regex (it would swallow whole minified lines of markup)."""
    html = str(html)
    for v in sorted(_known, key=len, reverse=True):
        html = html.replace(v, MASK)
    return _HTML_TOKEN.sub(lambda m: m.group(1) + '"' + MASK + '"', _JWT.sub(MASK, html))


def redact_obj(o):
    """Redact string VALUES inside a JSON-like structure. Keys are never touched, so dumps() always stays valid JSON."""
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [redact_obj(v) for v in o]
    return o
