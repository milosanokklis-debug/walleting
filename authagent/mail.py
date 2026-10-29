"""Pluggable email providers plus verification link / OTP extraction and completion. No secrets in output."""
import re
import time
from abc import ABC, abstractmethod
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, urlsplit

import requests

from . import secrets as sec
from .allowlist import HostRefused, check_url
from .fill import FIELDS_JS, detect_captcha

NEEDS_VERIFY = re.compile(
    r"check your (e-?mail|inbox)|enter (the |your |a )?(\d+-digit |verification |one-time |confirmation )?code|"
    r"verification code|we('ve)? (e-?mailed|sent)|verify your e-?mail|confirm your e-?mail", re.I)
VERIFIED = re.compile(r"e-?mail verified|(successfully )?verified|confirmed|account (is )?(now )?active|you can now (sign|log) ?in", re.I)
LINK_HINT = re.compile(r"verif|confirm|activat|token|key=|code=|validate", re.I)
LINK_AVOID = re.compile(r"unsubscribe|opt-?out|privacy|terms", re.I)
OTP_CTX = re.compile(r"(?:code|otp|pin|passcode|password)\D{0,40}?\b(\d{4,8})\b", re.I)
CODE_FIELD = re.compile(r"code|otp|pin|token", re.I)


class MailConfigError(ValueError):
    """Mail provider misconfigured (unknown provider, missing URL/token, token refused). Not a transient outage."""


def _poll(fetch, timeout, interval):
    """Call fetch() until it returns a message or the deadline passes; transient HTTP/JSON errors are retried."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            m = fetch()
            if m:
                return m
        except (requests.RequestException, ValueError) as e:
            if isinstance(e, MailConfigError):
                raise
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


class EmailProvider(ABC):
    """Future providers (e.g. IMAP catch-all) implement just these two methods."""

    @abstractmethod
    def reachable(self) -> bool: ...

    @abstractmethod
    def latest_message(self, to_address, timeout=30, interval=1.0):
        """Newest message to the address as {'subject','text','html'}, or None after timeout. Must not hang."""


class MailpitProvider(EmailProvider):
    def __init__(self, base="http://localhost:8025"):
        self.base = base.rstrip("/")
        check_url(self.base)  # the mail API is also only reachable if allowlisted

    def _get(self, path, timeout=3):
        r = requests.get(self.base + path, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def reachable(self):
        try:
            self._get("/api/v1/info", timeout=2)
            return True
        except Exception:
            return False

    def latest_message(self, to_address, timeout=30, interval=1.0):
        def fetch():
            msgs = self._get("/api/v1/search?query=" + quote(f"to:{to_address}", safe="")).get("messages") or []
            if msgs:
                m = max(msgs, key=lambda x: x.get("Created", ""))
                full = self._get("/api/v1/message/" + quote(str(m["ID"]), safe=""))
                return {"subject": full.get("Subject", ""), "text": full.get("Text") or "", "html": full.get("HTML") or ""}
        return _poll(fetch, timeout, interval)


class CloudflareWorkerProvider(EmailProvider):
    """Reads mail from the Cloudflare Email Worker in cloudflare/mail-worker (bearer-token HTTP API)."""

    def __init__(self, base, token):
        if not base or not token:
            raise MailConfigError("MAIL_PROVIDER=cloudflare needs MAIL_API_URL and MAIL_API_TOKEN in .env")
        self.base = base.rstrip("/")
        host = check_url(self.base)  # the worker host must be allowlisted (user_hosts)
        if urlsplit(self.base).scheme != "https" and host not in ("localhost", "127.0.0.1"):
            raise MailConfigError("MAIL_API_URL must be https (the bearer token would travel in cleartext)")
        sec.register_secret(token)
        self.headers = {"Authorization": f"Bearer {token}"}

    def _get(self, path, timeout=5):
        r = requests.get(self.base + path, headers=self.headers, timeout=timeout)
        if r.status_code in (401, 403):
            raise MailConfigError("mail worker refused MAIL_API_TOKEN")
        r.raise_for_status()  # 404 on /latest = nothing yet; retried by _poll
        return r

    def reachable(self):
        try:
            self._get("/health", timeout=3)
            return True
        except Exception:
            return False

    def latest_message(self, to_address, timeout=30, interval=1.0):
        def fetch():
            m = self._get("/latest?to=" + quote(to_address.lower(), safe="")).json()
            return {"subject": m.get("subject") or "", "text": m.get("text") or "", "html": m.get("html") or ""}
        return _poll(fetch, timeout, interval)


def provider_from_env():
    """Provider named by MAIL_PROVIDER in .env (mailpit by default, or cloudflare)."""
    kind = (sec.dotenv("MAIL_PROVIDER", "mailpit") or "mailpit").lower()
    if kind == "cloudflare":
        return CloudflareWorkerProvider(sec.dotenv("MAIL_API_URL", ""), sec.dotenv("MAIL_API_TOKEN", ""))
    if kind != "mailpit":
        raise MailConfigError(f"unknown MAIL_PROVIDER {kind!r} (mailpit|cloudflare)")
    return MailpitProvider()


class _Hrefs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs += [v for k, v in attrs if k == "href" and v]


def html_to_text(html):
    return re.sub(r"\s+", " ", unescape(re.sub(r"<(script|style).*?</\1>|<[^>]+>", " ", html or "", flags=re.S | re.I))).strip()


def extract_link(text="", html=""):
    """Best verification link that passes the allowlist. Links to non-allowlisted hosts are never returned."""
    p = _Hrefs()
    p.feed(html or "")
    urls = [unescape(h) for h in p.hrefs] + re.findall(r"https?://[^\s<>\"')\]]+", text or "")
    seen, ok = set(), []
    for u in urls:
        u = u.rstrip(".,;")
        if u in seen or not u.lower().startswith(("http://", "https://")) or LINK_AVOID.search(u):
            continue
        seen.add(u)
        try:
            check_url(u)
        except HostRefused:
            continue
        ok.append(u)
    return next((u for u in ok if LINK_HINT.search(u)), ok[0] if ok else None)


def extract_otp(text="", html=""):
    """Numeric code (4-8 digits): prefer one next to the words code/otp/pin; fall back to a standalone 6-digit number."""
    body = (text or "") + " " + html_to_text(html)
    m = OTP_CTX.search(body)
    if m:
        return m.group(1)
    m = re.search(r"(?<![\d.])(\d{6})(?![\d.])", body)
    return m.group(1) if m else None


def needs_verification(page):
    return bool(NEEDS_VERIFY.search(page.inner_text("body")))


def _verified(page):
    return bool(page.locator("[data-verified=true]").count()) or bool(VERIFIED.search(page.inner_text("body")))


def complete_verification(page, provider, creds, timeout=30, prefer="otp"):
    """If the page says 'check your email / enter code', fetch the mail and finish the step. Returns a result dict."""
    if not needs_verification(page):
        return {"ok": True, "required": False}
    if detect_captcha(page):
        return {"ok": False, "reason": "captcha_detected; stopped"}
    if not provider.reachable():
        return {"ok": False, "skipped": True, "reason": "mail provider unreachable (is Mailpit/Docker up, or the Cloudflare worker URL right?)"}
    msg = provider.latest_message(creds["TEST_EMAIL"], timeout=timeout)
    if not msg:
        return {"ok": False, "reason": "no_email_received"}
    link = extract_link(msg["text"], msg["html"])
    otp = extract_otp(msg["text"], msg["html"])
    sec.register_secret(otp)  # register immediately so nothing downstream can print them
    if link:
        sec.register_secret(link)
        for vals in parse_qs(urlsplit(link).query).values():
            for v in vals:
                if len(v) >= 6:
                    sec.register_secret(v)
    d = page.evaluate(FIELDS_JS)
    code_field = next((f for f in d["fields"] if (f.get("autocomplete") or "") == "one-time-code" or
                       CODE_FIELD.search(" ".join(str(f.get(k) or "") for k in ("name", "id", "aria_label", "label", "placeholder")))), None)
    if otp and code_field and (prefer == "otp" or not link):  # the page is asking for a code and the mail has one: use the UI as a user would
        method = "otp"
        for f in d["fields"]:
            loc = page.locator(f'[data-aa="{f["idx"]}"]')
            if f is code_field:
                loc.fill(otp, timeout=5000)
            elif f["type"] == "email" and not loc.input_value():
                loc.fill(creds["TEST_EMAIL"], timeout=5000)
        btn = next((b for b in d["buttons"] if re.search(r"verif|confirm|submit|continue|activate", b["text"], re.I)), None)
        if not btn:
            return {"ok": False, "reason": "no_submit_button", "method": method}
        if detect_captcha(page):
            return {"ok": False, "reason": "captcha_detected; stopped"}
        page.locator(f'[data-aa="b{btn["idx"]}"]').click(timeout=5000)
    elif link:
        method = "link"
        page.goto(link, wait_until="domcontentloaded", timeout=15000)
    else:
        return {"ok": False, "reason": "no_link_or_code_in_email"}
    try:
        page.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass  # shortcut: busy pages may never idle
    page.wait_for_timeout(500)
    return {"ok": _verified(page), "required": True, "method": method}
