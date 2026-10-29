"""Semantic form filler: map fields to roles, generate valid values, submit, read errors, retry, handle steps."""
import re
import secrets as _s
from urllib.parse import urlsplit

from . import secrets as sec
from .allowlist import check_url
from .classify import CONFIRM

# Tags the visible controls (so Python can address them after SPA re-renders) and reads constraints. Never reads values.
FIELDS_JS = """() => {
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const t = e => (e ? (e.innerText || e.textContent || '') : '').trim().replace(/\\s+/g, ' ').slice(0, 200);
  document.querySelectorAll('[data-aa]').forEach(e => e.removeAttribute('data-aa'));
  const dialogs = [...document.querySelectorAll('[role=dialog],[aria-modal=true],dialog[open]')].filter(vis);
  const cands = dialogs.length ? dialogs : [...document.forms].filter(vis);
  const root = cands.find(c => c.querySelector('input[type=password]')) || cands.find(c => c.querySelector('input,select')) || document.body;
  const labelOf = i => {
    let l = t(i.labels && i.labels[0]);
    if (!l && i.getAttribute('aria-labelledby')) l = t(document.getElementById(i.getAttribute('aria-labelledby')));
    if (!l && i.closest('label')) l = t(i.closest('label'));
    return l;
  };
  const hintOf = i => {
    const ids = (i.getAttribute('aria-describedby') || '').split(/\\s+/).filter(Boolean);
    let h = ids.map(x => t(document.getElementById(x))).join(' ');
    const n = i.nextElementSibling; if (n && /hint|help|desc|small|span|p|div/i.test(n.tagName + n.className) && !n.matches('input,button,select')) h += ' ' + t(n);
    return (h + ' ' + (i.title || '')).trim();
  };
  const fields = [];
  root.querySelectorAll('input,select,textarea').forEach(i => {
    const ty = (i.getAttribute('type') || (i.tagName === 'SELECT' ? 'select' : i.tagName === 'TEXTAREA' ? 'textarea' : 'text')).toLowerCase();
    if (['hidden','submit','button','image','reset','file'].includes(ty) || i.disabled || !vis(i)) return;
    const idx = fields.length; i.setAttribute('data-aa', idx);
    fields.push({idx, type: ty, name: i.name || null, id: i.id || null, autocomplete: i.getAttribute('autocomplete'),
      aria_label: i.getAttribute('aria-label'), label: labelOf(i), placeholder: i.getAttribute('placeholder'),
      minlength: i.minLength > 0 ? i.minLength : null, maxlength: i.maxLength > 0 ? i.maxLength : null,
      pattern: i.getAttribute('pattern'), required: i.required, hint: hintOf(i),
      options: i.tagName === 'SELECT' ? [...i.options].map(o => ({value: o.value, text: o.text, disabled: o.disabled})) : null});
  });
  const buttons = [];
  root.querySelectorAll('button,[role=button],input[type=submit]').forEach(b => {
    if (!vis(b) || b.disabled) return;
    const idx = buttons.length; b.setAttribute('data-aa', 'b' + idx);
    buttons.push({idx, text: t(b) || b.value || '', type: (b.getAttribute('type') || '').toLowerCase()});
  });
  const errs = new Set();
  document.querySelectorAll('[role=alert],[aria-live],.error,.alert,.invalid-feedback,.field-error,[class*=error]').forEach(e => { if (vis(e) && t(e)) errs.add(t(e)); });
  root.querySelectorAll(':invalid').forEach(e => { if (e.validationMessage) errs.add(e.validationMessage); });
  root.querySelectorAll('[aria-invalid=true]').forEach(e => { const m = hintOf(e); if (m) errs.add(m); });
  return {fields, buttons, errors: [...errs].slice(0, 6), text: t(root).slice(0, 500)};
}"""

FILL_TIMEOUT = 5000  # ms
CONSENT = re.compile(r"terms|consent|agree|accept|privacy|policy|tos|conditions", re.I)
SUBMIT_WORDS = re.compile(r"sign[\s-]?up|register|create|join|continue|next|submit|get started|finish", re.I)
SUCCESS_TEXT = re.compile(r"check your (e-?mail|inbox)|verif|confirmation|welcome|success|account (has been )?created", re.I)


CAPTCHA_FIELD = re.compile(r"captcha|robot|human|challenge", re.I)
CAPTCHA_JS = """() => {
  const sel = '.g-recaptcha,.h-captcha,.cf-turnstile,.grecaptcha-badge,[data-sitekey],#recaptcha,[class*=captcha i],[id*=captcha i],' +
    '[name*=captcha i],[aria-label*=captcha i],[placeholder*=captcha i],img[src*=captcha i],#challenge-form,#cf-challenge-running,.cf-browser-verification,' +
    'iframe[src*=recaptcha],iframe[src*=hcaptcha],iframe[src*=turnstile],iframe[src*=captcha i],iframe[src*=arkoselabs],iframe[src*=funcaptcha],iframe[src*="challenges.cloudflare"]';
  const el = document.querySelector(sel);
  if (el) return (typeof el.className === 'string' && el.className ? el.className : el.tagName).slice(0, 40);
  const txt = document.body.innerText + ' ' + document.title;
  return /i.?m not a robot|verify (that )?you are (a )?human|are you a human|checking your browser|just a moment|unusual traffic/i.test(txt) ? 'human-check text' : null;
}"""


def detect_captcha(page):
    """DOM-only detection (never interacts with or reads the widget). Returns a short label or None."""
    return page.evaluate(CAPTCHA_JS)


def _blob(f):
    return " ".join(str(f.get(k) or "") for k in ("name", "id", "aria_label", "label", "placeholder"))


def map_field(f, seen_password=False):
    """Semantic role for one extracted field."""
    ty, ac, b = f["type"], (f.get("autocomplete") or "").lower(), _blob(f)
    if ty == "checkbox":
        return "consent" if CONSENT.search(b + " " + (f.get("hint") or "")) or f.get("required") else "checkbox"
    if ty == "radio":
        return "radio"
    if ty == "select":
        return "select"
    if ty == "password":
        return "confirm_password" if bool(CONFIRM.search(b)) or seen_password else "password"
    if ty == "email" or ac == "email" or re.search(r"e-?mail", b, re.I):
        return "email"
    if ty == "tel" or ac.startswith("tel") or re.search(r"phone|mobile|\btel\b", b, re.I):
        return "phone"
    if ac == "username" or re.search(r"user[\s_-]?name|handle|nickname|login", b, re.I):
        return "username"
    if ac == "given-name" or re.search(r"first[\s_-]?name|given", b, re.I):
        return "first_name"
    if ac == "family-name" or re.search(r"last[\s_-]?name|surname|family", b, re.I):
        return "last_name"
    if ac == "name" or re.search(r"\bname\b|full[\s_-]?name", b, re.I):
        return "name"
    if ty == "date" or re.search(r"birth|dob", b, re.I):
        return "dob"
    return "other"


def length_limits(f, adj=None, role=""):
    """(min, max) from attributes, visible hint text ('3-24 characters', 'at least 8'), and retry adjustments."""
    lo, hi = f.get("minlength") or 0, f.get("maxlength") or 0
    h = f"{f.get('hint') or ''} {f.get('label') or ''} {f.get('placeholder') or ''}"
    m = re.search(r"(\d+)\s*(?:-|–|to)\s*(\d+)\s*(?:characters|chars|letters)?", h)
    if m:
        lo, hi = max(lo, int(m[1])), (min(hi, int(m[2])) if hi else int(m[2]))
    m = re.search(r"(?:at least|minimum(?: of)?|min\.?)\s*(\d+)", h, re.I)
    if m:
        lo = max(lo, int(m[1]))
    m = re.search(r"(?:at most|maximum(?: of)?|max\.?|up to|no more than)\s*(\d+)", h, re.I)
    if m:
        hi = min(hi, int(m[1])) if hi else int(m[1])
    adj = adj or {}
    lo = max(lo, adj.get(role + "_min", 0))
    if adj.get(role + "_max"):
        hi = min(hi, adj[role + "_max"]) if hi else adj[role + "_max"]
    return lo, hi


def make_password(base, lo=0, hi=0, no_symbol=False):
    """Password within [max(lo,8), min(hi,128)] that still has upper, lower, digit (and a symbol unless no_symbol)."""
    hi = min(hi or 128, 128)
    lo = min(max(lo, 8), hi)
    if no_symbol:
        base = re.sub(r"[^A-Za-z0-9]", "", base)
    base = base or "x"
    while len(base) < lo:
        base += base  # deterministic padding keeps the stored seed authoritative
    pw = list(base[:hi])
    need = [c for c, ok in (("A", re.search(r"[A-Z]", base[:hi])), ("a", re.search(r"[a-z]", base[:hi])),
                            ("1", re.search(r"\d", base[:hi])),
                            ("!", no_symbol or re.search(r"[^A-Za-z0-9]", base[:hi]))) if not ok]
    for i, c in enumerate(need[: len(pw)]):  # overwrite trailing chars so length limits still hold
        pw[-1 - i] = c
    return "".join(pw)


def sanitize_username(u, lo=3, hi=24):
    """Force a username into [a-z0-9_] and the length limits (hi defaults to 24 when unknown)."""
    u = re.sub(r"[^a-z0-9_]", "", str(u).lower()) or "agent"
    while len(u) < max(lo, 3):
        u += _s.token_hex(2)
    return u[: hi or 24]


def gen_value(role, f, creds, adj=None):
    """Valid test value for a role respecting visible constraints. Returns None to leave the field alone."""
    adj = adj or {}
    lo, hi = length_limits(f, adj, role)
    if role in ("password", "confirm_password"):
        lo, hi = length_limits(f, adj, "password")
        return make_password(creds["TEST_PASSWORD"], lo, hi, bool(adj.get("no_symbol")))
    if role == "email":
        return creds["TEST_EMAIL"]
    if role == "username":
        return sanitize_username(creds["TEST_USERNAME"], lo, hi)
    if role == "first_name":
        return "Test"
    if role == "last_name":
        return "Agent"
    if role == "name":
        return "Test Agent"
    if role == "phone":
        return "+15555550123" if not f.get("pattern") else "5555550123"
    if role == "dob":
        return "1990-01-15"
    if role == "select":
        for o in f["options"] or []:
            if o["value"] and not o["disabled"]:
                return o["value"]
    return None


def adjust_from_errors(errors, adj):
    """Turn visible validation text into value adjustments. Returns True if anything changed."""
    changed = False
    for e in errors:
        e = e.lower()
        scope = "password" if "password" in e else "username" if "user" in e else None
        for m in re.finditer(r"\b(?:at least|minimum(?: of)?|min|more than)\b\.?\s*(\d+)", e):
            for s in ([scope] if scope else ["password", "username"]):
                adj[s + "_min"] = max(adj.get(s + "_min", 0), int(m[1])); changed = True
        for m in re.finditer(r"\b(?:at most|maximum(?: of)?|max|no more than|too long.*?(\d+)|fewer than)\b\.?\s*(\d+)?", e):
            n = m[2] or m[1]
            if n:
                for s in ([scope] if scope else ["username"]):
                    adj[s + "_max"] = int(n); changed = True
        if re.search(r"only letters and numbers|alphanumeric|special characters? (are )?not allowed|no special", e):
            adj["no_symbol"] = True; changed = True
        if scope != "password" and re.search(r"\b(taken|already (taken|exists|registered|in use)|exists|in use)\b", e):
            adj["regen"] = adj.get("regen", 0) + 1; changed = True
    return changed


def new_creds(domain=None):
    c = sec.generate_creds(domain or sec.dotenv("MAIL_DOMAIN") or "authagent.test")
    c["TEST_USERNAME"] = "agent_" + _s.token_hex(4)
    return c


def _signature(d):
    return tuple((f["type"], f["name"], f["id"]) for f in d["fields"])


def _pick_submit(buttons):
    for b in buttons:
        if SUBMIT_WORDS.search(b["text"]):
            return b
    return next((b for b in buttons if b["type"] == "submit"), buttons[0] if buttons else None)


def fill_step(page, d, creds, adj):
    """Fill every mapped field in the current extraction. Returns list of roles filled (never values)."""
    roles, seen_pw = [], False
    for f in d["fields"]:
        if CAPTCHA_FIELD.search(_blob(f)):
            continue  # never touch a captcha-like field
        role = map_field(f, seen_pw)
        seen_pw = seen_pw or f["type"] == "password"
        loc = page.locator(f'[data-aa="{f["idx"]}"]')
        if role in ("password",):
            pw = gen_value("password", f, creds, adj)
            if pw != creds["TEST_PASSWORD"]:
                creds["TEST_PASSWORD"], creds["_dirty"] = pw, True
            creds["_pw_current"] = pw
            sec.register_secret(pw)
            loc.fill(pw, timeout=FILL_TIMEOUT)
        elif role == "confirm_password":
            loc.fill(creds.get("_pw_current") or gen_value("password", f, creds, adj), timeout=FILL_TIMEOUT)
        elif role in ("consent",):
            loc.check()
        elif role == "select":
            v = gen_value(role, f, creds, adj)
            if v is not None:
                loc.select_option(v)
        elif role == "radio" or (role == "checkbox" and f.get("required")):
            if f.get("required"):
                loc.check()
            else:
                continue
        elif role == "other" and f.get("required") and f["type"] in ("text", "textarea", "search"):
            loc.fill("test", timeout=FILL_TIMEOUT)
        elif role in ("checkbox", "other"):
            continue
        else:
            v = gen_value(role, f, creds, adj)
            if v is not None:
                loc.fill(v, timeout=FILL_TIMEOUT)
        roles.append(role)
    return roles


def run_signup(page, creds, max_steps=4, max_retries=3, persist=None):
    """Drive the signup form on the already-loaded page. Returns an outcome dict (no secrets)."""
    cap = detect_captcha(page)
    if cap:
        return _result("captcha_detected", 0, 0, [], [f"CAPTCHA/bot check detected ({cap}); stopped"], page, [])
    posts = []
    page.on("response", lambda r: posts.append(r.status) if r.request.method == "POST" else None)
    adj, steps, attempts, trail = {}, 0, 0, []
    last_sig = None
    while steps < max_steps:
        cap = detect_captcha(page)  # top of every step: widgets can load late or appear on step 2+
        if cap:
            return _result("captcha_detected", steps, attempts, trail, [f"CAPTCHA/bot check detected ({cap}); stopped"], page, posts)
        d = page.evaluate(FIELDS_JS)
        if not d["fields"] and not d["buttons"]:
            break
        sig = _signature(d)
        if sig == last_sig:  # same form again: this is a retry
            attempts += 1
            if attempts > max_retries or not adjust_from_errors(d["errors"], adj):
                return _result("validation_failed", steps, attempts, trail, d["errors"], page, posts)
            if adj.get("regen"):
                if persist is None:
                    return _result("validation_failed", steps, attempts, trail, d["errors"], page, posts)
                creds.update(new_creds()); adj.pop("regen"); persist(creds)
        else:
            steps += 1
            attempts = 0
        last_sig = sig
        trail.append(fill_step(page, d, creds, adj))
        if creds.pop("_dirty", False) and persist:
            persist(creds)
        btn = _pick_submit(d["buttons"])
        if not btn:
            return _result("no_submit", steps, attempts, trail, [], page, posts)
        cap = detect_captcha(page)  # and again right before the submit click
        if cap:
            return _result("captcha_detected", steps, attempts, trail, [f"CAPTCHA/bot check detected ({cap}); stopped"], page, posts)
        n = len(posts)
        page.locator(f'[data-aa="b{btn["idx"]}"]').click(timeout=FILL_TIMEOUT)
        try:
            page.wait_for_load_state("networkidle", timeout=4000)
        except Exception:
            pass  # shortcut: SPAs with live sockets may never idle
        page.wait_for_timeout(500)
        if len(posts) > n and not (200 <= posts[-1] < 300 or 300 <= posts[-1] < 400):
            if posts[-1] >= 500:
                return _result("server_error", steps, attempts, trail, page.evaluate(FIELDS_JS)["errors"], page, posts)
        after = page.evaluate(FIELDS_JS)
        if _signature(after) != sig:  # form changed: success page or next step
            ok_post = len(posts) > n and posts[-1] < 400
            if not any(f["type"] == "password" for f in after["fields"]) and (ok_post or SUCCESS_TEXT.search(after["text"]) or not after["fields"]):
                return _result("submitted", steps, attempts, trail, [], page, posts)
            continue
        if not after["errors"] and len(posts) > n:
            return _result("submitted", steps, attempts, trail, [], page, posts)
    return _result("submitted" if posts and posts[-1] < 400 else "incomplete", steps, attempts, trail, [], page, posts)


def _result(outcome, steps, attempts, trail, errors, page, posts):
    return {"outcome": outcome, "steps": steps, "retries": attempts, "roles_filled": trail,
            "post_statuses": posts[-3:], "final_path": urlsplit(page.url).path,
            "errors": [sec.redact(e)[:120] for e in errors]}


def signup(url, headless=True, sitemap=None):
    """Discover a signup page from url (crawl), fill and submit it. Creds persist only via .env.test."""
    from playwright.sync_api import sync_playwright

    from .crawl import crawl, guard_context

    check_url(url)
    sm = sitemap or crawl(url, depth=2, max_pages=15, headless=headless)
    target = next((u for u, p in sm["pages"].items() for f in p.get("forms", [])
                   if f["classification"]["kind"] == "signup"), None)
    if not target:
        return {"outcome": "no_signup_form_found", "pages": len(sm["pages"])}
    if sec.ENV_PATH.exists():
        creds = sec.load_env_seed()
        creds["TEST_USERNAME"] = sanitize_username(creds.get("TEST_USERNAME") or "agent_" + _s.token_hex(4))
        creds["_existing"] = True
    else:
        creds = new_creds()
        creds["TEST_SITE"] = urlsplit(url).netloc  # binds the seed to this site
        sec.write_env_seed({k: v for k, v in creds.items() if not k.startswith("_")})
    for k in ("TEST_EMAIL", "TEST_PASSWORD", "TEST_USERNAME"):
        sec.register_secret(creds.get(k))

    def persist(c):
        if not creds.get("_existing"):
            sec.write_env_seed({k: v for k, v in c.items() if not k.startswith("_")}, overwrite=True)
        for k in ("TEST_EMAIL", "TEST_PASSWORD", "TEST_USERNAME"):
            sec.register_secret(c.get(k))

    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=headless)
        ctx = b.new_context()
        guard_context(ctx, url, {"blocked": 0})
        page = ctx.new_page()
        page.goto(target, wait_until="domcontentloaded", timeout=15000)
        try:
            page.wait_for_load_state("networkidle", timeout=4000)
        except Exception:
            pass
        res = run_signup(page, creds, persist=None if creds.get("_existing") else persist)
        b.close()
    res["target_path"] = urlsplit(target).path
    return res
