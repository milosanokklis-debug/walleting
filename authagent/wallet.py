"""Opt-in deposit-flow wallet grab (--grab-wallets).

Drives an already-logged-in deposit form once per crypto payment method to reveal the site's RECEIVING wallet
address, which these HYIP templates only show on the deposit-confirmation page (never on a plain GET). It SUBMITS
a deposit request per method (no funds are sent); authorized-operator use only. Guardrails are unchanged: it stops
on a CAPTCHA, never prints creds, and the allowlist/same-origin guard still gates every request the page makes.

Fields are set and submitted via in-page JS rather than Playwright clicks: the templates hide the real radios
behind styled cards and float a live-chat widget over the submit button, so visibility-based actions time out."""
import re

from .intel import extract_addresses

COIN = re.compile(r"bitcoin|btc|ethereum|eth|usdt|trc\s?20|erc\s?20|tron|trx|litecoin|ltc|bnb|binance"
                  r"|ripple|xrp|dogecoin|doge|usdc|dash|monero|xmr|solana|\bsol\b|\bton\b", re.I)
AMOUNT_RANGE = re.compile(r"(\d[\d,]*\.?\d*)\s*[-–]\s*\d")  # "50.00 - 4999.00" -> plan minimum

_GROUPS_JS = r"""() => {
  const near = r => { let e = r; for (let i = 0; i < 4 && e; i++) { e = e.parentElement;
    const t = (e && e.innerText || '').trim().replace(/\s+/g, ' '); if (t) return t.slice(0, 80); } return ''; };
  const g = {};
  document.querySelectorAll('input[type=radio]').forEach(r => { (g[r.name] = g[r.name] || []).push({value: r.value, label: near(r)}); });
  return g;
}"""

# Set plan/amount/select/payment via JS (hidden radios are set directly), firing input/change so any handler sees them.
_SET_JS = r"""(a) => {
  const form = [...document.forms].find(f => f.querySelector(`input[name='${a.pay}']`)) || document.querySelector('form');
  if (!form) return false;
  const fire = el => ['input', 'change', 'click'].forEach(t => el.dispatchEvent(new Event(t, {bubbles: true})));
  if (a.plan) { const p = form.querySelector(`input[name='${a.plan}']`); if (p) { p.checked = true; fire(p); } }
  const amt = form.querySelector('[name=amount]'); if (amt) { amt.value = a.amount; fire(amt); }
  form.querySelectorAll('select').forEach(s => { if (s.options.length) { s.selectedIndex = 0; fire(s); } });
  const pr = form.querySelector(`input[name='${a.pay}'][value='${a.payVal}']`); if (pr) { pr.checked = true; fire(pr); }
  return true;
}"""

_SUBMIT_JS = r"""() => {
  const form = [...document.forms].find(f => f.querySelector('[type=submit]')) || document.querySelector('form');
  if (!form) return;
  const b = form.querySelector('[type=submit]');
  if (b) b.click(); else if (form.requestSubmit) form.requestSubmit(); else form.submit();
}"""


def _radio_groups(page):
    return page.evaluate(_GROUPS_JS)


def _amount_hint(page):
    m = AMOUNT_RANGE.search(page.evaluate("() => document.body.innerText"))
    return m.group(1).replace(",", "") if m else None


def _submit(page):
    """Submit via JS and wait for the resulting load; navigation may destroy the JS context mid-call (expected)."""
    try:
        page.evaluate(_SUBMIT_JS)
    except Exception:
        pass
    for state in ("domcontentloaded", "networkidle"):
        try:
            page.wait_for_load_state(state, timeout=10000)
        except Exception:
            pass


def _read_content(page):
    """page.content() raises while a redirect is mid-flight; wait it out and retry rather than abort the grab."""
    for _ in range(3):
        try:
            return page.content()
        except Exception:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=6000)
            except Exception:
                pass
            page.wait_for_timeout(500)
    return ""


def grab_wallets(page, ctx, deposit_url, amount=None):
    """On a logged-in `page`, submit the deposit form once per crypto method and read the revealed address.

    Returns {ok, addresses:[{address,cointype,method}], tuples:[(addr,coin)], methods:[...], reason?}. Never raises.
    """
    from .auth import _settle, failure_reason

    try:
        page.on("dialog", lambda d: d.dismiss())  # an invalid-amount alert() must not hang the run
    except Exception:
        pass
    try:
        page.goto(deposit_url, wait_until="domcontentloaded", timeout=15000)
        _settle(page)
        from .fill import detect_captcha
        if detect_captcha(page):
            return {"ok": False, "reason": "captcha detected; stopped", "addresses": [], "tuples": [], "methods": []}
        groups = _radio_groups(page)
        pay_name = next((n for n, opts in groups.items() if any(COIN.search(o["label"]) for o in opts)), None)
        if not pay_name:
            return {"ok": False, "reason": "no crypto payment options on deposit form",
                    "addresses": [], "tuples": [], "methods": []}
        plan_name = next((n for n in groups if n != pay_name), None)
        amount = str(amount or _amount_hint(page) or "50")
        found, methods = {}, []
        for opt in groups[pay_name]:
            try:
                page.goto(deposit_url, wait_until="domcontentloaded", timeout=15000)  # reload: CSRF form_token is per-request
                _settle(page)
                if detect_captcha(page):
                    methods.append({"method": opt["label"], "result": "captcha; stopped"})
                    break
                page.evaluate(_SET_JS, {"plan": plan_name, "pay": pay_name, "payVal": opt["value"], "amount": amount})
                _submit(page)
                page.wait_for_timeout(500)
                addrs = extract_addresses(_read_content(page))
                methods.append({"method": opt["label"], "final_path": _path(page.url), "addresses_found": len(addrs)})
                for a, coin in addrs:
                    found.setdefault(a, {"address": a, "cointype": coin, "method": opt["label"]})
            except Exception as e:
                methods.append({"method": opt["label"], "result": failure_reason(e)})
        try:  # leave the page on a normal members route so the logout step starts clean
            page.goto(_path_origin(deposit_url), wait_until="domcontentloaded", timeout=15000)
            _settle(page)
        except Exception:
            pass
        out = {"ok": bool(found), "addresses": [found[a] for a in sorted(found)],
               "tuples": sorted((v["address"], v["cointype"]) for v in found.values()), "methods": methods}
        if not found:
            out["reason"] = "deposit submitted but no address found (may redirect to an off-site payment page)"
        return out
    except Exception as e:
        return {"ok": False, "reason": failure_reason(e), "addresses": [], "tuples": [], "methods": []}


def _path(url):
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return p.path + (("?" + p.query) if p.query else "")


def _path_origin(url):
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}/"
