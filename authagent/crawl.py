"""Allowlist-gated, same-origin crawler (Scrapling StealthySession fetches, Scrapling parses) producing a classified site map."""
import json
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from scrapling.parser import Selector

from .allowlist import HostRefused, check_url
from .classify import classify_form
from .secrets import redact, safe_print

CACHE_DIR = Path(__file__).resolve().parent.parent / "runs"

# Runs in the rendered page; only what needs a live DOM. Marks visible elements and resolves input labels.
# Never reads field values. Parsing happens in Scrapling on page.content().
MARK_JS = """() => {
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  document.querySelectorAll('body *').forEach(e => { if (vis(e)) e.setAttribute('data-aa-vis', '1'); });
  document.querySelectorAll('input,select,textarea').forEach(i => {
    let l = i.labels && i.labels[0] ? i.labels[0].innerText : '';
    if (!l && i.getAttribute('aria-labelledby')) {
      const r = document.getElementById(i.getAttribute('aria-labelledby')); l = r ? r.innerText : '';
    }
    i.setAttribute('data-aa-label', l.trim().slice(0, 80));
  });
  return document.body.innerText.length;
}"""
UNMARK_JS = """() => document.querySelectorAll('[data-aa-vis],[data-aa-label]').forEach(e => {
  e.removeAttribute('data-aa-vis'); e.removeAttribute('data-aa-label'); })"""


def _txt(el):
    t = el.attrib.get("value") if el.tag == "input" else None
    return " ".join((t or el.get_all_text()).split())[:80]


def _field(i):
    a = i.attrib
    return {"type": (a.get("type") or ("textarea" if i.tag == "textarea" else "text")).lower(),
            "name": a.get("name") or None, "id": a.get("id") or None, "autocomplete": a.get("autocomplete"),
            "aria_label": a.get("aria-label"), "label": a.get("data-aa-label", ""), "placeholder": a.get("placeholder")}


def parse_page(html, url, text_len=0):
    """Rendered HTML (visible elements marked by MARK_JS) -> title/heading/links/buttons/forms."""
    sel = Selector(html, url=url)
    fields_in = lambda r: [_field(i) for i in r.css("input[data-aa-vis],select[data-aa-vis],textarea[data-aa-vis]")
                           if (i.attrib.get("type") or "").lower() not in ("hidden", "submit", "button")]
    btns = lambda r: [t for t in (_txt(b) for b in r.css("button[data-aa-vis],[role=button][data-aa-vis],input[type=submit][data-aa-vis]")) if t]
    heads = lambda r: " ".join(_txt(h) for h in r.css("h1,h2,h3,legend,label,a")).strip()[:400]
    forms = [{"action": f.attrib.get("action"), "aria_label": f.attrib.get("aria-label"), "fields": fields_in(f),
              "buttons": btns(f), "text": heads(f)} for f in sel.css("form[data-aa-vis]")]
    body = sel.css("body")
    if not forms and body:  # SPA pages often skip <form>; treat visible inputs as one pseudo-form
        fields = fields_in(body[0])
        if fields:
            forms.append({"action": None, "aria_label": None, "fields": fields, "buttons": btns(body[0]),
                          "text": heads(body[0]), "pseudo": True})
    h = sel.css("h1,h2")
    links = {}
    for a in sel.css("a[href]"):
        links.setdefault(urljoin(url, a.attrib["href"]), _txt(a))  # shortcut: <base href> ignored
    return {"title": " ".join(sel.css("title::text").get("").split()), "heading": _txt(h[0]) if h else "",
            "text_len": text_len, "links": list(links), "link_text": links, "buttons": btns(body[0]) if body else [], "forms": forms}


def _norm(url):
    p = urlsplit(url)
    # shortcut: query/fragment dropped so tokens never reach the map; query-only routes are not distinguished
    return urlunsplit((p.scheme, p.netloc.lower(), p.path.rstrip("/") or "/", "", ""))


def _origin(url):
    p = urlsplit(url)
    return (p.scheme, p.netloc.lower())


def _guard_handler(start_url, stats):
    """Route handler: every request (navigation, redirect, subresource) must pass check_url; cross-origin navigations are blocked."""
    origin = _origin(start_url)

    def handler(route):
        req = route.request
        u = req.url
        if urlsplit(u).scheme in ("data", "blob", "about"):
            return route.continue_()
        try:
            check_url(u)
            if req.is_navigation_request() and _origin(u) != origin:
                raise HostRefused("cross-origin navigation")
        except HostRefused:
            stats["blocked"] += 1
            return route.abort()
        return route.continue_()

    return handler


def guard_context(context, start_url, stats):
    """Guard a Playwright context (signup/login/logout browsers)."""
    context.route("**/*", _guard_handler(start_url, stats))


def extract_page(page):
    """Live-DOM marking in the guarded page, then Scrapling parses page.content(). Classification as before."""
    text_len = page.evaluate(MARK_JS)
    try:
        data = parse_page(page.content(), page.url, text_len)
    finally:
        page.evaluate(UNMARK_JS)  # keep saved HTML free of our markers
    for f in data["forms"]:
        f["classification"] = classify_form(f, page.url)
    return data


def fetch_page(session, url, start_url, stats):
    """One Scrapling fetch. The page is route-guarded via page_setup before navigation; markers via page_action."""
    box = {"text_len": 0}

    def mark(page):
        box["text_len"] = page.evaluate(MARK_JS)

    resp = session.fetch(url, page_setup=lambda pg: pg.route("**/*", _guard_handler(start_url, stats)), page_action=mark)
    check_url(resp.url)  # final URL after redirects: same gate, plus same origin
    if _origin(resp.url) != _origin(start_url):
        raise HostRefused("cross-origin final URL")
    data = parse_page(str(resp.html_content), resp.url, box["text_len"])
    for f in data["forms"]:
        f["classification"] = classify_form(f, resp.url)
    data["http_status"] = resp.status  # informational only, never trusted
    data["final_path"] = urlsplit(_norm(resp.url)).path
    return data


def crawl_page(session, start_url, depth=2, max_pages=25, skip=None, stats=None):
    """Same-origin BFS (GET navigation only) over an open Scrapling session. skip(url, link_text) -> True drops a link."""
    origin = _origin(start_url)
    stats = stats if stats is not None else {"blocked": 0}
    pages = {}
    queue, seen = deque([(_norm(start_url), 0)]), {_norm(start_url)}
    while queue and len(pages) < max_pages:
        url, d = queue.popleft()
        try:
            check_url(url)
            data = fetch_page(session, url, start_url, stats)
        except HostRefused as e:
            stats["blocked"] += 1
            pages[url] = {"error": redact(str(e))[:120]}
            continue
        except Exception as e:
            pages[url] = {"error": redact(str(e).splitlines()[0][:120] if str(e) else type(e).__name__)}
            continue
        texts = data.pop("link_text")
        links = sorted({_norm(h) for h in data["links"] if _origin(h) == origin and not (skip and skip(h, texts.get(h, "")))})
        data["links"] = links
        pages[url] = data
        if d < depth:
            for l in links:
                if l not in seen:
                    seen.add(l)
                    queue.append((l, d + 1))
    return pages


def crawl(start_url, depth=2, max_pages=25, headless=True, skip=None, cookies=None):
    """Crawl with Scrapling's StealthySession. Challenge solving stays off: a CAPTCHA/bot wall is never solved."""
    from scrapling.fetchers import StealthySession

    check_url(start_url)
    stats = {"blocked": 0}
    with StealthySession(headless=headless, solve_cloudflare=False, google_search=False, network_idle=True,
                         retries=1, cookies=cookies or []) as session:
        pages = crawl_page(session, start_url, depth, max_pages, skip, stats)
    return {"host": urlsplit(start_url).netloc, "pages": pages, "blocked_requests": stats["blocked"]}


def save_and_diff(sitemap):
    """Cache per host; return what changed versus the previous cached run (re-validation)."""
    CACHE_DIR.mkdir(exist_ok=True)
    f = CACHE_DIR / ("sitemap-" + sitemap["host"].replace(":", "_") + ".json")
    diff = {"previous": False}
    if f.exists():
        old = json.loads(f.read_text(encoding="utf-8")).get("pages", {})
        new = sitemap["pages"]

        def kinds(pg):
            return sorted(x["classification"]["kind"] for p in pg.values() for x in p.get("forms", []))

        diff = {"previous": True, "added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)),
                "forms_changed": kinds(old) != kinds(new)}
    if any("error" in p for p in sitemap["pages"].values()):
        diff["cache_kept"] = "run had errors; previous cache not overwritten"
    else:
        f.write_text(json.dumps(sitemap, indent=1), encoding="utf-8")
    return diff


def report(sitemap, diff):
    safe_print(f"host={sitemap['host']} pages={len(sitemap['pages'])} blocked_requests={sitemap['blocked_requests']}")
    for url, p in sitemap["pages"].items():
        path = urlsplit(url).path
        if "error" in p:
            safe_print(f"  {path}: ERROR {p['error']}")
            continue
        safe_print(f"  {path} (final {p['final_path']}) title={p['title']!r} links={len(p['links'])} buttons={len(p['buttons'])}")
        for f in p["forms"]:
            c = f["classification"]
            names = [f"{x['type']}({x['name'] or x['id']})" for x in f["fields"]]
            safe_print(f"    form -> {c['kind'].upper()} (signup={c['signup_score']} login={c['login_score']}) fields={names}")
    safe_print("revalidation:", json.dumps(diff))
