import pytest

from authagent.classify import classify_form
from authagent.crawl import MARK_JS, crawl_page, guard_context, parse_page

SIGNUP = """<form><h2>Create your account</h2><label>Email <input type=email name=email autocomplete=email></label>
<label>Password <input type=password name=pw autocomplete=new-password></label>
<label>Confirm password <input type=password name=pw2></label><button>Join</button></form>"""
LOGIN = """<form><h2>Welcome back</h2><label>Email <input type=email name=email></label>
<label>Password <input type=password name=pw autocomplete=current-password></label>
<button>Sign in</button><a href=#>Forgot password?</a></form>"""
OTHER = """<form role=search aria-label="Site search"><input type=search name=q aria-label=Search><button>Go</button></form>"""
NOFORM_SIGNUP = """<div><h1>Register</h1><input name=u><input type=password name=a><input type=password name=b><button>Go</button></div>"""


@pytest.fixture(scope="module")
def page():
    pw = pytest.importorskip("playwright.sync_api")
    with pw.sync_playwright() as p:
        b = p.chromium.launch()
        yield b.new_page()
        b.close()


def extract(page):
    page.evaluate(MARK_JS)
    return parse_page(page.content(), page.url)


def kind(page, html, url=""):
    page.set_content(html)
    forms = extract(page)["forms"]
    assert len(forms) == 1
    return classify_form(forms[0], url)["kind"]


def test_signup(page):
    assert kind(page, SIGNUP) == "signup"


def test_login(page):
    assert kind(page, LOGIN) == "login"


def test_other(page):
    assert kind(page, OTHER) == "other"


def test_pseudo_form_two_passwords_is_signup(page):
    assert kind(page, NOFORM_SIGNUP) == "signup"


def test_parse_page_shape(page):
    page.set_content("<title> T </title><h1>Hi</h1><a href=/a>Go</a><a href=/logout>Sign out</a>"
                     "<form action=/x>" + LOGIN[6:-7] + "<input type=hidden name=h><input name=hid style=display:none></form>")
    d = extract(page)
    assert d["title"] == "T" and d["heading"] == "Hi"
    assert list(d["link_text"].values())[:2] == ["Go", "Sign out"]
    f = d["forms"][0]
    assert [x["name"] for x in f["fields"]] == ["email", "pw"] and f["fields"][0]["label"] == "Email"
    assert f["buttons"] == ["Sign in"] and f["action"] == "/x"


def test_url_hints_break_ambiguity():
    f = {"fields": [{"type": "password"}], "buttons": ["Continue"], "text": ""}
    assert classify_form(f, "http://x.test/login")["kind"] == "login"
    assert classify_form({"fields": [{"type": "password"}, {"type": "password"}], "buttons": [], "text": ""}, "http://x.test/")["kind"] == "signup"


def test_guard_blocks_non_allowlisted_requests(page):
    ctx = page.context.browser.new_context()
    stats = {"blocked": 0}
    guard_context(ctx, "http://localhost:1/", stats)
    p = ctx.new_page()
    with pytest.raises(Exception):
        p.goto("http://example.com/", timeout=5000)
    assert stats["blocked"] >= 1
    ctx.close()


class FakeSession:
    """Stands in for Scrapling's StealthySession: url -> (final_url, html). No browser, no network."""

    def __init__(self, site, statuses=None):
        self.site, self.fetched = site, []
        self.statuses = dict(statuses or {})  # url -> list of statuses popped per fetch (default 200)

    def fetch(self, url, page_action=None):
        from types import SimpleNamespace
        self.fetched.append(url)
        final, html = self.site[url]
        seq = self.statuses.get(url)
        status = seq.pop(0) if seq else 200
        page_action(SimpleNamespace(evaluate=lambda js: 7))
        return SimpleNamespace(url=final, status=status, html_content=html)


def test_crawl_page_follows_same_origin_and_skips():
    b = "http://localhost:1"
    site = {b + "/": (b + "/", f"<a href=/a>A</a><a href=/logout>Out</a><a href=http://example.com/x>X</a>"),
            b + "/a": (b + "/a", "<form data-aa-vis=1><input data-aa-vis=1 type=password name=p><button data-aa-vis=1>Sign in</button></form>")}
    s = FakeSession(site)
    pages = crawl_page(s, b + "/", skip=lambda u, t: "logout" in u)
    assert s.fetched == [b + "/", b + "/a"]
    assert pages[b + "/"]["links"] == [b + "/a"]
    assert pages[b + "/a"]["forms"][0]["fields"][0]["name"] == "p"


def test_crawl_page_refuses_cross_origin_redirect():
    b = "http://localhost:1"
    stats = {"blocked": 0}
    pages = crawl_page(FakeSession({b + "/": ("http://example.com/", "<a href=/a>A</a>")}), b + "/", stats=stats)
    assert "error" in pages[b + "/"] and stats["blocked"] == 1


def test_route_keeps_route_params_and_drops_tokens():
    from authagent.crawl import route
    assert route("http://x.test/?a=signup") == "/?a=signup"
    assert route("http://x.test/?a=deposit_history") == "/?a=deposit_history"
    assert route("http://x.test/page?p=2") == "/page?p=2"
    # tokens dropped: named secret key, long hex under an unlisted key, long digit value, JWT-ish (dots fail fullmatch)
    assert route("http://x.test/?a=signup&token=abc123&otp=482913") == "/?a=signup"
    assert route("http://x.test/?t=0123456789abcdef0123456789abcdef") == "/"
    assert route("http://x.test/?ref=1234567890123") == "/"
    assert route("http://x.test/verify?code=xyz") == "/verify"
    # order-independent: same key after filtering, sorted
    assert route("http://x.test/?a=x&b=y") == route("http://x.test/?b=y&a=x")


def test_fetch_page_retries_then_succeeds(monkeypatch):
    import authagent.crawl as c
    monkeypatch.setattr(c.time, "sleep", lambda s: None)
    b = "http://localhost:1"
    s = FakeSession({b + "/": (b + "/", "<p>ok</p>")}, statuses={b + "/": [429, 403, 200]})
    data = c.fetch_page(s, b + "/", b + "/", {"blocked": 0})
    assert len(s.fetched) == 3 and data["title"] == ""


def test_fetch_page_raises_when_throttled_out(monkeypatch):
    import authagent.crawl as c
    monkeypatch.setattr(c.time, "sleep", lambda s: None)
    b = "http://localhost:1"
    s = FakeSession({b + "/": (b + "/", "<p>blocked</p>")}, statuses={b + "/": [403] * 9})
    with pytest.raises(RuntimeError, match="throttled"):
        c.fetch_page(s, b + "/", b + "/", {"blocked": 0})
    # a throttled-out page is recorded as an error by crawl_page, never a silent empty page
    pages = c.crawl_page(FakeSession({b + "/": (b + "/", "<p>x</p>")}, statuses={b + "/": [403] * 9}), b + "/")
    assert "error" in pages[b + "/"] and "throttled" in pages[b + "/"]["error"]
