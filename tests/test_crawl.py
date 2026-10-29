import pytest

from authagent.classify import classify_form
from authagent.crawl import crawl_page, extract_page, guard_context

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


def kind(page, html, url=""):
    page.set_content(html)
    forms = extract_page(page)["forms"]
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


def test_extract_page_shape_and_cleanup(page):
    page.set_content("<title> T </title><h1>Hi</h1><a href=/a>Go</a><a href=/logout>Sign out</a>"
                     "<form action=/x>" + LOGIN[6:-7] + "<input type=hidden name=h><input name=hid style=display:none></form>")
    d = extract_page(page)
    assert d["title"] == "T" and d["heading"] == "Hi" and d["text_len"] > 0
    assert list(d["link_text"].values())[:2] == ["Go", "Sign out"]
    f = d["forms"][0]
    assert [x["name"] for x in f["fields"]] == ["email", "pw"] and f["fields"][0]["label"] == "Email"
    assert f["buttons"] == ["Sign in"] and f["action"] == "/x"
    assert page.evaluate("document.querySelectorAll('[data-aa-vis],[data-aa-label]').length") == 0


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

    def __init__(self, site):
        self.site, self.fetched = site, []

    def fetch(self, url, page_setup=None, page_action=None):
        from types import SimpleNamespace
        self.fetched.append(url)
        final, html = self.site[url]
        page_action(SimpleNamespace(evaluate=lambda js: 7))
        return SimpleNamespace(url=final, status=200, html_content=html)


def test_crawl_page_follows_same_origin_and_skips():
    b = "http://localhost:1"
    site = {b + "/": (b + "/", f"<a href=/a>A</a><a href=/logout>Out</a><a href=http://example.com/x>X</a>"),
            b + "/a": (b + "/a", "<form data-aa-vis=1><input data-aa-vis=1 type=password name=p><button data-aa-vis=1>Sign in</button></form>")}
    s = FakeSession(site)
    pages = crawl_page(s, b + "/", skip=lambda u, t: "logout" in u)
    assert s.fetched == [b + "/", b + "/a"]
    assert pages[b + "/"]["links"] == [b + "/a"] and pages[b + "/"]["text_len"] == 7
    assert pages[b + "/a"]["forms"][0]["fields"][0]["name"] == "p"


def test_crawl_page_refuses_cross_origin_redirect():
    b = "http://localhost:1"
    stats = {"blocked": 0}
    pages = crawl_page(FakeSession({b + "/": ("http://example.com/", "<a href=/a>A</a>")}), b + "/", stats=stats)
    assert "error" in pages[b + "/"] and stats["blocked"] == 1
