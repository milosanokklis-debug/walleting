import pytest

from authagent.auth import fill_login, is_authenticated, login_once
from authagent.fill import detect_captcha, new_creds, run_signup
from authagent.fill import detect_captcha, new_creds, run_signup

CAPTCHA_FORM = """<form onsubmit="return false"><input name=email type=email><input type=password name=pw>
<div class="g-recaptcha" data-sitekey="x"></div><button>Sign in</button></form>"""
PLAIN_LOGIN = """<form onsubmit="return false"><label>Username<input name=username></label><input type=password name=pw>
<button>Log in</button></form>"""


@pytest.fixture(scope="module")
def ctxpage():
    pw = pytest.importorskip("playwright.sync_api")
    with pw.sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context()
        yield ctx, ctx.new_page()
        b.close()


def test_captcha_detected_and_untouched(ctxpage):
    _, page = ctxpage
    page.set_content(CAPTCHA_FORM + "<script>window.touched=0;document.querySelector('.g-recaptcha').onclick=()=>window.touched++</script>")
    assert detect_captcha(page)
    res = run_signup(page, new_creds())
    assert res["outcome"] == "captcha_detected"
    assert page.evaluate("window.touched") == 0
    assert page.locator("input[name=email]").input_value() == ""  # stopped before filling anything


def test_captcha_text_variant(ctxpage):
    _, page = ctxpage
    page.set_content("<p>Please verify you are human</p><form><input type=password></form>")
    assert detect_captcha(page)


def test_no_captcha_on_plain_form(ctxpage):
    _, page = ctxpage
    page.set_content(PLAIN_LOGIN)
    assert detect_captcha(page) is None


def test_login_fill_uses_stored_creds_verbatim(ctxpage):
    _, page = ctxpage
    page.set_content(PLAIN_LOGIN)
    c = {"TEST_EMAIL": "a@b.test", "TEST_PASSWORD": "Pw-1234567", "TEST_USERNAME": "agent_ab12"}
    roles, clicked = fill_login(page, c)
    assert clicked and roles == ["identifier:username", "password"]
    assert page.locator("input[name=username]").input_value() == "agent_ab12"
    assert page.locator("input[name=pw]").input_value() == "Pw-1234567"


def test_login_stops_on_captcha(ctxpage):
    ctx, page = ctxpage
    ctx.route("http://localhost:9/login", lambda r: r.fulfill(body=CAPTCHA_FORM, content_type="text/html"))
    r = login_once(page, ctx, "http://localhost:9/login", {"TEST_EMAIL": "a@b.test", "TEST_PASSWORD": "x", "TEST_USERNAME": "u"})
    assert not r["ok"] and r["reason"].startswith("captcha_detected")
    assert page.locator("input[name=email]").input_value() == ""


def test_success_needs_two_signals():
    assert not is_authenticated({"logout_control": False, "left_login_page": True, "browser_state_set": False, "me_user": False})
    assert is_authenticated({"logout_control": True, "left_login_page": False, "browser_state_set": False, "me_user": True})


# ---- DEV-004 r1 fixes ----
import re as _re

from authagent import auth as A
from authagent import secrets as S


def test_weak_signals_alone_do_not_pass():
    assert not is_authenticated({"logout_control": False, "me_user": False, "left_login_page": True, "browser_state_set": True})
    assert is_authenticated({"logout_control": True, "me_user": False, "left_login_page": True, "browser_state_set": False})


BAD_LOGIN = """<script>document.cookie='csrf=abc; path=/'</script><form onsubmit="return false"><input name=username>
<input type=password name=pw><button id=b>Log in</button></form>
<script>b.onclick=()=>history.pushState({}, '', '/fail')</script>"""


def test_csrf_cookie_plus_error_redirect_is_not_success(ctxpage):
    ctx, page = ctxpage
    ctx.route("http://localhost:9/login", lambda r: r.fulfill(body=BAD_LOGIN, content_type="text/html"))
    r = login_once(page, ctx, "http://localhost:9/login", {"TEST_EMAIL": "a@b.test", "TEST_PASSWORD": "x", "TEST_USERNAME": "u"})
    assert r["ok"] is False and r["signals"]["left_login_page"]


def test_fill_error_does_not_leak_password(ctxpage, monkeypatch):
    ctx, page = ctxpage
    monkeypatch.setattr(A, "FILL_TIMEOUT", 600)
    ctx.route("http://localhost:9/ro", lambda r: r.fulfill(
        body="<form><input name=username><input type=password name=pw readonly><button>Log in</button></form>", content_type="text/html"))
    pw = "Sup3rSecretPw-zz"
    S.register_secret(pw)
    r = login_once(page, ctx, "http://localhost:9/ro", {"TEST_EMAIL": "a@b.test", "TEST_PASSWORD": pw, "TEST_USERNAME": "u"})
    assert r["ok"] is False and pw not in str(r)


def test_failure_reason_masks_secret():
    S.register_secret("TopSecret-123")
    assert "TopSecret-123" not in A.failure_reason(RuntimeError("fill('TopSecret-123') timed out\nstack"))


def test_captcha_appears_on_step_two(ctxpage):
    _, page = ctxpage
    page.set_content("""<div id=m><form id=s1><input type=email name=email><button type=button id=n>Next</button></form></div>
    <script>n.onclick=()=>{m.innerHTML='<form><input type=password name=a><input type=password name=b><input name=captcha_answer><button>Go</button></form>'}</script>""")
    res = run_signup(page, new_creds())
    assert res["outcome"] == "captcha_detected" and res["steps"] >= 1


def test_captcha_name_only_is_detected(ctxpage):
    _, page = ctxpage
    page.set_content("<form><input name=captcha><button>Go</button></form>")
    assert detect_captcha(page)


def test_oauth_and_forgot_buttons_not_chosen(ctxpage):
    _, page = ctxpage
    page.set_content("""<form onsubmit="return false"><input name=username><input type=password name=pw>
    <button type=button id=g>Sign in with Google</button><button type=button id=f>Forgot password?</button></form>""")
    roles, status = fill_login(page, {"TEST_EMAIL": "a@b.test", "TEST_PASSWORD": "x", "TEST_USERNAME": "u"})
    assert status == "no_submit"


def test_captured_authenticated_html(ctxpage, tmp_path, monkeypatch):
    _, page = ctxpage
    monkeypatch.setattr(A, "EVIDENCE_DIR", tmp_path)
    pw = "Zz-captured-Pw-99"
    S.register_secret(pw)
    page.set_content(f"<title>Home</title><p>Hi agent_ab12</p><button>Log out</button><meta name=csrf-token content=abc123tok>"
                     f"<div data-debug='{pw}'></div>")
    creds = {"TEST_EMAIL": "a@b.test", "TEST_PASSWORD": pw, "TEST_USERNAME": "agent_ab12"}
    proof = A.capture_html(page, "login", creds)
    saved = (tmp_path / proof["path"].split("/")[-1]).read_text(encoding="utf-8")
    assert _re.search("log out", saved, _re.I) and proof["authed_marker"]["logout_control"] and proof["authed_marker"]["username_visible"]
    assert pw not in saved and "abc123tok" not in saved and proof["no_leak"]


@pytest.mark.parametrize("url,text", [
    ("http://a.test/logout", "x"), ("http://a.test/auth/sign_out", ""), ("http://a.test/x", "Log out"), ("http://a.test/x", "Sign-out"),
    ("http://a.test/account/delete", ""), ("http://a.test/x", "Remove card"), ("http://a.test/x", "Deactivate"),
    ("http://a.test/close-account", ""), ("http://a.test/x", "Close my account"),
    ("http://a.test/account?action=logout", ""), ("http://a.test/?do=sign_out", ""),
])
def test_skip_link_blocks_logout_and_destructive(url, text):
    from authagent.auth import skip_link
    assert skip_link(url, text)


@pytest.mark.parametrize("url,text", [("http://a.test/dashboard", "Home"), ("http://a.test/settings", "Settings"), ("http://a.test/", "")])
def test_skip_link_allows_normal(url, text):
    from authagent.auth import skip_link
    assert not skip_link(url, text)
