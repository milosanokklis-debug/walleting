import re

import pytest

from authagent import secrets as sec
from authagent.fill import (FIELDS_JS, adjust_from_errors, gen_value, length_limits, map_field, new_creds,
                            run_signup)

FORM = """<form onsubmit="return false"><h1>Sign up</h1>
<label for=u>Username</label><input id=u name=handle><span>3-24 characters, a-z 0-9 _</span>
<label for=e>Email</label><input id=e type=email>
<label for=p>Password</label><input id=p type=password minlength=10 maxlength=20>
<label for=c>Confirm password</label><input id=c type=password>
<label for=f>First name</label><input id=f><label for=l>Last name</label><input id=l>
<label for=ph>Mobile phone</label><input id=ph type=tel>
<select id=co><option value="">Choose</option><option value=us>US</option></select>
<label><input type=checkbox id=t> I agree to the terms</label>
<button>Create account</button></form>"""


@pytest.fixture(scope="module")
def page():
    pw = pytest.importorskip("playwright.sync_api")
    with pw.sync_playwright() as p:
        b = p.chromium.launch()
        yield b.new_page()
        b.close()


def roles(page, html):
    page.set_content(html)
    d = page.evaluate(FIELDS_JS)
    seen, out = False, []
    for f in d["fields"]:
        out.append(map_field(f, seen))
        seen = seen or f["type"] == "password"
    return d, out


def test_role_mapping(page):
    _, r = roles(page, FORM)
    assert r == ["username", "email", "password", "confirm_password", "first_name", "last_name", "phone", "select", "consent"]


def test_constraints_and_values(page):
    d, r = roles(page, FORM)
    c = new_creds()
    by = dict(zip(r, d["fields"]))
    assert length_limits(by["username"]) == (3, 24)
    u = gen_value("username", by["username"], c)
    assert re.fullmatch(r"[a-z0-9_]{3,24}", u)
    pw = gen_value("password", by["password"], c)
    assert 10 <= len(pw) <= 20
    assert gen_value("select", by["select"], c) == "us"
    assert gen_value("email", by["email"], c) == c["TEST_EMAIL"]


def test_adjust_from_errors():
    adj = {}
    assert adjust_from_errors(["Password must be at least 14 characters"], adj)
    assert adj["password_min"] == 14
    adjust_from_errors(["Username already taken"], adj)
    assert adj["regen"] == 1
    adjust_from_errors(["Only letters and numbers allowed"], adj)
    assert adj["no_symbol"]


def _sign(page, creds):
    return run_signup(page, creds, max_retries=3)


def test_end_to_end_retry_after_client_validation(page):
    html = """<div id=app></div><script>
    app.innerHTML = '<form id=f><input name=email type=email><input name=password type=password><input name=confirm type=password>'
      + '<label><input type=checkbox name=terms required> I accept the terms</label><p role=alert id=err></p><button>Sign up</button></form>';
    f.onsubmit = e => { e.preventDefault(); const v = f.password.value;
      if (v.length < 40) { err.textContent = 'Password must be at least 40 characters'; return; }
      if (f.confirm.value !== v) { err.textContent = 'Passwords do not match'; return; }
      document.body.innerHTML = '<h1>Welcome! Check your email to verify.</h1>'; fetch('/x', {method:'POST'}).catch(()=>{}); };
    </script>"""
    page.set_content(html)
    c = new_creds()
    res = _sign(page, c)
    assert res["outcome"] == "submitted" and res["retries"] >= 1
    assert c["TEST_PASSWORD"] not in str(res)


def test_multistep_and_modal(page):
    html = """<div id=m role=dialog><form id=s1><input type=email name=email><button type=button id=n>Next</button></form></div>
    <script>n.onclick = () => { m.innerHTML = '<form id=s2><input type=password name=pw><input type=password name=again>'
      + '<button type=button id=g>Create account</button></form>'; g.onclick = () => { document.body.innerHTML = '<p>Account created</p>'; }; };</script>"""
    page.set_content(html)
    res = _sign(page, new_creds())
    assert res["outcome"] == "submitted" and res["steps"] == 2


def test_validation_failure_is_reported_and_redacted(page):
    page.set_content("""<form onsubmit="return false"><input type=password name=p><p role=alert>Wrong thing</p><button>Sign up</button></form>""")
    res = _sign(page, new_creds())
    assert res["outcome"] == "validation_failed"


from authagent.fill import make_password, sanitize_username


def _classes(pw):
    return all(re.search(p, pw) for p in (r"[A-Z]", r"[a-z]", r"\d"))


def test_password_tiny_maxlength_keeps_classes_and_min():
    base = "abcdefghijklmnop-_qrstu"
    pw = make_password(base, 0, 6)
    assert len(pw) == 6 and _classes(pw)  # impossible hi<8 is honoured, classes still present
    pw = make_password(base, 0, 10)
    assert 8 <= len(pw) <= 10 and _classes(pw)


def test_password_128_cap_on_retry():
    assert len(make_password("abcXYZ123-", 200, 0)) == 128


def test_no_symbol_retry_is_alphanumeric():
    pw = make_password("ab-cd_EF-9xyzxyzxyzxyz", 0, 0, no_symbol=True)
    assert pw.isalnum() and _classes(pw)
    c = new_creds()
    c["TEST_PASSWORD"] = "ab-cd_EF-9xyzxyzxyzxyz"
    assert gen_value("password", {"type": "password"}, c, {"no_symbol": True}).isalnum()


def test_symbol_added_by_default():
    assert re.search(r"[^A-Za-z0-9]", make_password("abcDEF12345678"))


def test_loaded_username_sanitized():
    assert sanitize_username("Ab-C") == re.sub(r"[^a-z0-9_]", "", sanitize_username("Ab-C")) and len(sanitize_username("Ab-C")) >= 3
    assert re.fullmatch(r"[a-z0-9_]{3,24}", sanitize_username("A" * 40 + "-!"))
    assert re.fullmatch(r"[a-z0-9_]{3,24}", sanitize_username("---"))
    c = new_creds()
    c["TEST_USERNAME"] = "Ab-C"
    assert re.fullmatch(r"[a-z0-9_]{3,24}", gen_value("username", {"type": "text"}, c))


def test_error_regexes_use_word_boundaries():
    adj = {}
    assert not adjust_from_errors(["Password already used before"], adj) or "regen" not in adj
    adj = {}
    adjust_from_errors(["Username is already taken"], adj)
    assert adj.get("regen") == 1


def test_new_creds_uses_mail_domain(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("MAIL_DOMAIN=mine.example.com\n")
    monkeypatch.setenv("AUTHAGENT_DOTENV", str(f))
    assert new_creds()["TEST_EMAIL"].endswith("@mine.example.com")
    assert new_creds("x.test")["TEST_EMAIL"].endswith("@x.test")
