import pytest

from authagent.allowlist import HostRefused, check_url
from authagent import secrets as sec


@pytest.mark.parametrize("u", ["http://localhost:3000/x", "https://127.0.0.1/", "https://app.test/login", "http://LOCALHOST"])
def test_allowed(u):
    assert check_url(u)


@pytest.mark.parametrize("u", [
    "https://example.com", "http://test", "https://evil.com/?a=localhost", "http://localhost@evil.com/",
    "https://localhost.evil.com", "https://eviltest", "ftp://localhost", "localhost", "", "http://evil.com#.test",
    "http://evil.com\\@localhost/", "http://evil.com\\.test/", "http://evil.com\\@a.test/", "http://evil.test.example.com",
    "http://..test", "http://a..test", "http://localhost:abc", "http://u:p@localhost/", "http://local\nhost",
    "http://localhost\x00.evil.com", "http://löcalhost",
])
def test_refused(u):
    with pytest.raises(HostRefused):
        check_url(u)


def test_missing_allowlist_fails_closed(tmp_path):
    from authagent.allowlist import load_allowlist
    with pytest.raises(HostRefused):
        load_allowlist(tmp_path / "nope.yaml")


def test_redaction():
    sec.register_secret("s3cr3tVALUE")
    out = sec.redact("login with s3cr3tVALUE; Cookie: sid=abc123; password=hunter2")
    assert "s3cr3tVALUE" not in out and "abc123" not in out and "hunter2" not in out


def test_env_seed_only_env_test(tmp_path):
    with pytest.raises(ValueError):
        sec.write_env_seed(path=tmp_path / "creds.txt")
    p = sec.write_env_seed(path=tmp_path / ".env.test")
    pw = dict(l.split("=", 1) for l in p.read_text().splitlines())["TEST_PASSWORD"]
    assert pw not in sec.redact(f"pw is {pw}")


def test_refusal_does_not_echo_password():
    with pytest.raises(HostRefused) as e:
        check_url("ftp://user:SECRETpw@localhost")
    assert "SECRETpw" not in str(e.value)


def test_check_url_fails_closed_on_bad_config(tmp_path, monkeypatch):
    import authagent.allowlist as a
    monkeypatch.setattr(a.load_allowlist, "__defaults__", (tmp_path / "nope.yaml",))
    with pytest.raises(HostRefused):
        check_url("http://localhost")


def test_config_shape(tmp_path):
    from authagent.allowlist import load_allowlist
    for body in ["defaults: localhost\n", 'defaults: ["*.com"]\n', "user_hosts: [1]\n", "- x\n"]:
        f = tmp_path / "a.yaml"
        f.write_text(body)
        with pytest.raises(HostRefused):
            load_allowlist(f)
    with pytest.raises(HostRefused):
        check_url("http://l", allowlist="localhost")
    with pytest.raises(HostRefused):
        check_url("http://a.com", allowlist=["*.com"])


@pytest.mark.parametrize("t", [
    "TEST_PASSWORD=abc123", '{"password": "abc123"}', "access_token=abc123", "auth_token: abc123", "csrf_token=abc123",
    "sessionid=abc123", "pwd=abc123", '{"name": "sid", "cookie": "abc123"}', "Authorization: Bearer abc123",
])
def test_redaction_forms(t):
    assert "abc123" not in sec.redact(t)


def test_fresh_process_loads_seed(tmp_path):
    p = sec.write_env_seed({"TEST_EMAIL": "x@a.test", "TEST_PASSWORD": "Zq9-unique"}, path=tmp_path / ".env.test")
    with pytest.raises(FileExistsError):
        sec.write_env_seed(path=p)
    sec._known.clear()
    assert "Zq9-unique" in sec.redact("bare Zq9-unique here")  # not yet registered
    sec.load_env_seed(p)
    assert "Zq9-unique" not in sec.redact("bare Zq9-unique here")


def _dotenv(tmp_path, monkeypatch, body):
    f = tmp_path / ".env"
    f.write_text(body)
    monkeypatch.setenv("AUTHAGENT_DOTENV", str(f))


@pytest.mark.parametrize("v", ["false", "FALSE", "0", "no", " False "])
def test_localhost_only_false_allows_other_hosts(tmp_path, monkeypatch, v):
    _dotenv(tmp_path, monkeypatch, f"X=1\nLOCALHOST_ONLY={v}\n")
    assert check_url("https://example.com/x") == "example.com"


@pytest.mark.parametrize("u", [
    "http://u:p@example.com/", "http://example.com\\@a.com/", "ftp://example.com", "http://exa\nmple.com",
    "http://example.com:abc", "http://..example.com", "http://exämple.com", "example.com",
])
def test_localhost_only_false_keeps_url_checks(tmp_path, monkeypatch, u):
    _dotenv(tmp_path, monkeypatch, "LOCALHOST_ONLY=false")
    with pytest.raises(HostRefused):
        check_url(u)


@pytest.mark.parametrize("body", [None, "", "OTHER=1", "LOCALHOST_ONLY=banana", "LOCALHOST_ONLY=", "LOCALHOST_ONLY=true"])
def test_localhost_only_default_restricted(tmp_path, monkeypatch, body):
    if body is not None:
        _dotenv(tmp_path, monkeypatch, body)
    with pytest.raises(HostRefused):
        check_url("https://example.com")
    assert check_url("http://localhost")


def test_dotenv_reader(tmp_path, monkeypatch):
    assert sec.dotenv("A", "d") == "d"  # missing file (conftest points at a nonexistent path)
    _dotenv(tmp_path, monkeypatch, "A=1\nB='two'\nC=\"three\"\n# D=4\n")
    assert (sec.dotenv("A"), sec.dotenv("B"), sec.dotenv("C"), sec.dotenv("D"), sec.dotenv("D", "x")) == ("1", "two", "three", None, "x")
    (tmp_path / "bad.env").write_bytes(b"A=\xff\xfe\n")
    monkeypatch.setenv("AUTHAGENT_DOTENV", str(tmp_path / "bad.env"))
    assert sec.dotenv("A", "d") == "d"
