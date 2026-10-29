import json
import subprocess
import sys
from pathlib import Path

from authagent import secrets as S
from authagent.run import EXIT_REFUSED, _clean_url, _preflight, build_report, resolve_target, run, write_report

ROOT = Path(__file__).resolve().parent.parent
STEPS = [
    {"step": "allowlist", "pass": True, "at": "2026-01-01T00:00:00", "duration_s": 0, "host": "localhost:8889"},
    {"step": "login", "pass": True, "at": "2026-01-01T00:00:01", "duration_s": 1.2,
     "signals": {"logout_control": True}, "authenticated_html": {"landing": {"path": "runs/x.html", "screenshot": "runs/x.png"}}},
    {"step": "re_login", "pass": True, "at": "2026-01-01T00:00:02", "duration_s": 1.0, "fresh_login": True, "note": "token=abc-SECRETVAL-123"},
]


def test_report_is_valid_json_with_expected_keys(tmp_path):
    S.register_secret("SECRETVAL-123")
    rep = build_report("http://localhost:8889", STEPS, {"routes": [{"path": "/login", "form": "login"}]},
                       "t0", "t1", "passed", str(tmp_path))
    path = write_report(rep, tmp_path)
    loaded = json.load(open(path, encoding="utf-8"))  # must parse: keys are never masked
    assert {"status", "steps", "routes", "artifacts", "failure", "started_at", "finished_at"} <= set(loaded)
    assert [s["step"] for s in loaded["steps"]] == ["allowlist", "login", "re_login"]
    assert all({"at", "duration_s", "pass"} <= set(s) for s in loaded["steps"])
    assert loaded["steps"][2]["fresh_login"] is True
    assert loaded["artifacts"] == ["runs/x.html", "runs/x.png"] and loaded["failure"] is None
    assert "SECRETVAL-123" not in path.read_text(encoding="utf-8")  # values redacted


def test_redact_obj_never_touches_keys():
    S.register_secret("Hunter-2-xyz")  # values are masked by registration or key=value shape; keys are never masked
    out = S.redact_obj({"session_cookie_secret": "ok", "nested": [{"password": "Hunter-2-xyz"}]})
    assert set(out) == {"session_cookie_secret", "nested"}
    assert "Hunter-2-xyz" not in json.dumps(out)


def test_failure_is_reported():
    steps = STEPS[:1] + [{"step": "login", "pass": False, "reason": "bad creds", "at": "t", "duration_s": 0}]
    assert build_report("http://x.test", steps, {}, "a", "b", "failed", "d")["failure"] == {"step": "login", "reason": "bad creds"}


def test_clean_url_drops_query_and_applies_entry():
    assert _clean_url("http://localhost:8890/?token=abc#x") == "http://localhost:8890/"
    assert _clean_url("http://localhost:8890", "join") == "http://localhost:8890/join"


def test_refusal_exit_code_and_report(tmp_path):
    code, rp = run("https://example.com", runs_root=tmp_path)
    rep = json.load(open(rp, encoding="utf-8"))
    assert code == EXIT_REFUSED and rep["status"] == "refused" and rep["failure"]["step"] == "allowlist"


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "authagent", *args], cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_cli_contract_run_refusal_nonzero():
    r = _cli("run", "--url", "https://example.com")
    assert r.returncode == 2 and "refused" in (r.stdout + r.stderr) and "Traceback" not in r.stderr


def test_cli_existing_flags_still_work():
    assert "allowed: a.test" in _cli("--check-url", "http://a.test").stdout
    assert "--url" in _cli("run", "--help").stdout


def test_resolve_target_adds_scheme_and_keeps_full_urls():
    assert resolve_target("8891") == "http://localhost:8891"       # bare port
    assert resolve_target("localhost:8891") == "http://localhost:8891"
    assert resolve_target("myapp.test/join") == "http://myapp.test/join"
    assert resolve_target("[::1]:8891") == "http://[::1]:8891"      # IPv6 literal, scheme only
    assert resolve_target("http://x:1/y") == "http://x:1/y"         # full URL untouched
    assert resolve_target("https://x.test") == "https://x.test"


def test_bare_domain_still_allowlist_refused(tmp_path):
    code, rp = run("example.com", runs_root=tmp_path)  # resolves to http://example.com -> still refused
    assert code == EXIT_REFUSED and json.load(open(rp, encoding="utf-8"))["failure"]["step"] == "allowlist"


def test_preflight_ok_reports_mail_flag():
    pf = _preflight("t0")
    assert pf["step"] == "preflight" and pf["pass"] is True and "mail_reachable" in pf


def test_preflight_fails_without_playwright(monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)  # force the import to fail
    pf = _preflight("t0")
    assert pf["pass"] is False and "Playwright" in pf["reason"]
