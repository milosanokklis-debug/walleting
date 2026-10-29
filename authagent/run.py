"""`python -m authagent run --url <site>`: full pipeline with a per-run JSON report. No secrets in report or stdout."""
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import auth
from . import secrets as sec
from .allowlist import HostRefused, check_url

ROOT = Path(__file__).resolve().parent.parent
EXIT_OK, EXIT_FAIL, EXIT_REFUSED, EXIT_INCOMPLETE = 0, 1, 2, 3


def _clean_url(url, entry=None):
    p = urlsplit(url)
    path = entry if entry else p.path
    if path and not path.startswith("/"):
        path = "/" + path
    return f"{p.scheme}://{p.netloc}{path}"  # query/fragment dropped: they can carry tokens


def resolve_target(raw):
    """Bare domain / host:port / bare port / full URL -> a URL with a scheme (http for scheme-less local dev).

    Only adds a scheme; check_url is still the gate, so backslash/userinfo/non-local hosts stay refused.
    """
    s = str(raw).strip()
    if "://" in s:
        return s
    if s.isdigit():  # bare port, the old skill convenience
        s = "localhost:" + s
    return "http://" + s  # IPv6 like [::1]:8891 just gets the scheme; urlsplit handles the brackets


def _preflight(started):
    """Deterministic env checks before the browser pipeline. Playwright missing is a hard fail the agent can fix;
    Mail provider reachability is informational (email_verify already skips cleanly when it is down)."""
    try:
        import playwright.sync_api  # noqa: F401
    except Exception:
        return {"step": "preflight", "pass": False, "at": started, "duration_s": 0,
                "reason": "Playwright not installed (run: playwright install chromium)"}
    from .allowlist import HostRefused
    from .mail import MailConfigError, provider_from_env
    try:
        mail = provider_from_env().reachable()
    except (MailConfigError, HostRefused) as e:  # misconfiguration: stop before signup creates an account
        return {"step": "preflight", "pass": False, "at": started, "duration_s": 0, "reason": "mail provider: " + sec.redact(str(e))[:200]}
    except Exception:
        mail = False
    return {"step": "preflight", "pass": True, "at": started, "duration_s": 0, "mail_reachable": mail}


def _artifacts(steps):
    out = []
    for s in steps:
        for v in (s.get("authenticated_html") or {}).values():
            if isinstance(v, dict):
                out += [x for x in (v.get("path"), v.get("screenshot")) if x]
    return out


def build_report(url, steps, info, started, finished, status, run_dir):
    failed = next((s for s in steps if not s["pass"]), None)
    return {
        "schema": 1, "url": url, "host": urlsplit(url).netloc, "status": status,
        "started_at": started, "finished_at": finished,
        "steps": steps, "routes": info.get("routes", []), "artifacts": _artifacts(steps),
        "failure": ({"step": failed["step"], "reason": failed.get("reason") or failed.get("outcome") or failed.get("errors")}
                    if failed else None),
        "run_dir": run_dir,
    }


def write_report(report, run_dir: Path):
    """Redact string values (never keys), then dump: the file is valid JSON by construction."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "report.json"
    path.write_text(json.dumps(sec.redact_obj(report), indent=1), encoding="utf-8")
    return path


def run(url, entry=None, headless=True, runs_root=None):
    """Returns (exit_code, report_path). Allowlist refusal -> exit 2 with a clear message."""
    runs_root = Path(runs_root or os.environ.get("AUTHAGENT_RUNS_DIR") or ROOT / "runs")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    clean = _clean_url(resolve_target(url), entry)
    host = "".join(c if c.isalnum() or c in ".-" else "_" for c in (urlsplit(clean).netloc or "unknown").lower())
    run_dir = runs_root / f"run-{host}-{stamp}"
    info, steps = {}, []
    try:
        check_url(clean)
    except HostRefused as e:
        steps = [{"step": "allowlist", "pass": False, "at": started, "duration_s": 0, "reason": sec.redact(str(e))[:200]}]
        rp = write_report(build_report(clean, steps, info, started, started, "refused", str(run_dir)), run_dir)
        sec.safe_print(steps[0]["reason"])
        return EXIT_REFUSED, rp
    steps.append({"step": "allowlist", "pass": True, "at": started, "duration_s": 0, "host": urlsplit(clean).netloc})
    pf = _preflight(started)
    steps.append(pf)
    if pf["pass"]:  # a failed preflight (e.g. Playwright missing) stops before the browser; status becomes "failed"
        old = auth.EVIDENCE_DIR
        auth.EVIDENCE_DIR = run_dir  # authenticated-HTML proofs and screenshots land in the run dir
        try:
            steps += auth.e2e(clean, headless=headless, info=info)
        finally:
            auth.EVIDENCE_DIR = old
    finished = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    email_skip = any(s["step"] == "email_verify" and s.get("skipped") for s in steps)
    ok = all(s["pass"] for s in steps)
    status = "skipped_email" if email_skip else "passed" if ok else "failed"
    code = EXIT_INCOMPLETE if email_skip else EXIT_OK if ok else EXIT_FAIL
    rp = write_report(build_report(clean, steps, info, started, finished, status, str(run_dir)), run_dir)
    for s in steps:
        tag = "SKIP" if s.get("skipped") else "PASS" if s["pass"] else "FAIL"
        extra = s.get("reason") or s.get("skipped") or s.get("outcome") or ""
        sec.safe_print(f"{tag} {s['step']}" + (f" - {extra}" if extra and not s["pass"] or s.get("skipped") else ""))
    sec.safe_print(f"status={status} report={rp.relative_to(ROOT).as_posix() if rp.is_relative_to(ROOT) else rp.name}")
    return code, rp
