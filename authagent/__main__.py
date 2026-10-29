import argparse
import json

p = argparse.ArgumentParser(prog="authagent", description="Authorized auth-flow testing agent (allowlist-gated).")
p.add_argument("--check-url", metavar="URL", help="verify URL passes the allowlist")
p.add_argument("--crawl", metavar="URL", help="crawl a site (allowlist-gated) and classify forms")
p.add_argument("--depth", type=int, default=2)
p.add_argument("--max-pages", type=int, default=25)
p.add_argument("--signup", metavar="URL", help="discover and fill the signup form; creds go to .env.test only")
p.add_argument("--e2e", metavar="URL", help="discover, signup, login, logout, re-login (allowlist-gated)")
sub = p.add_subparsers(dest="cmd")
r = sub.add_parser("run", help="full pipeline: allowlist, discovery, signup, (email), login, logout, re-login + JSON report")
r.add_argument("--url", required=True, help="site URL (an entry path such as /join may be included or passed via --entry)")
r.add_argument("--entry", help="optional entry path, e.g. /join when the site root has no links")
r.add_argument("--headed", action="store_true", help="show the browser")
r.add_argument("--grab-wallets", action="store_true",
               help="opt-in: submit the logged-in deposit form per crypto method to reveal the site's receiving wallets (no funds sent)")
rp = sub.add_parser("report", help="render a run's report.json to a self-contained report.html next to it")
rp.add_argument("report_json")
a = p.parse_args()


def run(fn):
    """Any failure exits with only the redacted first line: Playwright tracebacks can embed filled values."""
    from .auth import failure_reason
    try:
        return fn()
    except Exception as e:
        raise SystemExit(failure_reason(e)) from None


if a.cmd == "report":
    from .report_html import write_report_html
    print(write_report_html(a.report_json))
    raise SystemExit(0)
if a.cmd == "run":
    from .run import run as pipeline
    code, _ = run(lambda: pipeline(a.url, entry=a.entry, headless=not a.headed, grab_wallets=a.grab_wallets))
    raise SystemExit(code)
if a.e2e:
    from .auth import e2e, report
    raise SystemExit(0 if run(lambda: report(e2e(a.e2e))) else 1)
if a.signup:
    from .fill import signup
    from .secrets import safe_print
    safe_print("signup result:", json.dumps(run(lambda: signup(a.signup))))
if a.crawl:
    from .crawl import crawl, report, save_and_diff
    sm = run(lambda: crawl(a.crawl, a.depth, a.max_pages))
    report(sm, save_and_diff(sm))
if a.check_url:
    from .allowlist import check_url
    print("allowed:", run(lambda: check_url(a.check_url)))
