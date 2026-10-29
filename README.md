# authagent

Authorized auth-flow testing for **your own** local sites. It discovers a site's sign-up and login pages, creates a
test account, completes email verification (link or code) through a local mail sink, logs in, confirms the session,
logs out and logs back in. Every request goes through one allowlist gate; anything not on the list is refused.

## Setup

```
python -m venv .venv
.venv\Scripts\activate            # Windows (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
playwright install chromium
scrapling install                 # browser for Scrapling's StealthySession (crawling)
```

## Run the agent

```
python -m authagent run --url http://localhost:8889
python -m authagent run --url http://localhost:8890/join
```

`run` executes: allowlist check, discovery, signup, email verification (only when the site asks for it), login,
success check, post-login crawl, logout, re-login. It prints one PASS/FAIL/SKIP line per step and writes
`runs/run-<host>-<timestamp>/report.json` (step timeline, discovered routes, artifact paths) plus the saved
authenticated-page HTML and a screenshot in the same folder.

Exit codes: `0` passed, `1` a step failed, `2` host refused by the allowlist, `3` email step skipped (mail sink down).

**Sites with no links on their root** (the 8890 test site returns 404 at `/` by design) need an entry page that links to
the rest: put the path in the URL (`.../join`) or pass `--entry /join`.

Other commands:

| Command | What it does |
|---|---|
| `python -m authagent --check-url <url>` | Says whether a URL passes the allowlist |
| `python -m authagent --crawl <url>` | Crawls same-origin, classifies forms (signup / login / other) |
| `python -m authagent --signup <url>` | Discovers and fills the signup form only |
| `python -m authagent --e2e <url>` | Older all-in-one runner (no run directory) |
| `python -m authagent report <report.json>` | Summarizes a finished report |

## Crawling

Crawling (discovery and the post-login crawl) is done entirely by [Scrapling](https://github.com/D4Vinci/Scrapling):
pages are fetched with its `StealthySession` browser and parsed with its HTML parser. Cloudflare/challenge solving is
off: a CAPTCHA or bot wall is never solved. The allowlist still gates every crawl request, including subresources (a
route guard is attached to each page before it loads), every URL is checked before it is fetched, and the final URL
after redirects must pass the allowlist and stay on the same origin. Signup, login and logout run in Playwright behind
the same guard.

The `post_login_crawl` step runs after `login`: Scrapling gets the logged-in context's cookies and does a same-origin
BFS (depth 2, up to 15 pages), GET navigation only, forms are never submitted. Links whose path or text looks like
logout/sign-out, or delete / remove / deactivate / close-account, are skipped. It passes if at least one page was crawled
and the Playwright session is still authenticated after a reload; the report records the page count and a route list
(path, title, form kinds), no HTML or field values.

## The `/helpmewallet` skill

`.claude/skills/helpmewallet/SKILL.md` wraps this pipeline for Claude Code, with AI-in-the-loop fallbacks: when a step
gets stuck (an unfamiliar form, a validation error, an odd "check your email" screen) it takes over in the browser pane,
then resumes. Same guardrails: allowlist only, never bypasses a CAPTCHA, never prints credentials.

```
/helpmewallet 8889
/helpmewallet http://localhost:8890/join
```

## Allowlist

`config/allowlist.yaml` holds the hosts the tool may touch. Defaults: `localhost`, `127.0.0.1`, `*.test` (subdomains of
`test` only). To add a site you own, add it under `user_hosts`:

```yaml
user_hosts:
  - myapp.internal.example
  - "*.staging.example"      # wildcards need at least a two-label suffix
```

Ports are not part of the match. Unreadable or malformed config refuses everything (fail closed).

### `LOCALHOST_ONLY` toggle

Copy `.env.example` to `.env` (gitignored) in the project root:

```
LOCALHOST_ONLY=true
```

`true` is the default, and also what you get if `.env` or the key is missing or the value is not recognised (fail
closed): hosts must match `config/allowlist.yaml`. `false` (also `0` / `no`, case-insensitive) skips only that host
match. Every other URL check still applies (http/https only, no userinfo, no backslash/control/non-ASCII characters,
valid hostname and port), and the same-origin navigation guard in the crawler stays on. Use `false` only against sites
you are authorised to test. Tests point `AUTHAGENT_DOTENV` at another path so they never read your real `.env`.

## Email verification: Mailpit and the 8890 test site

```
docker compose up -d          # Mailpit: SMTP 127.0.0.1:1025, REST API + web UI http://localhost:8025
cd testsite-email
npm install
SMTP_HOST=localhost SMTP_PORT=1025 npm start      # http://localhost:8890 (PowerShell: $env:SMTP_PORT=1025; npm start)
```

Mailpit accepts any recipient domain, so the generated `@authagent.test` address needs no mailbox setup. If Mailpit is
unreachable the email step is reported as a SKIP with a clear message (it does not hang). Other mail systems can plug
in by implementing `authagent.mail.EmailProvider` (`reachable()` and `latest_message()`).

## Email verification for your own remote sites: Cloudflare Email Worker

Only for sites you own, on a domain you own. Cloudflare Email Routing sends every address on the domain to a small
Email Worker (`cloudflare/mail-worker/`) that stores mail in D1 (1 hour retention) and serves the newest message per
recipient at `GET /latest?to=` behind a bearer token. authagent signs up as `agent-xxxx@yourdomain` and polls it.

1. Add your domain to Cloudflare.
2. Enable Email Routing for it (Email > Email Routing).
3. `cd cloudflare/mail-worker && npm install`, then `npx wrangler d1 create authagent-mail` and paste the printed
   `database_id` into `wrangler.toml`. Then `npx wrangler d1 execute authagent-mail --remote --file schema.sql`.
4. `npx wrangler secret put API_TOKEN` (pick a long random value), then `npx wrangler deploy`.
5. In Email Routing, set the catch-all rule to "Send to a Worker" and choose `authagent-mail`.
6. Add the worker host (e.g. `authagent-mail.<you>.workers.dev`) and your remote site to `user_hosts` in
   `config/allowlist.yaml`. Verification links to non-allowlisted hosts are never followed.
7. In `.env`: `MAIL_PROVIDER=cloudflare`, `MAIL_DOMAIN=yourdomain`, `MAIL_API_URL=https://authagent-mail...workers.dev`,
   `MAIL_API_TOKEN=<the token>`. The token is registered for redaction.

Local smoke test: put `API_TOKEN=x` in `cloudflare/mail-worker/.dev.vars` (gitignored), run `npx wrangler d1 execute
authagent-mail --local --file schema.sql` and `npx wrangler dev --local`, POST a `.eml` to
`/cdn-cgi/handler/email?from=a@x.com&to=agent-x@yourdomain`, then `curl -H "Authorization: Bearer x"
'localhost:8787/latest?to=agent-x@yourdomain'`.

## Secrets and git

Generated credentials are written only to `.env.test` (see `.env.test.example` for the keys) and are redacted from stdout,
JSON reports and saved HTML. A seed belongs to one site (`TEST_SITE`); running against a different site sets the old one
aside as `.env.test.prev`. Delete `.env.test` to force a fresh signup on the same site.

Gitignored: `node_modules/`, Playwright browsers (`ms-playwright/`), `.env.test` and every `.env.*` except
`.env.test.example`, `runs/` (reports, saved HTML, screenshots), virtualenvs, logs.

## Tests

```
pytest
```

Unit tests cover the allowlist (allowed, refused, bypass attempts), form classification, value generation, email link /
code extraction, redaction and report JSON validity. The live end-to-end tests (`tests/test_e2e.py`) run the real CLI:

- **8889 flow**: runs when `http://localhost:8889` is up, otherwise skips with a message.
- **Email-auth flow**: the suite starts and stops its own copy of the `testsite-email` site (port 8890 when free, SMTP
  pointed at Mailpit), then runs `/join` -> read the code from Mailpit -> `/verify` -> `/signin`. It skips cleanly if
  Mailpit, Docker or node are unavailable (it tries `docker compose up -d` once).

The e2e tests keep their seed and reports in temp folders, so your real `.env.test` and `runs/` are untouched.
