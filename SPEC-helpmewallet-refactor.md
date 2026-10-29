# Spec: Move the /helpmewallet front-end into code; run the skill on Sonnet

## Objective
Today the `/helpmewallet` skill does target resolution, the allowlist/local check, and
preflight *in prose on the Opus main thread*, then calls `python -m authagent run --url <full-url>`.
Move all of that into the deterministic program so no LLM is needed for the front-end, and
make the skill's orchestrator a **Sonnet** subagent that only touches the browser when the
program fails. Opus just dispatches.

Success = running `/helpmewallet localhost:8891` (a bare domain) does the same thing as today's
full-URL call, with zero model reasoning until/unless a pipeline step actually fails.

## Tech stack
Python 3.12 stdlib + Playwright (`authagent/`), Node test sites, Mailpit via Docker.
Update 2026-10-29: crawling (discovery + post-login crawl) uses Scrapling's `StealthySession` (challenge solving off,
allowlist route guard attached per page via `page_setup`); signup/login/logout stay on Playwright. CAPTCHAs are still
never solved.

## Commands
- Run: `python -m authagent run --url <domain|host:port|http(s)://url>` (now accepts a bare host)
- Test: `pytest`
- Skill: `/helpmewallet <localsite>`

## Project structure (touched files only)
```
authagent/run.py        → add resolve_target(); add a preflight step; wire both into run()
authagent/__main__.py    → unchanged interface (`run --url` now also accepts a bare host)
tests/test_run.py        → add resolve_target + preflight unit tests
.claude/agents/wallet-runner.md   → NEW: Sonnet agent that drives the CLI, browser only on failure
.claude/skills/helpmewallet/SKILL.md → rewrite: delegate to wallet-runner; drop the manual resolve/preflight prose
```

## Design

### 1. Target resolution (new `resolve_target(raw) -> url`, called at the top of `run()`)
Rules (local-dev defaults to `http`):
- Has a scheme (`http://`/`https://`) → pass through to the existing `_clean_url` unchanged.
- No scheme → prepend `http://`, then `_clean_url`. Covers:
  - `localhost:8891` → `http://localhost:8891`
  - `myapp.test/join` → `http://myapp.test/join`
  - bare integer `8891` → `http://localhost:8891` (keep the old skill convenience)
  - IPv6 `[::1]:8891` → `http://[::1]:8891` (don't split on `:` inside brackets; just prepend)
- `_clean_url` still drops query/fragment and applies `--entry`. `check_url` (allowlist) runs
  immediately after, unchanged — so a non-local host (`example.com`) is still refused, exit 2.
- The agent/skill NEVER normalizes or checks locality; it passes the raw argument straight through.

### 2. Allowlist / local check
No change — `check_url` already runs first inside `run()` and fails closed. Resolution just
feeds it a canonical URL.

### 3. Preflight (new first step inside `run()`, before discovery; recorded as a `preflight` report step)
- **Playwright importable / chromium present** → hard fail with a clear reason if missing
  (this is the real, actionable env failure; the agent can then run `playwright install chromium`).
- **Mailpit reachability** → best-effort, *informational only* (recorded, non-fatal). The existing
  `email_verify` step already skips cleanly when Mailpit is down, so preflight does NOT gate on it
  and does NOT try to `docker compose up -d` from Python (kept out of the deterministic core;
  bringing Mailpit up stays the agent's job only if the user wants the email path and it's down).
- Preflight failures surface as a normal failed step with a reason, which is exactly the signal the
  wallet-runner agent escalates on.

### 4. `wallet-runner` agent (`.claude/agents/wallet-runner.md`, `model: sonnet`)
- Tools: `Bash`, `Read`, `mcp__Claude_Browser__*`.
- Job: run `python -m authagent run --url <target>`; read the PASS/FAIL/SKIP lines + exit code
  (0 pass / 1 fail / 2 refused / 3 email-skipped); on a FAIL it can't dismiss, open the failing page
  in the browser pane, resolve that one step, and re-run/resume; then report a short summary + the
  report path. Enforces the guardrails (they're already in code): never bypass a CAPTCHA, never print
  credentials, allowlist refusal (exit 2) is final — report it, don't work around it.

### 5. `SKILL.md` rewrite (thin)
`/helpmewallet <localsite>`: spawn the `wallet-runner` Sonnet agent with the raw `<localsite>` and
relay its summary. No normalization, no allowlist reasoning, no preflight prose on the Opus thread.
Keep a one-paragraph guardrail note.

## Testing strategy
`pytest`. Add to `tests/test_run.py`:
- `resolve_target`: bare port, `host:port`, `host:port/path`, full `http`, full `https`, `[::1]:port`,
  and that a non-local host still raises `HostRefused` after resolution (exit 2 path).
- preflight: a passing case, and a simulated Playwright-missing case → failed `preflight` step.
Existing 100+ tests must stay green; legacy `--check-url/--crawl/--signup/--e2e` untouched.

## Boundaries
- **Always:** run `pytest` before done; keep guardrails (allowlist fail-closed, no CAPTCHA bypass, no secret printing); reuse `_clean_url`/`check_url`.
- **Ask first:** changing allowlist defaults; any new dependency; changing the `--url` flag name or exit codes.
- **Never:** print credentials; bypass a CAPTCHA; delete/skip existing tests to make the suite pass.

## Success criteria
1. `python -m authagent run --url localhost:8891` == today's `--url http://localhost:8891` (same steps pass, same report shape).
2. `python -m authagent run --url example.com` → `refused`, exit 2.
3. Legacy flags unchanged; full suite green **plus** the new resolve/preflight tests.
4. `SKILL.md` contains no manual resolve/allowlist/preflight steps and delegates to `wallet-runner` (model: sonnet); the Opus thread only dispatches and relays.
5. A real `/helpmewallet localhost:8891`-style run completes with the Sonnet agent driving.

## Open questions
1. **wallet-runner model:** Sonnet (my recommendation — the browser fallback needs real reasoning) or Haiku (cheaper, weaker on the stuck-page recovery)?
2. **Mailpit in preflight:** leave bring-up to the agent-on-failure path (my recommendation, since email already skips cleanly), or have preflight attempt `docker compose up -d`?
3. **Scheme default** for scheme-less input is `http` (local dev). Fine? (A non-local host is refused regardless.)
