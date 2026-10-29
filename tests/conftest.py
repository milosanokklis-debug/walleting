"""Shared fixtures: Mailpit (assumed or brought up) and a self-managed instance of the 8890 email-auth test site."""
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
SITE_DIR = ROOT / "testsite-email"


def port_open(port, host="localhost"):
    try:  # create_connection tries IPv6 and IPv4 (dev servers often bind only ::1)
        socket.create_connection((host, port), timeout=1).close()
        return True
    except OSError:
        return False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def mailpit():
    """Mailpit must be reachable; if not, try `docker compose up -d` once; otherwise skip the dependent tests."""
    from authagent.mail import MailpitProvider
    p = MailpitProvider()
    if not p.reachable() and shutil.which("docker"):
        subprocess.run(["docker", "compose", "up", "-d"], cwd=ROOT, capture_output=True, timeout=90)
        for _ in range(20):
            if p.reachable():
                break
            time.sleep(1)
    if not p.reachable():
        pytest.skip("Mailpit unreachable - skipping email verification (run `docker compose up -d`)")
    return p


@pytest.fixture(scope="session")
def site_email(mailpit):
    """Start the Node email-auth site (port 8890 if free, else any free port) with SMTP -> Mailpit; stop it afterwards."""
    if not shutil.which("node") or not (SITE_DIR / "node_modules").exists():
        pytest.skip("node or testsite-email/node_modules missing (cd testsite-email && npm install)")
    port = 8890 if not port_open(8890) else free_port()
    env = dict(os.environ, PORT=str(port), BASE_URL=f"http://localhost:{port}", SMTP_HOST="localhost", SMTP_PORT="1025")
    proc = subprocess.Popen(["node", "server.js"], cwd=SITE_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://localhost:{port}"
    try:
        for _ in range(40):
            try:
                if requests.get(base + "/join", timeout=1).status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(0.25)
        else:
            pytest.skip("testsite-email did not start")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(autouse=True)
def _no_real_dotenv(tmp_path, monkeypatch):
    """Never read a developer's real .env; tests that need one set AUTHAGENT_DOTENV themselves."""
    monkeypatch.setenv("AUTHAGENT_DOTENV", str(tmp_path / "no-such.env"))


@pytest.fixture(autouse=True)
def _no_crawl_delay(monkeypatch):
    """Drop the inter-fetch pacing delay so tests don't wait out the real burst-limit throttle."""
    import authagent.crawl as crawl
    monkeypatch.setattr(crawl, "CRAWL_DELAY", 0)
