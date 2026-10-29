"""Actionable intelligence from scraped pages: crypto wallet addresses, tech fingerprint, contacts.

Authorized-testing feature. It surfaces SITE-side data (e.g. a scam clone's receiving wallets shown to a
logged-in member) so an operator can prove the scrape worked and act on what it found. The operator's own
generated creds are registered secrets and are still masked by secrets.redact_obj before anything is printed
or written; the site's own wallet addresses are not secrets, so they come through.

Base58 addresses (BTC legacy, TRON) are checksum-validated, so a random base58 blob in a script is not reported.
Only the standard library is used (hashlib); no new dependency."""
import hashlib
import re
from urllib.parse import urlsplit

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}

# Coarse candidates; base58 ones are confirmed by _b58check below. 0x+40hex and T+33 are distinctive enough.
_BTC_B58 = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
_BTC_BECH32 = re.compile(r"\bbc1[02-9ac-hj-np-z]{11,71}\b")
_ETH = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CHAT = re.compile(r"smartsupp|tawk\.to|jivochat|livechat|tidio|intercom|crisp\.chat|zendesk|freshchat", re.I)
_SOCIAL = re.compile(r"(?:https?:)?//(?:t\.me/\S+|wa\.me/\d+|api\.whatsapp\.com/send\?phone=\d+"
                     r"|(?:www\.)?(?:twitter|x|facebook|instagram|youtube|telegram)\.com/[\w./?=-]+)", re.I)
_URL = re.compile(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
_GENERATOR = re.compile(r'(?:name|designer)="?(?:generator|designer)"?[^>]*(?:content|href)="?([^">]+)', re.I)


def _b58check(s):
    """Decode base58check; return (payload_without_checksum, ok). ok is False if the 4-byte checksum fails."""
    num = 0
    for ch in s:
        if ch not in _B58_INDEX:
            return None, False
        num = num * 58 + _B58_INDEX[ch]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw  # leading '1's are leading zero bytes
    if len(raw) < 5:
        return None, False
    payload, checksum = raw[:-4], raw[-4:]
    ok = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    return payload, ok


def _valid_btc(addr):
    payload, ok = _b58check(addr)
    return ok and payload[:1] in (b"\x00", b"\x05")  # P2PKH (1...) / P2SH (3...)


def _valid_tron(addr):
    payload, ok = _b58check(addr)
    return ok and payload[:1] == b"\x41"  # TRON mainnet prefix


def extract_addresses(text):
    """Return a sorted, de-duplicated list of (address, cointype) tuples found in text."""
    found = {}
    for m in _ETH.finditer(text):
        found[m.group(0)] = "ethereum"
    for m in _TRON.finditer(text):
        if _valid_tron(m.group(0)):
            found[m.group(0)] = "tron"
    for m in _BTC_B58.finditer(text):
        if _valid_btc(m.group(0)):
            found[m.group(0)] = "bitcoin"
    for m in _BTC_BECH32.finditer(text):
        found[m.group(0)] = "bitcoin"
    return sorted(found.items())


def extract_page_intel(html):
    """Per-page intel from rendered HTML. Scans raw HTML so addresses in input values / data-attrs are caught."""
    return {
        "addresses": extract_addresses(html),
        "emails": sorted(set(_EMAIL.findall(html)))[:20],
        "chat": sorted({m.lower() for m in _CHAT.findall(html)}),
        "social": sorted(set(_SOCIAL.findall(html)))[:20],
        "hosts": sorted(set(_URL.findall(html)))[:40],
        "generator": sorted(set(_GENERATOR.findall(html)))[:5],
    }


def _tech(headers):
    """Server/runtime fingerprint from response headers (case-insensitive)."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return [v for v in (h.get("server"), h.get("x-powered-by"), h.get("x-generator")) if v]


def aggregate_intel(pages, host=None, headers=None):
    """Roll per-page intel into one actionable summary. `pages` is a crawl sitemap's pages dict."""
    wallets, emails, chat, social, hosts, generators = {}, set(), set(), set(), set(), set()
    site = (host or "").split(":")[0].lower()
    for url, p in pages.items():
        pi = p.get("intel")
        if not pi:
            continue
        path = urlsplit(url).path + (("?" + urlsplit(url).query) if urlsplit(url).query else "")
        for addr, coin in pi["addresses"]:
            w = wallets.setdefault(addr, {"address": addr, "cointype": coin, "pages": []})
            if path not in w["pages"]:
                w["pages"].append(path)
        emails.update(pi["emails"])
        chat.update(pi["chat"])
        social.update(pi["social"])
        hosts.update(h for h in pi["hosts"] if site not in h.lower())  # third-party hosts only
        generators.update(pi["generator"])
    return {
        "wallets": [wallets[a] for a in sorted(wallets)],
        "tuples": [(w["address"], w["cointype"]) for w in (wallets[a] for a in sorted(wallets))],
        "tech": sorted(set(_tech(headers)) | generators),
        "emails": sorted(emails),
        "chat_widgets": sorted(chat),
        "contacts": sorted(social),
        "third_party_hosts": sorted(hosts),
    }


def format_intel(intel):
    """Human-readable terminal block. The wallet list of (address, cointype) tuples is printed verbatim."""
    tuples = [tuple(t) for t in intel.get("tuples", [])]  # redact_obj turns tuples into lists; restore for display
    lines = ["=== SITE INTELLIGENCE ===", f"crypto wallets ({len(tuples)}): {tuples}"]
    for w in intel["wallets"]:
        lines.append(f"  {w['address']}  [{w['cointype']}]  seen on: {', '.join(w['pages'])}")
    for label, key in (("tech", "tech"), ("emails", "emails"), ("live chat", "chat_widgets"),
                       ("contacts", "contacts"), ("third-party hosts", "third_party_hosts")):
        vals = intel.get(key)
        if vals:
            lines.append(f"{label}: {', '.join(vals)}")
    return "\n".join(lines)
