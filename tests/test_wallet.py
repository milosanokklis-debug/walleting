"""Deposit-flow wallet grab, driven against a fake Playwright page (no browser, no network)."""
import pytest

from authagent import wallet
from authagent.wallet import AMOUNT_RANGE, COIN

BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ETH = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

GROUPS = {"h_id": [{"value": "4", "label": "TYRO TRADE PACKAGE"}],
          "type": [{"value": "process_1006", "label": "Spend funds from BITCOIN"},
                   {"value": "process_1007", "label": "Spend funds from ETHEREUM"}]}


class FakePage:
    """Serves a deposit form; after a JS submit, serves a confirmation page showing that method's address."""

    def __init__(self, groups=GROUPS):
        self.url = "https://s.test/?a=deposit"
        self.groups, self.selected, self.submitted = groups, None, False
        self.addr_by_type = {"process_1006": BTC, "process_1007": ETH}

    def on(self, *a, **k):
        pass

    def goto(self, url, **k):
        self.url, self.selected, self.submitted = url, None, False

    def wait_for_timeout(self, ms):
        pass

    def wait_for_load_state(self, *a, **k):
        pass

    def content(self):
        if self.submitted and self.selected:
            return f"<p>Send your deposit to: {self.addr_by_type.get(self.selected, '')}</p>"
        return "<form name=spendform>deposit 50.00 - 4999.00</form>"

    def evaluate(self, js, arg=None):
        if arg is not None:            # _SET_JS: record the chosen payment method
            self.selected = arg["payVal"]
            return True
        if "[type=submit]" in js:      # _SUBMIT_JS
            self.submitted = True
            return None
        if "input[type=radio]" in js:  # _GROUPS_JS
            return self.groups
        return "Plan 50.00 - 4999.00"  # body innerText for the amount hint


def _patch(monkeypatch, captcha=None):
    import authagent.auth as auth
    monkeypatch.setattr(auth, "_settle", lambda p: None)
    monkeypatch.setattr("authagent.fill.detect_captcha", lambda p: captcha)


def test_grab_reads_one_address_per_method(monkeypatch):
    _patch(monkeypatch)
    out = wallet.grab_wallets(FakePage(), ctx=None, deposit_url="https://s.test/?a=deposit")
    assert out["ok"] is True
    assert set(out["tuples"]) == {(BTC, "bitcoin"), (ETH, "ethereum")}
    assert [m["method"] for m in out["methods"]] == ["Spend funds from BITCOIN", "Spend funds from ETHEREUM"]
    assert {w["method"] for w in out["addresses"]} == {"Spend funds from BITCOIN", "Spend funds from ETHEREUM"}


def test_grab_stops_on_captcha(monkeypatch):
    _patch(monkeypatch, captcha="recaptcha")
    out = wallet.grab_wallets(FakePage(), ctx=None, deposit_url="https://s.test/?a=deposit")
    assert out["ok"] is False and "captcha" in out["reason"]


def test_grab_no_crypto_options(monkeypatch):
    _patch(monkeypatch)
    page = FakePage(groups={"h_id": [{"value": "4", "label": "Plan A"}]})
    out = wallet.grab_wallets(page, ctx=None, deposit_url="https://s.test/?a=deposit")
    assert out["ok"] is False and "no crypto payment options" in out["reason"]


@pytest.mark.parametrize("label,hit", [("Spend funds from BITCOIN", True), ("USDT TRC20", True),
                                       ("Ethereum wallet", True), ("TYRO TRADE PACKAGE", False), ("Gold plan", False)])
def test_coin_label_detection(label, hit):
    assert bool(COIN.search(label)) is hit


def test_amount_range_parses_minimum():
    assert AMOUNT_RANGE.search("Spent 50.00 - 4999.00 daily").group(1) == "50.00"
