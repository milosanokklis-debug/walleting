from authagent.intel import (aggregate_intel, extract_addresses, extract_page_intel, format_intel)

# Real, checksum-valid addresses (public, well-known): BTC genesis, a P2SH, a bech32, the USDT-TRC20 contract.
BTC_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
BTC_BECH32 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
ETH = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def test_extracts_each_coin_type():
    text = f"BTC {BTC_P2PKH} P2SH {BTC_P2SH} segwit {BTC_BECH32} ETH {ETH} USDT {TRON}"
    found = dict(extract_addresses(text))
    assert found[BTC_P2PKH] == "bitcoin"
    assert found[BTC_P2SH] == "bitcoin"
    assert found[BTC_BECH32] == "bitcoin"
    assert found[ETH] == "ethereum"
    assert found[TRON] == "tron"


def test_returns_sorted_tuples():
    out = extract_addresses(f"{ETH} and {TRON}")
    assert isinstance(out, list) and all(isinstance(t, tuple) and len(t) == 2 for t in out)


def test_rejects_bad_base58_checksum():
    tampered = BTC_P2PKH[:-1] + ("b" if BTC_P2PKH[-1] != "b" else "c")  # flip the last char -> checksum fails
    assert tampered not in dict(extract_addresses(tampered))
    # a plausible base58 blob from a script is not a wallet
    assert extract_addresses("var id = '3Md2kquuseVeClydGarbageZZZ1111111';") == []


def test_tron_needs_valid_prefix_and_checksum():
    assert dict(extract_addresses(TRON)) == {TRON: "tron"}
    assert extract_addresses("T" + "1" * 33) == []  # right shape, wrong checksum


def test_page_intel_finds_contacts_and_hosts():
    html = ('<a href="mailto:support@westinsafe-holdings.com">mail</a>'
            '<script src="https://www.smartsupp.com/loader.js"></script>'
            '<a href="https://t.me/scamadmin">tg</a>'
            '<meta name="designer" href="https://hyipcustomize.com/">'
            f'<input value="{BTC_P2PKH}">')
    pi = extract_page_intel(html)
    assert (BTC_P2PKH, "bitcoin") in pi["addresses"]
    assert "support@westinsafe-holdings.com" in pi["emails"]
    assert "smartsupp" in pi["chat"]
    assert any("t.me/scamadmin" in s for s in pi["social"])
    assert "www.smartsupp.com" in pi["hosts"]


def test_aggregate_rolls_up_and_drops_own_host():
    pages = {
        "http://site.test/?a=deposit": {"intel": extract_page_intel(f'x {BTC_P2PKH} <a href=https://www.smartsupp.com>c</a>')},
        "http://site.test/?a=wallet": {"intel": extract_page_intel(f'y {BTC_P2PKH} {ETH} <a href=https://site.test/x>s</a>')},
    }
    agg = aggregate_intel(pages, host="site.test", headers={"Server": "Apache", "X-Powered-By": "PHP/5.6.40"})
    wallets = {w["address"]: w for w in agg["wallets"]}
    assert wallets[BTC_P2PKH]["cointype"] == "bitcoin"
    assert sorted(wallets[BTC_P2PKH]["pages"]) == ["/?a=deposit", "/?a=wallet"]  # seen on both
    assert (ETH, "ethereum") in agg["tuples"]
    assert "Apache" in agg["tech"] and "PHP/5.6.40" in agg["tech"]
    assert "www.smartsupp.com" in agg["third_party_hosts"] and "site.test" not in agg["third_party_hosts"]


def test_format_prints_tuple_list():
    agg = aggregate_intel({"http://s.test/p": {"intel": extract_page_intel(ETH)}}, host="s.test")
    out = format_intel(agg)
    assert f"('{ETH}', 'ethereum')" in out
