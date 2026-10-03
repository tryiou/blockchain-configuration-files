#!/usr/bin/env python3
"""
Proof-first R9 regression tests for coin-scaffold defects.

CONFIRMED bug 1 (live XVG v26.8 evidence): CppExpressionEvaluator.resolve_cexpr()
searches raw file text INCLUDING //-commented lines. Verge src/amount.h carries
a commented-out `// static const CAmount CENT = 1000000;` above the active
`static const CAmount CENT = 10000;`, so the relay resolves to 10*1000000 =
10,000,000 sat/kB instead of 100,000 — and the scaffold emits
MinTxFee=6780000/FeePerByte=15000, 100x above the correct 67800/150.
This test must FAIL before the fix (rate == 10000000) and PASS after (100000).

New behavior 2: CoinScaffolder.derive_identity() must read daemon + datadir
names from source (Makefile.am bin_PROGRAMS, GetDefaultDataDir) instead of
guessing from the ticker, so --apply output is committable without hand-edits.
"""

import audit_manifest as audit


def _make_verge_like_tree(tmp_path):
    """XVG-shaped: commented CENT above the active one; Verge daemon layout."""
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "amount.h").write_text(
        "// static const CAmount CENT = 1000000;\n"
        "static const CAmount COIN = 100000000;\n"
        "static const CAmount CENT = 10000;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "validation.h").write_text(
        "static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 10 * CENT;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "Makefile.am").write_text(
        "/* license block spanning\n"
        "   multiple lines with bin_PROGRAMS mentioned inside */\n"
        "bin_PROGRAMS =\n"
        "bin_PROGRAMS += verged\n"
        "bin_PROGRAMS += verge-cli verge-tx\n"
        "check-symbols: $(bin_PROGRAMS)\n"
        "\t$(AM_V_at) READELF=$(READELF) < $(bin_PROGRAMS)\n",
        encoding="utf-8",
    )
    util = tmp_path / "src" / "util"
    util.mkdir(parents=True)
    (util / "system.cpp").write_text(
        "fs::path GetDefaultDataDir()\n"
        "{\n"
        '    // Mac: ~/Library/Application Support/VERGE\n'
        '    // Unix: ~/.verge\n'
        "#ifdef WIN32\n"
        '    return GetSpecialFolderPath(CSIDL_APPDATA) / "VERGE";\n'
        "#else\n"
        "#ifdef MAC_OSX\n"
        '    return pathRet / "Library/Application Support/VERGE";\n'
        "#else\n"
        '    return pathRet / ".VERGE";\n'
        "#endif\n"
        "#endif\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_commented_cent_ignored(tmp_path):
    src = _make_verge_like_tree(tmp_path)
    rate, rate_ev, _, _ = audit.CppSourceInspector.fee_constants(src)
    assert rate == 100000, (
        f"relay must resolve via ACTIVE CENT=10000 -> 10*10000=100000, got {rate!r} ({rate_ev})"
    )


def test_derive_identity_from_source(tmp_path):
    src = _make_verge_like_tree(tmp_path)
    ident = audit.CoinScaffolder.derive_identity(src, "XVG")
    assert ident["daemon"] == "verged", f"daemon must be verged, got {ident!r}"
    assert ident["conf_name"] == "verge.conf", f"conf_name must be verge.conf, got {ident!r}"
    assert ident["dir_linux"] == "VERGE", f"linux dir must be VERGE, got {ident!r}"
    assert ident["dir_mac"] == "VERGE", f"mac dir must be VERGE, got {ident!r}"
    assert ident["dir_win"] == "VERGE", f"win dir must be VERGE, got {ident!r}"


VERGE_AMOUNT_H = """#include <stdint.h>
/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

// static const CAmount COIN = 100000000;
// static const CAmount CENT = 1000000;
// Use peercoin standard
static const CAmount COIN = 1000000;
static const CAmount CENT = 10000;
"""


def test_coin_ignores_commented_definition(tmp_path):
    """CONFIRMED bug 2 (live XVG v26.8 evidence): the COIN regexes run on raw
    file text, so Verge's commented-out `// ... COIN = 100000000;` wins over
    the active `COIN = 1000000` (6 decimals, peercoin standard). The scaffold
    then emits COIN=100000000 and check_coin passes 1e8==1e8 — self-consistent
    wrongness, 100x fund-loss risk. Must resolve 1000000."""
    value, ev = audit.CppSourceInspector.coin_value_from_amount_h(
        VERGE_AMOUNT_H, "src/amount.h", tmp_path)
    assert value == 1000000, f"COIN must resolve via ACTIVE definition -> 1000000, got {value!r} ({ev})"


def test_check_coin_passes_corrected_conf(tmp_path):
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "amount.h").write_text(VERGE_AMOUNT_H, encoding="utf-8")
    coin = audit.ManifestCoin(ticker="XVG", ver_id="verge--v26.8")
    status, msg = audit.CppSourceInspector.check_coin(
        coin, tmp_path, {"COIN": "1000000"})
    assert status == audit.ParamStatus.PASS, (
        f"conf COIN=1000000 must match source 1000000, got {status!r} ({msg})"
    )
