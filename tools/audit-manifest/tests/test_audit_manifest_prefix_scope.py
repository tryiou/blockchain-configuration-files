#!/usr/bin/env python3
"""
Proof-first regression tests for prefix scope priority (PART evidence).

CppSourceInspector.prefix_value tried the std::vector(...) pattern over the
whole mainnet slice BEFORE the brace {..} pattern, so a dead legacy setter
later in the slice (Particl CMainParams::SetOld at chainparams.cpp:665-667,
Bitcoin fossils 0/5/128) shadowed the live brace assignments 100 lines
earlier (chainparams.cpp:566/567/570, 0x38/0x3c/0x6c = 56/60/108).

Rule: earliest match in slice order wins, regardless of which syntactic
form matched. These must FAIL before the fix and PASS after.
"""

import audit_manifest as audit

prefix_value = audit.CppSourceInspector.prefix_value

# Live brace assignments first, dead SetOld vector assignments later —
# reduced Particl CMainParams shape (values/lines mirror the real file).
PARTICL_SHAPED = """\
        base58Prefixes[PUBKEY_ADDRESS]     = {0x38}; // P
        base58Prefixes[SCRIPT_ADDRESS]     = {0x3c};
        base58Prefixes[SECRET_KEY]         = {0x6c};
    void SetOld()
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
"""


def test_live_brace_beats_dead_vector():
    val, ln = prefix_value(PARTICL_SHAPED, 0, len(PARTICL_SHAPED), "PUBKEY_ADDRESS")
    assert val == 0x38, f"dead SetOld shadowed live value: {val!r} @{ln}"
    assert ln == 1, f"wrong line: {ln}"
    val, _ = prefix_value(PARTICL_SHAPED, 0, len(PARTICL_SHAPED), "SCRIPT_ADDRESS")
    assert val == 0x3C, f"dead SetOld shadowed live value: {val!r}"
    val, _ = prefix_value(PARTICL_SHAPED, 0, len(PARTICL_SHAPED), "SECRET_KEY")
    assert val == 0x6C, f"dead SetOld shadowed live value: {val!r}"


def test_vector_only_still_resolves():
    # Old-style coins have only the vector form — no regression.
    txt = "        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,30);\n"
    val, ln = prefix_value(txt, 0, len(txt), "PUBKEY_ADDRESS")
    assert (val, ln) == (30, 1)


def test_brace_only_still_resolves():
    txt = "        base58Prefixes[SECRET_KEY] = {0x6c};\n"
    val, ln = prefix_value(txt, 0, len(txt), "SECRET_KEY")
    assert (val, ln) == (0x6C, 1)
