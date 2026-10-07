#!/usr/bin/env python3
"""audit-manifest.py - probe every coin repo referenced by manifest-latest.json.

For each distinct repo_url the script:
  * detects whether the repo has moved (HTTP redirect via curl -sI)
  * probes the repo for tags using `git ls-remote` (smart-HTTP git protocol)
  * checks every version tag we hold for that coin against the live tag set
  * detects NEWER upstream tags we are missing (upgrade candidates):
      - newer_same = numeric version tuple strictly newer than the max we hold,
        same component count (high-confidence upgrade signal)
      - newer_alt  = numeric tuple newer but different shape (e.g. <example>
        `3.7.0.1` vs our `v0.17.4.x`) -> flagged for manual review
  * fetches creatordate per tag via ONE bounded shallow git fetch per repo
    (only the tags we hold plus the --top-tags newest by version), so we can
    spot stale repos without downloading full histories.

`git ls-remote` / `git fetch` / `curl` do NOT use the GitHub REST API
(api.github.com), so GitHub API rate limits do not apply. No personal access
token is required.

Output: human-readable report on stdout, optionally a JSON report via --report (parallel to console, single parsable file only when requested).

--param-check adds a fact-check pass that verifies every XBridge-conf and
core-wallet-conf parameter against the coin's own source AT THE EXACT
MANIFEST TAG (one checkout per coin at .cache/audit-manifest/repos/<ticker>:
HEAD checked first, reused only when it already is that tag's commit from
this repo URL AND the tree has no edits or leftover files; otherwise the
exact tag is force-fetched into that folder, switched in and verified;
btcd-family handled via golang layout: chaincfg/params.go + mempool/policy.go).
It is a REPORTING tool: rows state observed values with file:line citations
and, where a value differs from source, the git birth-date of that conf line.
No intent is assumed and param results NEVER affect exit codes; judgment
belongs to whoever reads the report. Statuses are factual:
MATCH/DIFFERS (vs source constant), BROKEN (our own files disagree),
CONFLICT (fleet-level facts: two or more wallets share one P2P/RPC port),
FAIL only where mathematically certain (fee below relay floor -> mempool
rejection; COIN=0 rejected by blocknet; TxVersion above bound; unknown
connector), UNRESOLVED (source constant not located).

Severity policy (deliberate, do not "toughen" without cause):
mismatch vs source is WARN, not FAIL/DIFFERS — every WARN carries the conf
file:line plus the git birth-date of that line, so a reviewer can tell
fleet-reassigned ports (old value, deliberate) from real source drift.
Missing source constant is UNRESOLVED (investigate), never silent SKIP;
SKIP exists only where the key is absent from the conf by design
(e.g. addresstype/changetype not used). Absent keys (deprecatedrpc not
set) are INFO. Checker exceptions never propagate: add_check logs and
records WARN/FAIL with "checker error" detail.

Exit codes: 0 = all probed repos reachable; 1 = at least one repo dead,
moved, or unresolved; 2 = usage/load error.
"""

import sys

from audit_manifest.cli import main

if __name__ == "__main__":
    sys.exit(main())
