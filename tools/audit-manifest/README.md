# audit-manifest — manifest audit, conf fact-check and maintenance for this repo

`audit-manifest.py` is the maintenance tool for this repository's coin fleet.
It reads `manifest-latest.json` as the source of truth and answers three
questions:

1. **Is our state still real?** — every upstream repo is probed, every
   version tag we hold is checked against the live tag set, stale/fossil
   repos and missing/conflicting local files are reported.
2. **Do our confs match the coin's own source?** — optional fact-check of
   every `wallet-confs/` and `xbridge-confs/` parameter against the coin's
   C++ (or Go/btcd) source at the exact manifest tag.
3. **What changed upstream?** — newer tags we do not hold yet, mandatory
   hard forks detected in release notes, plus a scaffold for onboarding a
   new coin from its GitHub core-wallet repo.

It is **stdlib-only** (Python ≥ 3.9, no third-party imports) and probes
upstream via `git ls-remote` / `curl` — **no GitHub API token, no rate
limits**.

---

## Layout

| Path | Role |
|---|---|
| `tools/audit-manifest/audit-manifest.py` | The tool (single file) |
| `tools/audit-manifest/dashboard.py` | Textual TUI + one-JSON-object-per-task interface over the tool |
| `tools/audit-manifest/requirements.txt` | Optional: Textual, needed only by the dashboard's TUI |
| `tools/audit-manifest/tests/` | Its tests: `test_audit_manifest_*` cover the tool, `test_dashboard_*` the dashboard |
| `tools/audit-manifest/README.md` | This file |
| `.cache/audit-manifest/` | Local scratch: source clones + changelog cache + reports. Gitignored, never committed |

Everything resolves from the script's own location (`tools/audit-manifest/`),
so the repository is self-contained: a plain `git clone` of this repo is enough
to run it, with no sibling checkouts, no environment variables and no token.

---

## Running it

Every command below runs from the **root of this repository**.

```bash
# 1. Fleet overview — read-only, no cloning, no writes (safe default)
python3 tools/audit-manifest/audit-manifest.py

# 2. Only the coins you name — comma-separated ticker list
python3 tools/audit-manifest/audit-manifest.py --ticker BTC,LTC

# 3. Source fact-check — clones the coin source and verifies every conf
#    parameter. Always batch it: fleet-wide --param-check exceeds timeouts.
python3 tools/audit-manifest/audit-manifest.py \
    --ticker BTC,FIRO --param-check --timeout 10

# 4. Machine-readable report (parallel to console output)
python3 tools/audit-manifest/audit-manifest.py --report /tmp/audit.json
```

`--manifest <path>` overrides the manifest location; by default it is
resolved to `manifest-latest.json` at the root of this repository.

### Modes

| Goal | Flags | Writes to the repo? |
|---|---|---|
| Fleet liveness, missing tags, newer upstream tags, staleness, local cross-check, port collisions | *(none)* | No |
| Offline subset of the same: local cross-check + fleet port matrix, no probe at all | `--local-only` | No |
| Fact-check confs against coin source at the exact manifest tag | `--param-check` (`--fees-only`, `--strict-per-version`) | No |
| Preview any write below — compute it, report it, touch nothing | `--dry-run` | No |
| Auto-fix missing `txindex`, dust placeholder, stale `deprecatedrpc` | `--write-config` | **Yes** |
| Rewrite `MinTxFee` / `FeePerByte` to the strict chain gates | `--fee-write` | **Yes** |
| Reassign colliding P2P/RPC ports (earliest lineage wins) | `--fix-ports` | **Yes** |
| Append the latest upstream tag to `manifest-latest.json` + regen `base.j2` | `--update-versions` (`--replace-versions`) | **Yes** |
| Onboard a new coin from a GitHub core-wallet repo | `--scaffold --repo-url <url>` | Only with `--apply` |
| JSON report | `--report <path>` | Report file only |

`--local-only` runs only the local cross-check, the fleet port matrix and
(when asked) `--param-check`, so it is fast — no remote probes, though a
source checkout still fetches a tag its cache does not hold. Tags,
liveness, staleness and `--update-versions` data are unavailable, and the
report carries a zeroed `summary` with `meta.local_only: true` so a caller
can tell the difference. `--dry-run` applies to every write flag: the
report's `plan[]` entries come back with `applied=false` and the working
tree is untouched.

**Every flag in the "Yes" column edits git-tracked files.** They are strictly
opt-in — nothing is written unless you pass the flag. Review the diff
(`git diff`) before committing; rendered `.conf` files are regenerated from
`manifest-latest.json` + `autobuild/configs/*.base.j2`, never hand-edited.

**The three conf/port write flags imply `--param-check`.** `--write-config`,
`--fee-write` and `--fix-ports` derive their work from the parameter
fact-check, which only runs when `--param-check` is on — so passing any of
them turns it on and prints `NOTE: <flag> implies --param-check; enabling it
now`. That is deliberate: without it those flags would silently do nothing.
The fact-check clones coin source, so factor that cost in (batch it with
`--ticker`, as above). `--update-versions` does not imply anything: it reads
tags, not confs.

### New coin onboarding

```bash
python3 tools/audit-manifest/audit-manifest.py \
    --scaffold --repo-url https://github.com/<org>/<coin>-core
```

This shallow-clones the repo at its newest stable tag and extracts ports,
address/secret prefixes, `COIN` decimals, block time, `TxVersion`, relay fee
constants and daemon/datadir names straight from source, proposing free ports
against the current fleet. Output lands in `/tmp/newcoin_<ticker>/` (override
with `--scaffold-out-dir`); add `--apply` to write the conf pair and manifest
entry into this repo. If the fee constants cannot be resolved from source it
**refuses to emit defaults** rather than guessing.

---

## Dashboard — a TUI for people, one JSON object per task for agents

`dashboard.py` drives `audit-manifest.py` for you: it assembles the right
flags for the task you picked, captures the tool's console output into a
per-verb log, and hands back a single JSON envelope. It adds no auditing of
its own — every verdict still comes from the tool.

```bash
# Interactive. Four tabs (Overview / Findings / Run / Write) plus a detail
# pane, Ctrl+P to pick a task, Ctrl+R to refresh. Needs a TTY and Textual.
python3 tools/audit-manifest/dashboard.py

# One task, one JSON object on stdout:
python3 tools/audit-manifest/dashboard.py findings --tickers BTC,LTC | jq .counts

# Everything after -- reaches audit-manifest.py untouched:
python3 tools/audit-manifest/dashboard.py ports -- --timeout 5
```

With no arguments it starts the TUI when stdout is a TTY; otherwise it
prints the verb list to stderr and exits `2`, so a script can never hang
waiting for a terminal that is not there.

### Verbs

| Verb | What it runs | Default mode |
|---|---|---|
| `list` | manifest entries, no probe | offline |
| `audit` | the full fleet audit | probe + changelog |
| `findings` | aggregated findings, worst-first | probe, `--no-changelog` |
| `param-check` | conf fact-check against coin source | `--local-only` |
| `ports` | fleet port-collision matrix | `--local-only` |
| `cross-check` | missing and orphaned conf files | `--local-only` |
| `plan-fix` | preview every write, apply none | `--local-only --param-check --dry-run` |
| `apply-fix` | apply the conf and port fixes | `--local-only --param-check` (**writes**) |
| `update-versions` | bump manifest versions to the latest tag | `--no-changelog` (**writes**) |
| `scaffold` | extract a new coin entry from a repo URL | preview; `--apply` to write |
| `report` | metadata, summary and counts of the last run | offline |

Each verb has exactly one documented default mode. `--with-probe` widens a
local-only verb, `--with-changelog` widens a `--no-changelog` verb,
`--local-only` narrows anything. Nothing is ever narrowed silently.

**`plan-fix` is expensive on purpose.** It runs the full `--param-check`, so
it touches every coin's source: measured **11 min on a cold cache**. A warm
cache skips the clone — it stays offline only for a tag already checked
out from the same URL with a clean tree; a multi-version run switches
HEAD per version, and every switch past the tag the cache already sits
at costs one refetch. `apply-fix` repeats that work, so run `plan-fix` first,
read it, and only then apply. If all you want is the diff, `--dry-run` is
available on any write verb.

### The JSON envelope

stdout carries exactly one JSON object and nothing else; every
human-readable line goes to stderr, so `dashboard.py findings | jq` always
works.

| Key | Meaning |
|---|---|
| `schema_version` | `1` |
| `verb`, `ok`, `exit_code` | which task, and how it went |
| `counts` | `total`, `by_severity`, `by_category`, `by_coin` |
| `plan_count`, `findings[]`, `plan[]` | the data, without walking the report file |
| `sources` | `report`, `log`, `argv`, `audit_exit_code`, `duration_seconds`, `age_seconds` |
| `summary`, `meta`, `report_schema_version` | copied from the report when one was read |

Verb extras: `cross-check` and `ports` add `local` and `port_collisions`,
`param-check` adds a per-coin `param_check` rollup, `scaffold` adds its
`scaffold` payload, `report` adds `last_run`, `report_path` and `log_path`.

Reports land in `.cache/audit-manifest/<verb>.json`, next to `<verb>.log`
(the tool's full console output) and `<verb>.meta.json` (what produced it);
`last-run.json` and `last-run.meta.json` mirror whichever verb ran last.
Keeping one file per verb is what stops a cheap `ports` run from overwriting
a richer `findings` report.

### Textual

`dashboard.py` imports Textual only when the TUI actually starts, so every
verb above runs on a bare interpreter, exactly like `audit-manifest.py`. To
get the TUI, install the optional dependency into a dedicated venv (`.venv/`
is gitignored):

```bash
python3 -m venv .venv
.venv/bin/pip install -r tools/audit-manifest/requirements.txt
.venv/bin/python tools/audit-manifest/dashboard.py
```

---

## Reports and exit codes

* Console output is always printed; `--report <path>` additionally writes one
  parsable JSON file. Never commit reports.
* `0` — all probed repos reachable
* `1` — at least one repo dead, moved, or unresolved
* `2` — usage / manifest-load error

`dashboard.py` in verb mode keeps its own contract, which answers a
different question — not "is the fleet healthy" but "does a human still have
something to decide":

* `0` — finished, nothing left to decide
* `1` — finished, and something needs acting on: findings, port collisions,
  or planned-but-not-applied writes
* `2` — could not complete: bad usage, the tool exited `2`, or the report
  could not be read

A write verb that really wrote returns `0`, because the work is done. Run it
with `--dry-run` (or `scaffold` without `--apply`) for the preview, which
follows the data-verb rule instead. The envelope's `ok` mirrors this: it is
`false` only for `2`.

Severity is deliberate: a value that differs from source is a **WARN**
(carrying the conf `file:line` and the git birth-date of that line, so a
reviewer can tell a deliberate fleet-reassigned port from real drift), an
unlocatable source constant is **UNRESOLVED** (investigate, never silently
skipped), and **FAIL** is reserved for mathematically certain breakage (fee
below the relay floor, `COIN=0`, `TxVersion` above bound). Parameter results
never change the exit code — judgment belongs to whoever reads the report.

### Version signal and the `versions` block

Held tags come **only** from the manifest's `versions` array — the field
contract in this repository's root `README.md`, where `ver_id` is a unique
identifier for a conf version group (it never yields a tag) and `versions`
must match the upstream git tags exactly. An entry that declares no
versions is audited as `no-tag`; its `ver_id` is never used as a fallback.

Every finding carries a `versions` key with a stable shape
(`schema_version` stays `1`). For `REPO-ACTION` findings it is an object —
`{declared, our_latest, remote_latest, newer_same, newer_alt, missing,
found, tag_count, conf}` — assembled from the manifest entry and the
probe: list-valued keys (`declared`, `missing`, `found`, `newer_same`,
`newer_alt`) are `[]` when there is nothing to report; `our_latest`,
`remote_latest` and `tag_count` are `null` when unavailable (an
unreachable repo has no `tag_count`); `conf` carries the entry's
`ver_id` — the conf version-group identifier. For every other finding the
value is `null`. The dashboard envelope relays the block untouched.

---

## Tests

From the root of this repository:

```bash
python3 -m pytest tools/audit-manifest/ -q
```

The suite covers the version engine, fee policy/floor model, block-time
and tx-time extraction, prefix scoping, scaffold extraction, shared-conf
and per-version audit behaviour; `dashboard.py`'s contract (verbs, flag
translation, exit codes, JSON envelope, report plumbing); and the TUI,
driven through Textual's own runner. Nothing skips on a fresh clone
once `requirements.txt` is installed — without it the TUI tests drop out on
their own and the suite needs nothing beyond `pytest`.

The suite is hermetic: probes are stubbed, `--local-only` is used where a
real invocation is needed, and no test contacts the network or modifies the
working tree — about two seconds without the TUI tests, ten with them.

Most tests build their own fixtures under pytest's tmp dir. Nothing
skips on a fresh clone and no test needs a warm `.cache/audit-manifest/`.

Requires `pytest` (the tool itself does not — it is stdlib-only). The TUI
tests additionally need Textual, from `tools/audit-manifest/requirements.txt`.

---

## Local cache

`.cache/audit-manifest/` holds three things, all disposable:

* **Source checkouts** — `repos/<ticker>`, ONE folder per coin (never per
  tag), used by `--param-check`, `--fee-write`, `apply-fix` and
  `scaffold`. A missing folder is
  shallow-cloned at the exact manifest tag; an existing one is reused
  (offline) only if it already sits at that tag's commit with a clean
  tree and the right origin URL — otherwise the tag is force-fetched and
  switched in. The folder is scratch: switching discards local edits
  and clears stray files. Failures are loud (an ERROR line plus a
  `fetch-failed`/`clone-failed` status in the report — `no-repo-url` or
  `no-valid-ticker` when the manifest entry itself is unusable) and the
  next pass repairs a half-finished switch — except a `.git/index.lock`
  left by a killed run: git names it on the ERROR line and only you can
  remove it. Run one `param-check` pass per coin at
  a time — concurrent runs on one coin share a working tree and a git
  index.
* **Changelog cache** — `.changelog_cache/`, GitHub release bodies already
  probed for mandatory-hard-fork detection.
* **Dashboard artefacts** — `<verb>.json` (the report), `<verb>.log` (the
  tool's full console output) and `<verb>.meta.json` (what produced it), plus
  `last-run.json` / `last-run.meta.json` mirroring the most recent verb. One
  file per verb is what keeps a cheap run from overwriting a richer report.

The directory is gitignored. Delete it (or just `.changelog_cache/`) to force
fresh probes; nothing of value is lost.

Older checkouts (the `<coin>_check` / `<coin>_<tag>_check` /
`scaffold_<ticker>_check` folders, a multi-GB bulk in total) predate the
one-repo-per-coin layout: they are stale, and the tool neither reads nor
deletes them — remove them yourself when you want the space back.
`repos/<ticker>` is scratch too: the tool never deletes a checkout
folder itself (an obstruction it reports is yours to remove);
everything inside one is scratch — nested folders included — and stray
files or leftover staging folders under `repos/` are safe to delete.
