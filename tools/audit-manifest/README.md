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
| `tools/audit-manifest/audit-manifest.py` | Shim (59 lines) into `audit_manifest/` |
| `tools/audit-manifest/audit_manifest/` | Engine: probe, param-check, fixers, applier (`apply_plan.py`), scaffold, versions |
| `tools/audit-manifest/dashboard/` | Textual TUI: verbs, runner, screens, widgets, state, paths (`model.py` holds pure fleet math) |
| `tools/audit-manifest/requirements.txt` | Optional: textual for the TUI; ruff and mypy for the test/lint gates |
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
resolved to `manifest-latest.json` at the root of this repository. The
manifest's directory must be the repo root: the data verbs (probe,
param-check, write flags, report) refuse with exit 2 when `wallet-confs/`
or `xbridge-confs/` is missing next to the manifest, since every fact
they report or write is anchored there.

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
| Read version data from a probe report instead of probing (offline) | `--versions-from <report>` (with `--update-versions`) | No |
| Apply a reviewed plan file with per-entry old verification | `--apply-plan <plan>` | **Yes** |
| Remove coins from the manifest plus every coin file | `--delist --ticker X` (`--dry-run` to preview) | **Yes** |
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

**Port checks ride along with the conf write flows.** `--write-config` and
`--fee-write` imply `--fix-ports`, so a write without it still plans the
collision moves; a bare `--dry-run` implies nothing — with nothing else to
plan, collisions stay reported as findings instead of moves. Every port
write re-verifies fleet freedom at apply time, refusing instead of
introducing a collision the plan predates.

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
against the current fleet (a crowded-out fleet refuses instead of staging a
collision). Output lands in `/tmp/newcoin_<ticker>/` (override
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
# Interactive. Two screens — pick the coin scope, then work in the
# workspace (task groups, Findings/Plan/Log, detail pane). Ctrl+P picks a
# task, Ctrl+R refreshes. Needs a TTY and Textual.
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

| Verb | What it runs | Default mode | Cost | TUI answers in |
|---|---|---|---|---|
| `list` | manifest entries, no probe | offline | local | Log |
| `audit` | the full fleet audit | probe + changelog | network | Findings |
| `findings` | aggregated findings, worst-first | probe, `--no-changelog` | network | Findings |
| `param-check` | conf fact-check against coin source | `--local-only` | heavy | Findings |
| `ports` | fleet port-collision matrix | `--local-only` | local | overview |
| `cross-check` | missing and orphaned conf files | `--local-only` | local | overview |
| `plan-fix` | preview every write, apply none | `--local-only --param-check --dry-run` | heavy | Plan |
| `apply-fix` | apply the conf and port fixes | `--local-only --param-check` (**writes**) | heavy | Plan |
| `apply-plan` | apply a reviewed plan file | `--apply-plan <file>` (**writes**) | local | Plan |
| `update-versions` | bump manifest versions to the latest tag | changelog probe (**writes**, gate live) | network | Plan |
| `scaffold` | extract a new coin entry from a repo URL | preview; `--apply` to write | network | Plan |
| `delist` | preview removal of ticked coins | `--delist --dry-run` | local | Plan |
| `analyze` | probe the fleet (TUI depth toggles available) | probe, `--no-changelog` | network | Findings |
| `report` | metadata, summary and counts of the last run | offline | local | Log |

The Findings tab merges every fleet finding-slot (`findings.json`,
`audit.json`, `param-check.json`, `analyze.json`) into one row per coin — newest row
wins per coin+check, scoped runs never leak in. The overview's
Sources ledger names each slot's row count and age, plus the ports
collision map and the cross-check missing/orphan lists. The ledger
also falls back to a fresh probe report's embedded sections when no
dedicated ports/cross-check run exists yet.

Cost: `local` reads this checkout only, `network` talks to upstream,
and `heavy` is network plus minutes (see `plan-fix` below). The TUI
shows the same classes as `[local]`, `[network]` and `[network (slow)]`
on each task row.

Each verb has exactly one documented default mode. `--with-probe` widens a
local-only verb, `--with-changelog` widens a `--no-changelog` verb,
`--local-only` narrows anything. Nothing is ever narrowed silently.

**`plan-fix` is expensive on purpose.** It runs the full `--param-check`, so
it touches every coin's source: expect minutes, scaling with fleet size
and connection. A warm
cache skips the clone — it stays offline only for a tag already checked
out from the same URL with a clean tree; a multi-version run switches
HEAD per version, and every switch past the tag the cache already sits
at costs one refetch. Applying never re-derives: `apply-fix` and
`--apply-plan` execute the reviewed entries with per-entry
old-verification, so run Plan first,
read it, and only then apply. If all you want is the diff, `--dry-run` is
available on any write verb.

### The TUI

The TUI opens on the **coin scope picker**: tick what the next task may
touch, then Continue. All / None / Invert act on the whole fleet — the
filter only hides rows. Every coin ticked (the fresh state) is the full
fleet: no `--ticker` flag is emitted. Continue is disabled at zero, so
an empty scope can never be confirmed that way — a scope arriving empty
another way is refused at run time — and `Ctrl+O` reopens the picker
at any time.

The **workspace** underneath runs four actions — press a button,
or `Ctrl+P` for the palette (which also offers Analyze depths):

| Action | Does |
|---|---|
| Analyze | Probe the fleet → Findings (depths: quick local-only, standard, full +changelog, deep +source) |
| Plan | Preview every write — conf/port fixes plus version bumps — touches nothing → Plan |
| Apply | Confirm the reviewed plan, then apply exactly those entries → Plan |
| Add coin | Preview a new coin from a GitHub URL, review it in Plan, apply it |

On short terminals the ledger compacts so the results tabs keep
their rows; the four rows always fit.

Each action row leads with its cost class (table above), so truncation
eats the summary, never the safety tag. A read-only action on a
narrowed scope confirms its exact size
first — and states what the scope does *not* narrow: probes and
param-check follow the ticked coins, while the cross-check and the
port matrix always survey the whole fleet; a full-fleet run starts
immediately. Apply confirms before it runs, through the Apply dialog —
always carrying
its scope line, full fleet included — and listing the files it will
touch; confirming writes the confirmed set to `plan-fix.apply.json`
and applies exactly that file, so the preview and the apply cannot
disagree. Add coin asks for the coin's GitHub URL in a dialog
(`https://github.com/<org>/<repo>`, refused with a hint otherwise),
stages the extracted files for review in the Plan tab, and never
inherits the coin scope. Removing a coin works the same way in
reverse: tick it, run delist from the palette, review, apply.

While a task runs, the strip above the tabs shows the current phase,
the elapsed time, and **Stop** — visible from Findings, Plan and Log
alike. Stop terminates the child process; its
output up to that point is kept in the verb's log file, and progress
lines stay on the strip so the panes remain readable output. The log
file keeps human lines only — machine progress events never land in
it. `Ctrl+D`
toggles the detail pane (hidden by default on narrow terminals).

Your scope, filter and open tab are saved to
`.cache/audit-manifest/dashboard.json` when you quit (`Ctrl+Q`) and
restored on the next start.

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
(the tool's human console output) and `<verb>.meta.json` (what produced it);
`last-run.json` and `last-run.meta.json` mirror whichever verb ran last.
Keeping one file per verb is what stops a cheap `ports` run from overwriting
a richer `findings` report.

A narrowed (`--ticker`) run writes the parallel `<verb>.scoped.json`
slot instead and never touches the fleet slot: fleet views (the TUI
overview, the findings table, the fleet-report pick) only ever read
fleet-slot files, while `last-run.json` still mirrors whatever ran last
— check its `tickers`/`argv` before quoting it as the fleet. The Plan
tab and the Apply dialog likewise resolve the plan by current scope
(`plan-fix.scoped.json` when narrowed).

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
* `1` — at least one repo dead, moved, or unresolved; or a write verb refused
  an entry at apply time (it no longer matched the tree, so nothing was written
  for it)
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

With `pytest-xdist` installed the same suite runs in ~24s on a
multicore box (`-n 8`); without it, ~170s — the cost is ~100 Textual
pilot startups plus a few real subprocess spawns, not the assertions.

The suite covers the version engine, fee policy/floor model, block-time
and tx-time extraction, prefix scoping, scaffold extraction, shared-conf
and per-version audit behaviour; `dashboard.py`'s contract (verbs, flag
translation, exit codes, JSON envelope, report plumbing); and the TUI,
driven through Textual's own runner. Nothing skips on a fresh clone
once `requirements.txt` is installed — without it the TUI tests drop out on
their own and the suite needs nothing beyond `pytest`.

The suite is hermetic: probes are stubbed, `--local-only` is used where a
real invocation is needed, and no test contacts the network or modifies the
working tree — about nine seconds without the three pilot-driven dashboard
files (`test_dashboard_tui.py`, `test_dashboard_scoped_cache.py`,
`test_dashboard_corruption_matrix.py`), ~170s with them (serial; `-n 8`
cuts the full run to ~24s).

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
