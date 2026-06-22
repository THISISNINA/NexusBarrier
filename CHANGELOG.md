# CHANGELOG — Detection Layer Upgrade

This documents what changed in this pass, on top of the existing system
described in `README.md` (architecture, routes, Parts 1–5 are all still
accurate — this upgrade only touches the detection layer and a couple of
pre-existing bugs found during regression testing).

## Session 2: Audit hardening + rule versioning

### Append-only enforcement (DB-level, not just convention)

`str_decisions` was already insert-only by code discipline — every
workflow transition calls `AMLWorkflowManager.transition_alert()`, which
only ever `INSERT`s a new decision row. But nothing in the database itself
stopped a direct `UPDATE`/`DELETE` from a future code path, a migration
script, or manual DB access from silently rewriting audit history. Added
SQLite `BEFORE UPDATE`/`BEFORE DELETE` triggers that physically reject any
write attempt against `str_decisions`, `risk_scores`, and the new
`aml_alert_views` table. Verified: normal `INSERT`-only operation is
unaffected; direct `UPDATE`/`DELETE` against any of these tables raises
immediately regardless of what code path attempts it.

### Rule versioning (`rule_versions` table)

`aml_scenarios` holds the *current* threshold/window/severity per
scenario as a single mutable-in-principle row — if a threshold changes,
there was previously no record of what it used to be, so an alert from
six months ago would look like it was raised under today's threshold.

Added `rule_versions`: a proper historical ledger, one row per
(scenario, version), each with an `effective_from`/`effective_to` range.
Three new functions in `aml_engine.py`:
- **`publish_rule_version()`** — the only supported way to change a
  scenario's parameters. Closes out the current version, inserts a new
  one, requires a non-empty `change_reason`. Uses PATCH semantics (only
  specified fields change; everything else carries forward).
- **`get_active_rule_version(scenario_code, as_of_date)`** — the actual
  audit-proof lookup: "what threshold was in effect for this scenario on
  this date?" Defaults to now; pass a past date to time-travel.
- **`rule_version_history(scenario_code)`** — full version history,
  most recent first, for an examiner/auditor view.

Every alert is now stamped with `rule_version_id` at creation
(`raise_alert()`), so it stays permanently tied to the exact threshold
that produced it — publishing a new rule version never retroactively
changes what a historical alert's record shows. `rule_versions` itself
has a selective trigger: only the `effective_to` column may be updated
(closing out a superseded version); every other field, including
`threshold_value`, is immutable once recorded — verified that a direct
attempt to rewrite a historical threshold is blocked, while the
legitimate `effective_to`-only update (what `publish_rule_version` does)
succeeds.

Initial versions are seeded automatically on first `init_schema()` call
(version 1 of each of the 10 scenarios, `changed_by='SYSTEM'`), and this
seeding is idempotent — verified safe across repeated `init_schema()`
calls (every engine run calls it) without minting duplicate "version 1"
rows.

**Honest limitation:** rule-version history only exists from whenever the
system started using `publish_rule_version()`. It cannot retroactively
reconstruct what a threshold "was" before this feature existed — a
`get_active_rule_version()` lookup for a date before the system's first
version was seeded correctly returns `None`, not a guess.

### View history + time-per-case

Added `aml_alert_views` (append-only, same trigger protection as above):
logs every time an analyst opens an alert's detail page, including the
role they were acting in. Distinct from `str_decisions`, which only
records workflow *state changes* — a view log also captures "an analyst
looked at this and didn't act yet," which matters for the audit story.

`aml_engine.time_in_review_summary(alert_id)` derives a "time spent
investigating" estimate from first-view to closure (or to now, if open),
plus view count and the list of distinct analysts who touched it. This is
a *different* metric from `aml_reports.avg_time_to_close_days`, which
measures calendar time from alert creation to closure — including
however long the alert simply sat unclaimed. Documented as a proxy, not a
precise time-tracker (it can't know how long a tab sat open unattended).

Surfaced in `alert_detail.html` as a new "Investigation Activity" panel,
plus a Role column added to the existing Audit Trail table.

### Role labeling (not yet access control)

Added `CURRENT_ANALYST_ROLE = "L1_ANALYST"` in `app.py`, threaded through
`claim_alert`/`escalate_alert`/`close_alert` → `transition_alert` →
`str_decisions.analyst_role`, and through `record_alert_view` →
`aml_alert_views.analyst_role`. This is explicitly the *labeling* half of
multi-role support, not the *access-control* half — there's still no role
switcher, no `QA_REVIEW` workflow state, and nothing stops an
`L1_ANALYST` from doing anything an `MLRO` could. Real role-gating is a
separate, larger piece (changes to `AMLWorkflowManager.VALID_TRANSITIONS`
plus route-level permission checks) — intentionally not built in this
pass since it wasn't what was requested.

### Schema additions (all additive)

- `rule_versions` — historical ledger, append-only except `effective_to`
- `aml_alert_views` — append-only view-history log
- `aml_alerts.rule_version_id` — stamped at alert creation
- `str_decisions.analyst_role` — now actually populated (column already
  existed from session 1's migration, but nothing wrote to it)
- 8 new SQLite triggers total (2 each on `str_decisions`, `risk_scores`,
  `rule_versions`, `aml_alert_views`)

### Bugs found during this pass

None new in the audit-hardening code itself — but one test-design mistake
on my own part worth noting for anyone extending this: `rule_versions.
version_id` is a single global autoincrement shared across all scenarios,
not scoped per-scenario, so comparing `version_id` (or assuming a given
`version_id` belongs to a specific scenario) across different
`scenario_code` values is meaningless. Use `(scenario_code,
version_number)` together when reasoning about a specific scenario's
version history, not `version_id` alone, unless you've already confirmed
the row's `scenario_code`.

---

## Session 1: Detection layer (risk scoring, new scenarios, bug fixes)

### New: `aml_risk.py` — weighted risk scoring engine

Read-only, advisory scoring layer. Does **not** replace the deterministic
rule thresholds — those stay authoritative for "does this alert fire at
all." The score only sharpens severity (can escalate, never downgrade) and
feeds a `risk_score_at_alert` / `risk_tier_at_alert` stamp on every alert
for queue prioritisation.

Four weighted components (weights sum to 1.0, all in `aml_risk.py`):
- **Velocity (30%)** — recent (14d) vs. baseline (90d) transaction volume ratio
- **Jurisdiction (30%)** — max risk-tier score across transactions in a
  365-day window (see bug #1 below for why it's 365, not 180)
- **Structuring proximity (25%)** — closeness to the threshold ceiling,
  scaled by transaction clustering
- **Customer segment (15%)** — risk rating, PEP status, customer type

Severity mapping: `severity_from_score()` takes a `floor_severity` param —
the score can only push severity up from what the rule itself implies,
never down. This keeps the rule layer the regulatory source of truth.

## New scenarios (6, registered in `SCENARIOS` / `SCENARIO_SEED`)

| Scenario | What it catches |
|---|---|
| `SCN_PEP_EXPOSURE` | PEP accounts: single tx ≥ AED 50,000, or 30-day aggregate ≥ 1.5x the account's own expected monthly volume |
| `SCN_SANCTIONS_SCREENING` | Customer name match against local mock `sanctions_list` (illustrative only — not a real OFAC/UN/EU feed) |
| `SCN_DORMANT_REACTIVATION` | 180+ days silent, then a transaction ≥ AED 15,000 |
| `SCN_RAPID_LAYERING` | 3+ transactions, ≥ AED 20,000 total, within 72 hours, same account |
| `SCN_MULTI_ACCOUNT_STRUCTURING` | 3+ distinct accounts all transacting in the AED 8,500–9,999 band within 14 days (smurfing) |
| `SCN_CROSS_BORDER_ANOMALY` | Account transacts across 4+ distinct countries within 30 days |

All ten scenarios (4 original + 6 new) verified `COMPLETED` with zero
exceptions across a 7-run periodic schedule spanning the full seed year.

## Schema additions (all additive — no existing table/column removed)

- `risk_scores` — append-only score history (one row per computation, not
  an upsert; this is the input data for a future analyst-feedback loop)
- `sanctions_list` — local mock screening list, seeded by `seed_sanctions_list()`
- `aml_alerts.risk_score_at_alert`, `.risk_tier_at_alert`, `.priority_rank`
- `str_decisions.analyst_role`
- New columns added via an idempotent `_add_column_if_missing()` helper
  (SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`), verified
  safe to run `init_schema()` repeatedly against an already-migrated DB.

## UI changes

- `alerts.html` — new sortable **Risk Score** column (badge: score + tier),
  open-queue default sort is now risk score descending (was `created_at`)
- `alert_detail.html` — risk score breakdown shown in the Alert Information panel
- `style.css` — added `.risk-critical` badge class (CRITICAL tier didn't
  exist before this pass)

## `generator.py` — persona injection

The original generator assigns a fresh random `account_id` to every
transaction, so almost no account ever accumulates multiple transactions
close together in time. That's fine for the volume-threshold scenarios
(`SCN_CASH_AGG_6M`, `SCN_HIGH_RISK_JURISDICTION`) but means the
time-clustered scenarios (structuring, rapid layering, cross-border,
smurfing, dormant reactivation) had no real signal to find in the
synthetic data, regardless of whether the detection logic was correct.

Added a `build_persona_transactions()` pass that injects ~10 named
`PERSONA_*` accounts with realistic clustered patterns (one structuring
account, one rapid-layering account, one cross-border account, a 4-account
smurfing cluster, two dormant-reactivation accounts), layered on top of —
not replacing — the existing 5,000 random transactions. This is additive
and backward-compatible; nothing about the original random population
changed.

## Bugs found during this pass and fixed

1. **Jurisdiction score lookback too short (180 → 365 days).** A test
   transaction (AED 415,678 to North Korea, ~11 months before the test's
   `as_of_date`) scored `jurisdiction_score: 0` because it fell outside
   the original 180-day window. Widened to 365 days — jurisdiction
   exposure is now the longest-memory component of the four by design,
   since a single high-risk-jurisdiction transaction shouldn't silently
   age out of a risk profile after 6 months.

2. **`SCN_PEP_EXPOSURE` over-fired (152 alerts on first test run).** The
   original flat AED 7,500 single-transaction threshold sat too close to
   the synthetic generator's normal "borderline" band (AED 8,500+), so it
   flagged routine activity for ~1/3 of all PEP transaction volume.
   Fixed: single-tx threshold raised to AED 50,000 (meaningfully above the
   structuring band), and the aggregate check changed from a flat AED
   25,000 figure to 1.5x the account's own `expected_monthly_volume` —
   relative to the customer's declared profile, not a flat number. Now
   produces 20 alerts on the same dataset — a defensible rate for ~386
   PEP-flagged accounts.

3. **`SCN_BEHAVIOUR_CHANGE` over-fired (381 alerts, 97% noise).** The
   original SQL fired whenever an account had *either* (a) 3x baseline
   volume, *or* (b) no baseline at all. Branch (b) matched any account
   with literally one transaction ever, which — given the sparse
   per-account transaction density in the seed data — was nearly every
   account that had any current-period activity. Of 381 alerts, only 13
   were genuine 3x-baseline signals. Fixed: now requires a real,
   non-zero baseline to fire at all. The "no prior history, then
   activity" case is a different, legitimate signal — it's now covered
   properly by `SCN_DORMANT_REACTIVATION`, which actually verifies a
   genuine silence period rather than just "baseline happens to be zero."
   Also fixed a narrative string bug ("vs historical baseline baseline.")
   along the way.

4. **`/case/<case_id>` 404 was unreachable.** `case_detail()` wrapped
   `abort(404)` in a bare `except Exception`, and `abort()` works by
   raising `werkzeug.exceptions.NotFound` — which is itself an
   `Exception` subclass, so the route's own catch-all silently swallowed
   it and redirected with a flash message instead of ever returning a
   real 404. A request for a nonexistent case always returned 302, never
   404. Fixed by re-raising `HTTPException` before the generic catch-all.

5. **`404.html` template was missing entirely.** `app.py`'s
   `errorhandler(404)` referenced a template that didn't exist anywhere
   in the codebase, so any 404 path crashed with an unhandled 500 instead
   of rendering an error page. (This means the README's claim of having
   tested 404 handling end-to-end predates whatever removed this file, or
   was never actually exercised against a fresh checkout.) Created
   `templates/404.html`, matching the existing dark theme/component
   classes.

6. **Air-gap enforcement block was fully commented out.** Per explicit
   instruction, removed entirely rather than re-enabled — the
   "no data leaves this machine" claim in the README/footer should now be
   read as a deployment property (no outbound code paths exist), not an
   enforced runtime guarantee.

## Known limitations / good next steps

- **`SCN_SANCTIONS_SCREENING`** does exact-match-after-normalisation only.
  Real sanctions screening needs fuzzy/phonetic matching (aliases,
  transliteration). It also only screens the account holder's name, not
  counterparty names on the transaction itself — the transaction schema
  has no counterparty field yet.
- **`SCN_RAPID_LAYERING`** is a same-account concentration proxy, not true
  layering — it can't trace fund *flow* (in vs. out) without a
  `direction` / `counterparty_account_id` field on `transactions`.
- **`SCN_MULTI_ACCOUNT_STRUCTURING`** flags coordinated-looking clusters
  but can't prove common beneficial ownership without the entity-resolution
  layer (shared phone/address/identifier linking) — that's a natural next
  workstream, not built in this pass.
- **`as_of_date` matters a lot for testing/demos.** Every windowed
  scenario looks backward from `as_of_date`; running against historical
  seed data with the default (today) finds nothing, since "today" is
  months past the dataset's end. In production this is correct (you run
  close to real-time); for demos, either pass an explicit date inside the
  data's range or run the engine periodically across the data's timespan
  (see `generator.py`'s `PERSONA_WINDOW_START` spacing for why personas
  are deliberately spread across the year rather than clustered on one date).
- **PEP seed rate (10% of accounts)** is unrealistically high for a retail
  book (real-world is usually well under 1%) — fine for demo purposes
  but worth lowering if you want the PEP scenario's alert *rate* (not just
  its per-transaction logic) to be representative.
