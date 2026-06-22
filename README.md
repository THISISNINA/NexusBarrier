# AML Analyst Dashboard — Enterprise Edition

A layered, production-style AML monitoring and case management system.
Detection and compliance live in `aml_engine.py`; everything else is a thin
layer that reads from or calls into it, nothing duplicates its rules.

## Architecture

```
templates/        Presentation only. No logic, no SQL, no workflow decisions.
app.py             Routing + UI layer. Calls AMLService. Renders templates.
                   Catches WorkflowError and turns it into flash() messages.
                   NO SQL. NO direct AMLWorkflowManager calls.
aml_service.py     Business logic / service layer. ALL database access for
                   the dashboard lives here. Every write goes through
                   AMLWorkflowManager.transition_alert() — no exceptions.
aml_reports.py     Read-only SLA/reporting aggregate queries.
alert_filter.py    Read-only suppression policy (recently-cleared check).
aml_engine.py      Detection scenarios + AMLWorkflowManager (the only thing
                   allowed to decide or write alert status). Unmodified
                   except for additive schema (cases tables) and one
                   suppression check inside raise_alert().
```

**The rule that holds everywhere:** only `AMLWorkflowManager.transition_alert()`
writes `aml_alerts.status` or inserts into `str_decisions`. Every other file
either reads, or calls a service method that calls `transition_alert()`. This
was verified by grep across the whole codebase, see "Compliance audit" below.

## Routes

| Method | Path                          | Purpose                                  |
|--------|-------------------------------|-------------------------------------------|
| GET    | `/`                            | Open alert queue (status = OPEN)         |
| GET    | `/alerts/all`                  | All alerts, any status                    |
| GET    | `/alert/<alert_id>`            | Alert detail, investigation panel, case info |
| GET    | `/reports`                     | SLA dashboard (`?format=json` for raw JSON) |
| POST   | `/claim/<alert_id>`            | OPEN → UNDER_REVIEW                      |
| POST   | `/close/<alert_id>`            | UNDER_REVIEW/ESCALATED → CLOSED_SAR / CLOSED_NO_ACTION |
| POST   | `/escalate/<alert_id>`         | UNDER_REVIEW → ESCALATED                 |
| POST   | `/case/create/<alert_id>`      | Create a new case, link this alert       |
| POST   | `/case/<case_id>/link/<alert_id>` | Link an additional alert to a case    |
| GET    | `/case/<case_id>`              | Case detail page                          |

**Legacy paths** (`/alerts/<id>`, `/alerts/<id>/claim`, `/alerts/<id>/close`,
`/alerts/<id>/escalate`) still work — GET redirects 301 to the new path,
POST routes are thin pass-throughs to the same handler. These exist only
for backward compatibility with anything already linking to the old paths;
the table above is canonical going forward.

## Part-by-part notes

### Part 1 — app.py (Execution Layer)
Routes match the spec exactly. `app.py` contains no SQL and never calls
`AMLWorkflowManager.transition_alert()` directly, every action goes through
`AMLService`. Errors are caught as `WorkflowError` and shown via `flash()`.

### Part 2 — aml_service.py (Service Layer)
Implements every method from the spec (`get_open_alerts`, `get_all_alerts`,
`get_alert`, `get_alert_transactions`, `get_customer_profile`,
`get_decision_history`, `claim_alert`, `close_alert`, `escalate_alert`),
plus a few read helpers `app.py` needs (`get_alert_status`,
`get_valid_next_states`) and the Part 5 case-management methods. Each public
method opens and closes its own connection — safe across Flask's
multi-threaded dev server without sharing connection objects.

### Part 3 — aml_reports.py (SLA & Reporting)
All five requested metrics, each reading the **latest** `str_decisions` row
per alert (same definition of "current state" `AMLWorkflowManager` itself
uses) so timing math and the live `aml_alerts.status` shown on the dashboard
never disagree:
- Average time to review (`created_at` → `reviewed_at`)
- Average time to close (`created_at` → `closed_at`)
- Alerts by scenario (open/closed breakdown)
- False positive rate (`closure_reason_code = 'FALSE_POSITIVE'` ÷ all closed)
- SAR rate (`CLOSED_SAR` ÷ all closed)

Exposed at `/reports` as HTML, or `/reports?format=json` as raw JSON.

### Part 4 — alert_filter.py (Suppression)
**A schema ambiguity in the brief, resolved explicitly rather than guessed:**
the brief says "closed as FALSE_POSITIVE / CLOSED_NO_ACTION" as if these were
one thing. In the real schema they're different fields —
`FALSE_POSITIVE` is a `closure_reason_code`, `CLOSED_NO_ACTION` is a
`workflow_status` and a closure can never be both `CLOSED_SAR` and
`FALSE_POSITIVE` at once. `alert_filter.py` implements suppression on
`workflow_status = 'CLOSED_NO_ACTION'` (any reason, FALSE_POSITIVE included
as the headline case), with an optional `closure_reason_codes` parameter to
narrow it to specific reasons if you want different behavior. Full reasoning
is in the module docstring.

Wired into `aml_engine.raise_alert()` suppression is checked before a new
alert is created, so it affects detection, not the UI. Verified: closing an
alert as `CLOSED_NO_ACTION` and then attempting `raise_alert()` for the same
`account_id` + `scenario_code` within 30 days returns `None` (suppressed); a
different scenario on the same account is **not** suppressed.

### Part 5 — Case Management
`cases` and `case_alert_map` tables added (additive DDL in
`aml_engine.SCHEMA_DDL`, no existing tables touched). Service functions:
`create_case(alert_id)`, `get_case(case_id)`, `link_alert_to_case(alert_id, case_id)`,
plus `get_case_for_alert()` and `find_related_open_alerts()` to support the UI.

**Grouping policy — analyst-confirmed, not automatic:** the brief says
"automatically group alerts by account_id or recent activity window" without
specifying what should trigger that grouping or what happens if it's wrong
(e.g. two unrelated alerts on a joint account auto-merged into one case).
Auto-merging cases is a one-way door for a compliance audit trail, so rather
than guess a threshold, the alert detail page surfaces a **suggestion**:
other open alerts on the same account within a 30-day window are shown with
a "Create Case" / "Link to existing case" action the analyst takes
explicitly. The detection logic for "what counts as related" is real
(`find_related_open_alerts`, same `account_id` + `created_at` within N days)
— only the decision to act on it is left to a human. If you want true
auto-grouping (no analyst confirmation step), say so and I'll wire
`find_related_open_alerts` to call `create_case`/`link_alert_to_case`
automatically inside `raise_alert()` — that's a small change once the
trigger condition is confirmed.

Case status (`OPEN`/`CLOSED` on the `cases` table) is **independent** of
alert-level workflow status — closing every alert in a case does not
auto-close the case, and there's no case-level state machine. If you want
one, that's also a explicit follow-up rather than something I should infer.

## Compliance audit (verified, not just asserted)

Ran a grep-based audit confirming:
- `app.py` contains zero raw SQL statements
- `app.py` never calls `AMLWorkflowManager.transition_alert()` directly
  (only reads `VALID_CLOSURE_CODES` for the closure-reason dropdown)
- `transition_alert()` is called only from `aml_engine.py` (its own
  self-test) and `aml_service.py` — nowhere else in the codebase
- No `UPDATE aml_alerts SET status` or `INSERT INTO str_decisions` exists
  outside `aml_engine.py`
- `alert_filter.py` and `aml_reports.py` contain no INSERT/UPDATE/DELETE

## Running it

```bash
pip install flask

python seed_demo_data.py   # creates transactions table + demo data, runs
                            # the real engine (suppression included) to
                            # generate alerts
python app.py
# -> http://127.0.0.1:5000
```

If pointing at your real database instead of the demo seed: the schema
additions (`cases`, `case_alert_map`) are created automatically the first
time `aml_engine.init_schema()` runs against your existing `.db` file
(`CREATE TABLE IF NOT EXISTS`, so nothing existing is touched).

## Tested end-to-end (Flask test client — real sockets, including loopback,
are blocked in this build environment)

- All GET routes (`/`, `/alerts/all`, `/alert/<id>`, `/reports`,
  `/reports?format=json`) return 200
- Legacy `/alerts/<id>` 301-redirects to `/alert/<id>`; legacy POST paths
  delegate to the same handlers as the new paths
- Claim → close (empty narrative rejected) → escalate → close with SAR
  reference (missing-reference rejected, then valid) → terminal-state
  lockout, full chain visible in the audit trail table
- Suppression: close as `CLOSED_NO_ACTION`/`FALSE_POSITIVE`, then attempt to
  re-raise the same account+scenario — confirmed suppressed; a different
  scenario on the same account is not
- Case creation, linking a second alert, idempotent re-linking (no
  duplicate row, no error), case detail page rendering
- 404 for unknown alert IDs and unknown case IDs
- Full fresh-start smoke test (wiped DB, reseeded, re-imported `app.py`,
  hit every route) with no errors
