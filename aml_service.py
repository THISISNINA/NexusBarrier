"""
aml_service.py — Business Logic / Service Layer
---------------------------------------------------
Sits between app.py (routing/UI) and aml_engine.py (detection + compliance
state machine). This is where ALL database access for the dashboard lives.

Layering contract:
    aml_engine.py    -> detection scenarios + AMLWorkflowManager (compliance
                         rules, the only thing allowed to decide or write
                         alert status)
    alert_filter.py  -> suppression policy (read-only signal, no writes)
    aml_service.py    -> THIS FILE. Every query and every workflow call the
                         UI needs, in one place. Owns connection lifecycle.
    app.py            -> routing only. Calls AMLService methods and renders
                         templates / flashes errors. Contains no SQL and no
                         workflow-transition calls of its own.

Every method that changes alert state (claim_alert, close_alert,
escalate_alert) does so by calling
AMLWorkflowManager.transition_alert() and nothing else — this file does
not perform direct UPDATE statements against aml_alerts.status or
str_decisions.workflow_status anywhere. WorkflowError is allowed to
propagate up to app.py uncaught; app.py is responsible for catching it
and turning it into a flash() message, since that's a UI concern, not a
service concern.
"""
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional, Sequence

import aml_engine
from aml_engine import AMLWorkflowManager, WorkflowError  # re-exported for app.py convenience

DB_PATH = aml_engine.DB_PATH


class AMLService:
    """
    Stateless-ish facade: each public method opens its own short-lived
    connection, does its work, and closes it. This keeps the service safe
    to call from multiple Flask request threads without sharing connection
    objects across requests (sqlite3 connections are not thread-safe by
    default). For read methods this is a plain try/finally. For write
    methods that call AMLWorkflowManager, we commit on success and roll
    back on any exception, then re-raise — callers (app.py) decide how to
    present the error.
    """

    # ── Connection helper ────────────────────────────────────────────────

    @staticmethod
    def _connect() -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def ensure_db_ready() -> None:
        """Create schema if this is a fresh DB (idempotent, delegates to aml_engine)."""
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = AMLService._connect()
        try:
            conn.execute("SELECT 1 FROM aml_alerts LIMIT 1")
        except sqlite3.OperationalError:
            aml_engine.init_schema(conn)
        finally:
            conn.close()

    # ── Read queries ─────────────────────────────────────────────────────

    @staticmethod
    def get_alerts_for_role(role: str) -> list[sqlite3.Row]:
        """Role-aware version of the 'Open Queue' landing view.

        - L1_ANALYST sees alerts with status OPEN — the first-line queue,
          awaiting an analyst to claim and investigate.
        - MLRO sees alerts with status ESCALATED — cases an analyst has
          already investigated and kicked up for second-line / SAR-filing
          review. This is what makes the escalate -> MLRO's "My Reviews"
          flow work: an MLRO's landing queue IS the escalated queue, not
          the OPEN queue (an MLRO claiming a fresh OPEN alert isn't part
          of the two-tier review model this dashboard implements).

        Falls back to the OPEN queue for any unrecognised role string,
        rather than raising, since role is sourced from a session value
        that should always be one of the two above but shouldn't crash
        the whole queue page if it somehow isn't.
        """
        target_status = "ESCALATED" if role == "MLRO" else "OPEN"
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    s.typology AS scenario_typology, a.severity, a.trigger_value,
                    a.account_id, a.created_at, a.status,
                    a.risk_score_at_alert, a.risk_tier_at_alert
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                WHERE a.status = ?
                ORDER BY COALESCE(a.risk_score_at_alert, 0) DESC, a.created_at DESC
            """, (target_status,)).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_open_alerts() -> list[sqlite3.Row]:
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    s.typology AS scenario_typology, a.severity, a.trigger_value,
                    a.account_id, a.created_at, a.status,
                    a.risk_score_at_alert, a.risk_tier_at_alert
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                WHERE a.status = 'OPEN'
                ORDER BY COALESCE(a.risk_score_at_alert, 0) DESC, a.created_at DESC
            """).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_open_and_escalated_alerts() -> list[sqlite3.Row]:
        """MLRO's full-visibility 'Open Queue': every alert that is either
        still OPEN (unclaimed, awaiting an analyst) or already ESCALATED
        (awaiting MLRO sign-off). Exists so the MLRO is never blind to
        what's sitting in the analyst-side pipeline — they can see the
        whole funnel end-to-end, not just the slice that's already been
        kicked up to them via get_alerts_for_role(). Ordered the same way
        as the other queue views (risk score desc, then recency), with
        status included so the template can badge/sort OPEN vs ESCALATED
        rows distinctly."""
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    s.typology AS scenario_typology, a.severity, a.trigger_value,
                    a.account_id, a.created_at, a.status,
                    a.risk_score_at_alert, a.risk_tier_at_alert
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                WHERE a.status IN ('OPEN', 'ESCALATED')
                ORDER BY COALESCE(a.risk_score_at_alert, 0) DESC, a.created_at DESC
            """).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_all_alerts() -> list[sqlite3.Row]:
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    a.severity, a.trigger_value, a.account_id, a.created_at, a.status,
                    a.risk_score_at_alert, a.risk_tier_at_alert
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                ORDER BY a.created_at DESC
            """).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_rule_version_for_alert(alert_id: str) -> Optional[sqlite3.Row]:
        """Looks up the full rule_versions row stamped on this alert at
        creation time (see aml_engine.raise_alert's rule_version_id stamp)
        — the actual audit-proof answer to 'what threshold produced this
        alert', even if the scenario's threshold has since changed."""
        conn = AMLService._connect()
        try:
            conn.row_factory = sqlite3.Row
            return conn.execute("""
                SELECT rv.* FROM aml_alerts a
                JOIN rule_versions rv ON rv.version_id = a.rule_version_id
                WHERE a.alert_id = ?
            """, (alert_id,)).fetchone()
        finally:
            conn.close()

    @staticmethod
    def get_alert(alert_id: str) -> Optional[sqlite3.Row]:
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT a.*, s.description AS scenario_description, s.typology AS scenario_typology
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                WHERE a.alert_id = ?
            """, (alert_id,)).fetchone()
        finally:
            conn.close()

    @staticmethod
    def log_alert_view(alert_id: str, analyst_id: str, analyst_role: Optional[str] = None) -> None:
        """Records that an analyst opened this alert's detail page —
        see aml_engine.record_alert_view(). Best-effort: a logging failure
        here should never block the analyst from actually viewing the
        alert, so callers (app.py) should treat this as fire-and-forget."""
        conn = AMLService._connect()
        try:
            aml_engine.record_alert_view(conn, alert_id, analyst_id, analyst_role)
        finally:
            conn.close()

    @staticmethod
    def get_time_in_review(alert_id: str) -> dict:
        """See aml_engine.time_in_review_summary() — view-history-derived
        investigation time, distinct from the calendar-time SLA metrics
        in aml_reports.py."""
        conn = AMLService._connect()
        try:
            return aml_engine.time_in_review_summary(conn, alert_id)
        finally:
            conn.close()

    @staticmethod
    def get_alert_transactions(alert_id: str) -> list[sqlite3.Row]:
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT t.transaction_id, t.amount, t.transaction_date, t.country
                FROM aml_alert_transactions at
                JOIN transactions t ON t.transaction_id = at.transaction_id
                WHERE at.alert_id = ?
                ORDER BY t.transaction_date DESC
            """, (alert_id,)).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_customer_profile(account_id: str) -> Optional[sqlite3.Row]:
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT * FROM customer_profiles WHERE account_id = ?
            """, (account_id,)).fetchone()
        finally:
            conn.close()

    @staticmethod
    def get_decision_history(alert_id: str) -> list[sqlite3.Row]:
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT * FROM str_decisions WHERE alert_id = ? ORDER BY decision_id ASC
            """, (alert_id,)).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_alert_status(alert_id: str) -> str:
        """Authoritative status comes from str_decisions (what AMLWorkflowManager
        itself reads via get_latest_decision), not aml_alerts.status directly —
        the engine keeps both in sync on every transition, but routing through
        the same lookup the engine uses means this can never diverge from what
        transition_alert() will actually enforce next. Falls back to 'OPEN' to
        match AMLWorkflowManager's own default for alerts with no decision row."""
        conn = AMLService._connect()
        try:
            record = AMLWorkflowManager.get_latest_decision(conn, alert_id)
            return record["workflow_status"] if record else "OPEN"
        finally:
            conn.close()

    @staticmethod
    def get_valid_next_states(alert_id: str) -> list[str]:
        status = AMLService.get_alert_status(alert_id)
        return AMLWorkflowManager.VALID_TRANSITIONS.get(status, [])

    @staticmethod
    def get_viewed_alert_ids(analyst_id: str) -> set[str]:
        """Distinct alert_ids this specific analyst/MLRO has opened at least
        once, sourced from the append-only aml_alert_views log. Used to
        build a genuinely personal 'My Reviews' view for MLRO — alerts
        THIS MLRO has actually looked at — instead of just re-showing the
        full escalated inbox under a different page title. Scoped by
        analyst_id rather than analyst_role, since role is a single shared
        session value in this demo (see README's single-identity note);
        if multiple real MLRO accounts existed, this still does the right
        thing per-identity."""
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT DISTINCT alert_id FROM aml_alert_views WHERE analyst_id = ?
            """, (analyst_id,)).fetchall()
            return {r["alert_id"] for r in rows}
        finally:
            conn.close()

    # ── Workflow actions (ALL routed through AMLWorkflowManager) ───────────

    @staticmethod
    def claim_alert(alert_id: str, analyst_id: str, analyst_role: Optional[str] = None) -> None:
        """OPEN -> UNDER_REVIEW. Raises WorkflowError if alert is not
        currently OPEN — AMLWorkflowManager.VALID_TRANSITIONS only allows
        this transition from OPEN, so that rule is enforced there, not here.
        Callable by either role: an MLRO claiming a fresh OPEN alert directly
        (skipping the analyst tier) is an explicit, supported path, not just
        an L1_ANALYST action — the audit trail still records exactly who
        claimed it and in what role via analyst_role."""
        conn = AMLService._connect()
        try:
            AMLWorkflowManager.transition_alert(
                conn, alert_id=alert_id, analyst_id=analyst_id,
                target_status="UNDER_REVIEW", analyst_role=analyst_role,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def escalate_alert(alert_id, analyst_id, role, narrative=""):
        conn = AMLService._connect()
        try:
            # Pass the arguments directly
            AMLWorkflowManager.transition_alert(
                conn, 
                alert_id=alert_id, 
                analyst_id=analyst_id,
                target_status="ESCALATED", 
                analyst_role=role,
                narrative=narrative 
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    @staticmethod
    def return_to_analyst(alert_id: str, analyst_id: str, note: str, analyst_role: Optional[str] = None) -> None:
        """ESCALATED -> UNDER_REVIEW. The MLRO-side counterpart to
        escalate_alert(): lets an MLRO kick an alert back down to the
        analyst tier (e.g. needs more investigation / more evidence before
        MLRO can sign off) instead of being forced to either close it
        outright or take no action at all. This is a transition the state
        machine has always permitted (see VALID_TRANSITIONS['ESCALATED']
        in aml_engine.py) but which previously had no UI/route calling it.

        `note` is REQUIRED — explaining why an alert is being bounced back
        is the whole point of giving the analyst something actionable to
        work from, not just a bare status flip with no context. Stored in
        str_decisions.risk_justification_narrative (the same column the
        closure narrative uses) so it shows up in the Audit Trail like any
        other decision rationale. Enforced here rather than relying on
        AMLWorkflowManager.transition_alert's own narrative check, since
        that check only fires for CLOSED_* target states — UNDER_REVIEW
        isn't a terminal transition the engine itself requires a narrative
        for, but this specific MLRO-initiated path should still have one.

        Raises WorkflowError if the alert is not currently ESCALATED, or
        if note is missing/too short.
        """
        if not note or len(note.strip()) < 10:
            raise WorkflowError("A note explaining why this alert is being returned to the analyst is required (minimum 10 characters).")

        conn = AMLService._connect()
        try:
            AMLWorkflowManager.transition_alert(
                conn, alert_id=alert_id, analyst_id=analyst_id,
                target_status="UNDER_REVIEW", narrative=note, analyst_role=analyst_role,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Closure reason codes that resolve to CLOSED_SAR (a SAR was filed) vs
    # CLOSED_NO_ACTION (no SAR). This mapping is a UI/orchestration concern —
    # "which closure reasons imply a SAR was filed" — not a compliance rule
    # itself. The actual enforcement (narrative required, code must be valid,
    # goAML reference required specifically for CLOSED_SAR) lives entirely in
    # AMLWorkflowManager.transition_alert and is NOT duplicated here.
    SAR_CLOSURE_CODES = ("STRUCTURING_CONFIRMED", "HIGH_RISK_CONFIRMED")

    @staticmethod
    def close_alert(
        alert_id: str,
        analyst_id: str,
        narrative: str,
        closure_reason: str,
        sar_reference: Optional[str] = None,
        analyst_role: Optional[str] = None,
    ) -> str:
        """
        UNDER_REVIEW / ESCALATED -> CLOSED_SAR or CLOSED_NO_ACTION.

        Determines the target terminal status from closure_reason (SAR-implying
        codes -> CLOSED_SAR, everything else -> CLOSED_NO_ACTION), then calls
        AMLWorkflowManager.transition_alert with that target. ALL validation —
        narrative non-empty/long enough, closure_reason must be a recognised
        code, goAML reference required when filing a SAR, and the current
        status must permit closing at all — is enforced inside transition_alert
        itself via WorkflowError. This method does not pre-validate or
        short-circuit any of those checks; it only decides which of the two
        terminal states to *attempt*.

        Returns the target_status string on success (useful for flash messages).
        Raises WorkflowError on any compliance violation.
        """
        target_status = (
            "CLOSED_SAR" if closure_reason in AMLService.SAR_CLOSURE_CODES
            else "CLOSED_NO_ACTION"
        )

        conn = AMLService._connect()
        try:
            AMLWorkflowManager.transition_alert(
                conn,
                alert_id=alert_id,
                analyst_id=analyst_id,
                target_status=target_status,
                narrative=narrative,
                closure_code=closure_reason or None,
                goaml_ref=sar_reference or None,
                analyst_role=analyst_role,
            )
            conn.commit()
            return target_status
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Case management (Part 5) ────────────────────────────────────────

    @staticmethod
    def create_case(alert_id: str) -> str:
        """Creates a new case and links the given alert to it. Returns the
        new case_id. Does NOT touch alert workflow status — cases are an
        independent grouping layer on top of alerts, not a replacement for
        the alert-level state machine."""
        conn = AMLService._connect()
        try:
            alert = conn.execute(
                "SELECT account_id FROM aml_alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if alert is None:
                raise ValueError(f"No such alert: {alert_id}")

            case_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT INTO cases (case_id, account_id, status, created_at, updated_at)
                VALUES (?, ?, 'OPEN', ?, ?)
            """, (case_id, alert["account_id"], now, now))
            conn.execute("""
                INSERT INTO case_alert_map (case_id, alert_id, linked_at)
                VALUES (?, ?, ?)
            """, (case_id, alert_id, now))
            conn.commit()
            return case_id
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def link_alert_to_case(alert_id: str, case_id: str) -> None:
        """Adds an additional alert to an existing case (idempotent — linking
        the same alert twice is a no-op, not an error)."""
        conn = AMLService._connect()
        try:
            case = conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if case is None:
                raise ValueError(f"No such case: {case_id}")
            alert = conn.execute("SELECT 1 FROM aml_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if alert is None:
                raise ValueError(f"No such alert: {alert_id}")

            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR IGNORE INTO case_alert_map (case_id, alert_id, linked_at)
                VALUES (?, ?, ?)
            """, (case_id, alert_id, now))
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def get_case(case_id: str) -> Optional[dict]:
        """Returns the case row plus all linked alerts, or None if not found."""
        conn = AMLService._connect()
        try:
            case = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if case is None:
                return None
            alerts = conn.execute("""
                SELECT a.alert_id, a.scenario_code, a.severity, a.status, a.created_at,
                       cam.linked_at
                FROM case_alert_map cam
                JOIN aml_alerts a ON a.alert_id = cam.alert_id
                WHERE cam.case_id = ?
                ORDER BY cam.linked_at ASC
            """, (case_id,)).fetchall()
            return {"case": case, "alerts": alerts}
        finally:
            conn.close()

    @staticmethod
    def bulk_transition(alert_ids: list[str], action: str, analyst_id: str, analyst_role: Optional[str] = None,
                         narrative: Optional[str] = None) -> dict:
        """Applies one of the two supported bulk workflow actions
        (claim / escalate) to a batch of alerts, one transition_alert()
        call per alert — NOT a single bulk SQL UPDATE. This matters for
        compliance correctness: each alert gets its own str_decisions
        audit row (so the audit trail still shows exactly who acted on
        which alert and when, individually), and each alert's current
        status is independently validated by AMLWorkflowManager — an
        alert that's no longer in a valid state for this action (e.g.
        someone else closed it a moment ago) is skipped with its own
        error rather than aborting the whole batch.

        `narrative` is required for action="escalate" (enforced by the
        caller in app.py — bulk escalation now needs the same kind of
        justification a single-alert escalation does) and is written
        identically into every selected alert's str_decisions row. Bulk
        Claim ignores it entirely, since claiming isn't a decision that
        needs justifying the way escalating is.

        Deliberately excludes 'close' (requires a real per-alert narrative
        and closure-reason code under VALID_CLOSURE_CODES enforcement —
        a shared narrative would be the wrong call here, since closures
        are individual dispositions, not a single shared judgment the way
        an escalation reason can be) and 'return_to_analyst' (also
        requires a note specific to why that one alert is being bounced
        back). Both stay one-at-a-time via their existing per-alert forms.

        Returns {"succeeded": [alert_id, ...], "failed": [(alert_id, reason), ...]}.
        """
        if action not in ("claim", "escalate"):
            raise ValueError(f"bulk_transition: unsupported action {action!r}. Supported: ['claim', 'escalate']")

        succeeded, failed = [], []
        for alert_id in alert_ids:
            try:
                if action == "claim":
                    AMLService.claim_alert(alert_id, analyst_id, analyst_role)
                else:
                    AMLService.escalate_alert(alert_id, analyst_id, analyst_role, narrative=narrative or "")
                succeeded.append(alert_id)
                # Acting on an alert counts as reviewing it, same as the
                # single-alert routes in app.py — keeps My Reviews accurate
                # for alerts touched via a bulk action too.
                try:
                    AMLService.log_alert_view(alert_id, analyst_id, analyst_role)
                except Exception:
                    pass
            except WorkflowError as e:
                failed.append((alert_id, str(e)))
            except Exception as e:
                failed.append((alert_id, f"Unexpected error: {e}"))
        return {"succeeded": succeeded, "failed": failed}

    @staticmethod
    def get_all_scenarios() -> list[sqlite3.Row]:
        """Every active scenario's current definition (description,
        typology, threshold, window) straight from aml_scenarios — the
        live source of truth, not a hardcoded copy — for the onboarding
        page's expandable scenario reference. If a threshold is later
        changed via publish_rule_version(), this reflects the new value
        immediately rather than going stale like a hand-written summary
        would."""
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT scenario_code, description, typology, threshold_value,
                       window_days, default_severity
                FROM aml_scenarios
                WHERE is_active = 1
                ORDER BY scenario_code
            """).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_dashboard_summary() -> dict:
        """Status counts + oldest still-open alert for the Dashboard
        landing block. Delegates to aml_reports.build_dashboard_summary()
        — the exact same underlying queries the full SLA Report uses for
        its own volume summary and oldest-open figure — so the Dashboard
        and /reports can never silently disagree on these numbers."""
        import aml_reports
        conn = AMLService._connect()
        try:
            return aml_reports.build_dashboard_summary(conn)
        finally:
            conn.close()

    @staticmethod
    def get_open_cases_for_account(account_id: str) -> list[sqlite3.Row]:
        """All OPEN cases already existing for this account, for the
        'link to an existing case' dropdown on the alert detail page —
        scoped to one account (not a system-wide case browser) since
        that's the only grouping that makes sense: an alert can only
        sensibly join a case about the same customer."""
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT case_id, status, created_at, updated_at
                FROM cases
                WHERE account_id = ? AND status = 'OPEN'
                ORDER BY created_at DESC
            """, (account_id,)).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_case_for_alert(alert_id: str) -> Optional[sqlite3.Row]:
        """Convenience lookup: which open case (if any) is this alert already
        linked to? Used by the UI to decide whether to show 'Create Case' or
        'View Case'."""
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT c.* FROM cases c
                JOIN case_alert_map cam ON cam.case_id = c.case_id
                WHERE cam.alert_id = ? AND c.status = 'OPEN'
                ORDER BY c.created_at DESC
                LIMIT 1
            """, (alert_id,)).fetchone()
        finally:
            conn.close()

    @staticmethod
    def find_related_open_alerts(alert_id: str, window_days: int = 30) -> list[sqlite3.Row]:
        """
        Suggests candidate alerts for grouping: other alerts on the SAME
        account_id, raised within `window_days` of this alert, that are not
        already in a case together with it. This is a *suggestion* query for
        the UI ("these look related, want to group them?") — it does not
        auto-create a case. Auto-grouping policy (if/when alerts should be
        grouped automatically rather than analyst-confirmed) is intentionally
        left as an explicit decision; see README for the policy note.
        """
        conn = AMLService._connect()
        try:
            target = conn.execute(
                "SELECT account_id, created_at FROM aml_alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if target is None:
                return []
            return conn.execute("""
                SELECT alert_id, scenario_code, severity, status, created_at
                FROM aml_alerts
                WHERE account_id = :account_id
                  AND alert_id != :alert_id
                  AND ABS(julianday(created_at) - julianday(:anchor_created_at)) <= :window_days
                ORDER BY created_at DESC
            """, {
                "account_id": target["account_id"],
                "alert_id": alert_id,
                "anchor_created_at": target["created_at"],
                "window_days": window_days,
            }).fetchall()
        finally:
            conn.close()

    # ── SLA / Reporting (Part 3) ─────────────────────────────────────────

    @staticmethod
    def get_sla_report() -> dict:
        """Aggregates the SLA/reporting metrics from str_decisions and
        aml_alerts. See aml_reports.py for the underlying query
        implementations — this method just delegates and assembles the
        response dict the /reports route renders."""
        import aml_reports
        conn = AMLService._connect()
        try:
            return aml_reports.build_sla_report(conn)
        finally:
            conn.close()