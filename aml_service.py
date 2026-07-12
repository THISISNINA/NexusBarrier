"""aml_service.py — service layer between app.py (routing only, no SQL) and aml_engine.py (detection + AMLWorkflowManager); owns all dashboard DB access and connection lifecycle, routes every alert-state change through transition_alert(), and lets WorkflowError propagate to app.py."""
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional, Sequence

import aml_engine
import aml_loader
import kyc_risk
import pii_crypto
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

    # Connection helper

    @staticmethod
    def _connect() -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def ensure_db_ready() -> None:
        """Runs schema setup/migration unconditionally on every app start.
        Deliberately NOT gated behind a probe query — aml_engine.init_schema is
        fully idempotent (CREATE TABLE IF NOT EXISTS, INSERT OR IGNORE, additive
        ALTER TABLE guards via _apply_additive_migrations), so calling it every
        time costs nothing on a healthy DB, but guarantees a DB created before a
        newer table/column existed (e.g. ctr_filings) gets migrated forward
        instead of silently staying stale."""
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = AMLService._connect()
        try:
            aml_engine.init_schema(conn)
        finally:
            conn.close()

    # Child-before-parent so DROPs are safe under foreign_keys=ON; ingestion_log is excluded (global, no company_id) and aml_alert_transactions is special-cased (no company_id, scoped via aml_alerts).
    _RESET_TABLES_CHILD_FIRST = (
        "aml_alert_transactions", "aml_alert_views", "risk_scores",
        "case_alert_map", "cases", "str_decisions", "aml_alerts",
        "aml_engine_runs", "ctr_filings", "customer_profiles", "transactions",
    )

    @staticmethod
    def reset_demo_data(company_id: str) -> None:
        """Wipes company_id's alert/decision/risk-score/case/transaction
        data back to a blank slate, WITHOUT touching any other company's
        data. Used by the manual "Reset Demo" button (MLRO-only, company-
        scoped — see app.py's /reset-demo route).

        DROPS rather than DELETEs each table — str_decisions, risk_scores,
        aml_alert_views, and ctr_filings each carry a BEFORE DELETE trigger
        that intentionally blocks row deletion (append-only audit trail,
        per the "do not change" design constraint) — DROP TABLE doesn't
        fire per-row triggers. What makes this company-scoped rather than
        the original whole-DB wipe: every other company's rows are saved
        into a temp table first, and restored after aml_engine.init_schema()/
        aml_loader.init_db() recreate each table (with its triggers) fresh.

        Leaves untouched: aml_scenarios and rule_versions (global app
        configuration, not demo data), the seeded sanctions_list / pep_list
        baseline in screening.db (also global), and ingestion_log (global,
        no company_id). Only removes this company's internal_watchlist rows
        that the engine itself added during the session (auto-added when a
        SAR was filed).
        """
        conn = AMLService._connect()
        try:
            for table in AMLService._RESET_TABLES_CHILD_FIRST:
                if table == "aml_alert_transactions":
                    # No company_id of its own — filter through aml_alerts, which still exists (nothing dropped yet).
                    conn.execute(
                        f"CREATE TEMP TABLE _keep_{table} AS SELECT * FROM {table} "
                        "WHERE alert_id IN (SELECT alert_id FROM aml_alerts WHERE company_id != ?)",
                        (company_id,),
                    )
                else:
                    conn.execute(
                        f"CREATE TEMP TABLE _keep_{table} AS SELECT * FROM {table} WHERE company_id != ?",
                        (company_id,),
                    )
            for table in AMLService._RESET_TABLES_CHILD_FIRST:
                conn.execute(f"DROP TABLE {table}")
            conn.commit()

            # Recreates every dropped table (with triggers) and re-seeds aml_scenarios/rule_versions idempotently.
            aml_engine.init_schema(conn)
            # transactions is aml_loader's table, not aml_engine's — recreate it too (ingestion_log was never dropped).
            aml_loader.init_db(conn)

            # Parent-before-child on the way back in, for the same FK reasons.
            for table in reversed(AMLService._RESET_TABLES_CHILD_FIRST):
                temp_name = f"_keep_{table}"
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({temp_name})").fetchall()]
                col_list = ", ".join(cols)
                conn.execute(f"INSERT INTO {table} ({col_list}) SELECT {col_list} FROM {temp_name}")
                conn.execute(f"DROP TABLE {temp_name}")
            conn.commit()
        finally:
            conn.close()

        try:
            s_conn = aml_engine._get_screening_conn()
            s_conn.execute(
                "DELETE FROM internal_watchlist WHERE company_id = ? AND added_by = 'SYSTEM' "
                "AND notes LIKE 'Auto-added on SAR filing%'",
                (company_id,),
            )
            s_conn.commit()
            s_conn.close()
        except Exception:
            pass

    # Read queries

    @staticmethod
    def get_alerts_for_role(company_id: str, role: str) -> list[dict]:
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

        `company_id` comes from the authenticated session (g.user) —
        never from anything client-supplied — and scopes every alert,
        every join, to that tenant only.
        """
        target_status = "ESCALATED" if role == "MLRO" else "OPEN"
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    a.typology, a.severity, a.trigger_value,
                    a.account_id, a.created_at, a.status, a.sla_breached, a.sla_due_date,
                    a.risk_score_at_alert, a.risk_tier_at_alert, cp.risk_rating AS customer_risk_rating
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                LEFT JOIN customer_profiles cp ON cp.account_id = a.account_id AND cp.company_id = a.company_id
                WHERE a.company_id = ? AND a.status = ?
                ORDER BY COALESCE(a.risk_score_at_alert, 0) DESC, a.created_at DESC
            """, (company_id, target_status)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def get_open_alerts(company_id: str) -> list[dict]:
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    a.typology, a.severity, a.trigger_value,
                    a.account_id, a.created_at, a.status, a.sla_breached, a.sla_due_date,
                    a.risk_score_at_alert, a.risk_tier_at_alert, cp.risk_rating AS customer_risk_rating
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                LEFT JOIN customer_profiles cp ON cp.account_id = a.account_id AND cp.company_id = a.company_id
                WHERE a.company_id = ? AND a.status = 'OPEN'
                ORDER BY COALESCE(a.risk_score_at_alert, 0) DESC, a.created_at DESC
            """, (company_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def get_open_and_escalated_alerts(company_id: str) -> list[dict]:
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
            rows = conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    a.typology, a.severity, a.trigger_value,
                    a.account_id, a.created_at, a.status, a.sla_breached, a.sla_due_date,
                    a.risk_score_at_alert, a.risk_tier_at_alert, cp.risk_rating AS customer_risk_rating
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                LEFT JOIN customer_profiles cp ON cp.account_id = a.account_id AND cp.company_id = a.company_id
                WHERE a.company_id = ? AND a.status IN ('OPEN', 'ESCALATED', 'DRAFT_SAR')
                ORDER BY COALESCE(a.risk_score_at_alert, 0) DESC, a.created_at DESC
            """, (company_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def get_all_alerts(company_id: str) -> list[dict]:
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    a.typology, a.severity, a.trigger_value, a.account_id, a.created_at, a.status,
                    a.sla_breached, a.sla_due_date,
                    a.risk_score_at_alert, a.risk_tier_at_alert, cp.risk_rating AS customer_risk_rating
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                LEFT JOIN customer_profiles cp ON cp.account_id = a.account_id AND cp.company_id = a.company_id
                WHERE a.company_id = ?
                ORDER BY a.created_at DESC
            """, (company_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


    @staticmethod
    def get_rule_version_for_alert(company_id: str, alert_id: str) -> Optional[sqlite3.Row]:
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
                WHERE a.alert_id = ? AND a.company_id = ?
            """, (alert_id, company_id)).fetchone()
        finally:
            conn.close()

    @staticmethod
    def get_alert(company_id: str, alert_id: str) -> Optional[dict]:
        """Filters by BOTH company_id and alert_id — IDOR-safe by
        construction. A user guessing/incrementing another company's
        alert_id gets None back, indistinguishable from the alert simply
        not existing, even though that id is perfectly valid for a
        different tenant."""
        conn = AMLService._connect()
        try:
            row = conn.execute("""
                SELECT a.*, s.description AS scenario_description, s.typology AS scenario_typology
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                WHERE a.alert_id = ? AND a.company_id = ?
            """, (alert_id, company_id)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def log_alert_view(company_id: str, alert_id: str, analyst_id: str, analyst_role: Optional[str] = None) -> None:
        """Records that an analyst opened this alert's detail page —
        see aml_engine.record_alert_view(). Best-effort: a logging failure
        here should never block the analyst from actually viewing the
        alert, so callers (app.py) should treat this as fire-and-forget."""
        conn = AMLService._connect()
        try:
            aml_engine.record_alert_view(conn, alert_id, analyst_id, company_id, analyst_role)
        finally:
            conn.close()

    @staticmethod
    def get_time_in_review(company_id: str, alert_id: str) -> dict:
        """See aml_engine.time_in_review_summary() — view-history-derived
        investigation time, distinct from the calendar-time SLA metrics
        in aml_reports.py."""
        conn = AMLService._connect()
        try:
            return aml_engine.time_in_review_summary(conn, alert_id, company_id)
        finally:
            conn.close()

    @staticmethod
    def get_alert_transactions(company_id: str, alert_id: str) -> list[dict]:
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT t.* FROM aml_alert_transactions at
                JOIN aml_alerts a ON a.alert_id = at.alert_id
                JOIN transactions t ON t.transaction_id = at.transaction_id
                WHERE at.alert_id = ? AND a.company_id = ?
                ORDER BY t.transaction_date DESC
            """, (alert_id, company_id)).fetchall()
            # Task 3: decrypt counterparty_wallet_address (encrypted at rest) for the alert-detail transactions table.
            txns = [dict(r) for r in rows]
            for t in txns:
                if "counterparty_wallet_address" in t:
                    t["counterparty_wallet_address"] = pii_crypto.decrypt_pii(t.get("counterparty_wallet_address"))
            return txns
        finally:
            conn.close()

    @staticmethod
    def get_customer_profile(company_id: str, account_id: str) -> Optional[dict]:
        conn = AMLService._connect()
        try:
            row = conn.execute(
                "SELECT * FROM customer_profiles WHERE account_id = ? AND company_id = ?", (account_id, company_id)
            ).fetchone()
            if row is None:
                return None
            profile = dict(row)
            # Task 3: the authorized profile fetch — decrypt the PII columns (customer_name/nationality/date_of_birth) so the page and downstream computations see cleartext.
            pii_crypto.decrypt_profile_fields(profile)
            try:
                profile["watchlist_entry"] = aml_engine.check_internal_watchlist(conn, account_id, company_id)
            except Exception:
                profile["watchlist_entry"] = None
            # Initial risk rating — computed on read, never persisted (pure function of the profile row; storing it would just be a driftable cache).
            profile["initial_risk"] = kyc_risk.calculate_initial_risk_rating(profile)
            profile["risk_rating_reason"] = AMLService._resolve_crr_reason(conn, profile)
            return profile
        finally:
            conn.close()

    @staticmethod
    def _resolve_crr_reason(conn: sqlite3.Connection, profile: dict) -> Optional[str]:
        """Display-time CRR justification, resolved on read like initial_risk
        and never persisted. The stored risk_rating_reason is written once at
        onboarding and only rewritten when recalculate_customer_risk_ratings
        strictly RAISES the stored rating — a customer seeded straight into
        an elevated tier keeps its onboarding text even while live alerts
        justify that tier, contradicting the Initial Risk Matrix rendered on
        the same page. When the current CRR sits above the computed KYC
        baseline and the stored text doesn't document the escalation,
        rebuild the justification from the live open-alert facts instead."""
        stored = profile.get("risk_rating_reason")
        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        current = (profile.get("risk_rating") or "").upper()
        baseline = profile["initial_risk"]["tier"]
        if rank.get(current, 0) <= rank.get(baseline, 0):
            return stored  # at/below onboarding baseline: onboarding text still valid
        if stored and stored.startswith("Auto re-rated"):
            return stored  # engine already documented this escalation
        open_alerts = conn.execute("""
            SELECT COUNT(*) FROM aml_alerts
            WHERE account_id = ? AND company_id = ?
              AND status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'DRAFT_SAR')
        """, (profile["account_id"], profile["company_id"])).fetchone()[0]
        if open_alerts:
            return (
                f"Escalated from {baseline} baseline due to {open_alerts} active "
                f"transaction monitoring alert{'s' if open_alerts != 1 else ''} under review"
            )
        return stored

    @staticmethod
    def get_decision_history(company_id: str, alert_id: str) -> list[dict]:
        conn = AMLService._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM str_decisions WHERE alert_id = ? AND company_id = ? ORDER BY decision_id ASC",
                (alert_id, company_id),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def get_alert_status(company_id: str, alert_id: str) -> str:
        """Authoritative status comes from str_decisions (what AMLWorkflowManager
        itself reads via get_latest_decision), not aml_alerts.status directly —
        the engine keeps both in sync on every transition, but routing through
        the same lookup the engine uses means this can never diverge from what
        transition_alert() will actually enforce next. Falls back to 'OPEN' to
        match AMLWorkflowManager's own default for alerts with no decision row
        — and, since aml_engine.AMLWorkflowManager itself has no company_id
        awareness, also for an alert_id that doesn't belong to company_id at
        all, same as the "no decision row" case (not a different error path
        that could disclose whether a foreign alert_id exists)."""
        conn = AMLService._connect()
        try:
            owned = conn.execute(
                "SELECT 1 FROM aml_alerts WHERE alert_id = ? AND company_id = ?", (alert_id, company_id)
            ).fetchone()
            if not owned:
                return "OPEN"
            record = AMLWorkflowManager.get_latest_decision(conn, alert_id)
            return record["workflow_status"] if record else "OPEN"
        finally:
            conn.close()

    @staticmethod
    def get_valid_next_states(company_id: str, alert_id: str) -> list[str]:
        status = AMLService.get_alert_status(company_id, alert_id)
        return AMLWorkflowManager.VALID_TRANSITIONS.get(status, [])

    @staticmethod
    def get_viewed_alert_ids(company_id: str, analyst_id: str) -> set[str]:
        """Distinct alert_ids this specific analyst/MLRO has opened at least
        once, sourced from the append-only aml_alert_views log. Used to
        build a genuinely personal 'My Reviews' view for MLRO — alerts
        THIS MLRO has actually looked at — instead of just re-showing the
        full escalated inbox under a different page title. Scoped by
        analyst_id (a real per-user id post-login, not a shared session
        value) and, for consistency with every other per-company table,
        company_id too."""
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT DISTINCT alert_id FROM aml_alert_views WHERE analyst_id = ? AND company_id = ?
            """, (analyst_id, company_id)).fetchall()
            return {r["alert_id"] for r in rows}
        finally:
            conn.close()

    # Workflow actions (ALL routed through AMLWorkflowManager)

    @staticmethod
    def _assert_alert_owned_by(conn: sqlite3.Connection, company_id: str, alert_id: str) -> None:
        """Gate every write path the same way get_alert() gates reads: if
        alert_id doesn't belong to company_id, refuse before touching
        AMLWorkflowManager at all — transition_alert itself has no
        company_id awareness, so ownership must be verified here, once,
        at entry. Raises WorkflowError (not a 403/permission error) so a
        guessed alert_id from another tenant is indistinguishable from an
        alert_id that simply doesn't exist."""
        owned = conn.execute(
            "SELECT 1 FROM aml_alerts WHERE alert_id = ? AND company_id = ?", (alert_id, company_id)
        ).fetchone()
        if not owned:
            raise WorkflowError("Alert not found.")

    @staticmethod
    def claim_alert(company_id: str, alert_id: str, analyst_id: str, analyst_role: Optional[str] = None) -> None:
        """OPEN -> UNDER_REVIEW. Raises WorkflowError if alert is not
        currently OPEN — AMLWorkflowManager.VALID_TRANSITIONS only allows
        this transition from OPEN, so that rule is enforced there, not here.
        Callable by either role: an MLRO claiming a fresh OPEN alert directly
        (skipping the analyst tier) is an explicit, supported path, not just
        an L1_ANALYST action — the audit trail still records exactly who
        claimed it and in what role via analyst_role."""
        conn = AMLService._connect()
        try:
            AMLService._assert_alert_owned_by(conn, company_id, alert_id)
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
    def escalate_alert(company_id: str, alert_id: str, analyst_id: str, role: Optional[str], narrative: str = ""):
        conn = AMLService._connect()
        try:
            AMLService._assert_alert_owned_by(conn, company_id, alert_id)
            AMLWorkflowManager.transition_alert(
                conn,
                alert_id=alert_id,
                analyst_id=analyst_id,
                target_status="ESCALATED",
                analyst_role=role,
                narrative=narrative
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def return_to_analyst(company_id: str, alert_id: str, analyst_id: str, note: str, analyst_role: Optional[str] = None) -> None:
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
            AMLService._assert_alert_owned_by(conn, company_id, alert_id)
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

    # UI/orchestration mapping of closure reason codes to CLOSED_SAR vs CLOSED_NO_ACTION; actual enforcement lives in AMLWorkflowManager.transition_alert, not here.
    SAR_CLOSURE_CODES = ("STRUCTURING_CONFIRMED", "HIGH_RISK_CONFIRMED")

    @staticmethod
    def close_alert(
        company_id: str,
        alert_id: str,
        analyst_id: str,
        narrative: str,
        closure_reason: str,
        sar_reference: Optional[str] = None,
        analyst_role: Optional[str] = None,
        mlro_rationale: Optional[str] = None,
        self_attested: bool = False,
    ) -> str:
        """
        UNDER_REVIEW / ESCALATED / DRAFT_SAR -> CLOSED_SAR or CLOSED_NO_ACTION.

        Determines the target terminal status from closure_reason (SAR-implying
        codes -> CLOSED_SAR, everything else -> CLOSED_NO_ACTION), then calls
        AMLWorkflowManager.transition_alert with that target. ALL validation —
        narrative non-empty/long enough, closure_reason must be a recognised
        code, goAML reference required when filing a SAR, and the current
        status must permit closing at all — is enforced inside transition_alert
        itself via WorkflowError. This method does not pre-validate or
        short-circuit any of those checks; it only decides which of the two
        terminal states to *attempt*.

        `mlro_rationale` (item 1): the MLRO's independent assessment, kept
        separate from the analyst's own `narrative` — see
        AMLWorkflowManager.transition_alert, which only persists this when
        analyst_role == 'MLRO'.

        Returns the target_status string on success (useful for flash messages).
        Raises WorkflowError on any compliance violation.
        """
        target_status = (
            "CLOSED_SAR" if closure_reason in AMLService.SAR_CLOSURE_CODES
            else "CLOSED_NO_ACTION"
        )

        conn = AMLService._connect()
        try:
            AMLService._assert_alert_owned_by(conn, company_id, alert_id)
            AMLWorkflowManager.transition_alert(
                conn,
                alert_id=alert_id,
                analyst_id=analyst_id,
                target_status=target_status,
                narrative=narrative,
                closure_code=closure_reason or None,
                goaml_ref=sar_reference or None,
                analyst_role=analyst_role,
                mlro_rationale=mlro_rationale,
                self_attested=self_attested,
            )
            conn.commit()
            return target_status
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Item 13: DRAFT_SAR workflow

    @staticmethod
    def draft_sar(company_id: str, alert_id: str, analyst_id: str, analyst_role: Optional[str], mlro_rationale: str) -> None:
        """ESCALATED -> DRAFT_SAR. MLRO-only (enforced in transition_alert).
        mlro_rationale doubles as the narrative so the draft has a real
        written assessment behind it, not a bare status flip."""
        conn = AMLService._connect()
        try:
            AMLService._assert_alert_owned_by(conn, company_id, alert_id)
            AMLWorkflowManager.transition_alert(
                conn, alert_id=alert_id, analyst_id=analyst_id, target_status="DRAFT_SAR",
                narrative=mlro_rationale, analyst_role=analyst_role, mlro_rationale=mlro_rationale,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def submit_sar(company_id: str, alert_id: str, analyst_id: str, analyst_role: Optional[str],
                    goaml_ref: str, narrative: str, mlro_rationale: Optional[str] = None,
                    self_attested: bool = False) -> None:
        """DRAFT_SAR -> CLOSED_SAR. The 'Submit SAR' button on the
        DRAFT_SAR alert page — requires the goAML reference number.

        `self_attested` carries the sole-MLRO self-review confirmation through
        to the four-eyes gate, since filing from DRAFT_SAR is itself a closure."""
        conn = AMLService._connect()
        try:
            AMLService._assert_alert_owned_by(conn, company_id, alert_id)
            AMLWorkflowManager.transition_alert(
                conn, alert_id=alert_id, analyst_id=analyst_id, target_status="CLOSED_SAR",
                narrative=narrative, closure_code="HIGH_RISK_CONFIRMED", goaml_ref=goaml_ref,
                analyst_role=analyst_role, mlro_rationale=mlro_rationale,
                self_attested=self_attested,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Case management (Part 5)

    @staticmethod
    def create_case(company_id: str, alert_id: str) -> str:
        """Creates a new case and links the given alert to it. Stamps
        case_id directly onto aml_alerts (item 10) so the alert detail
        page can show the case reference without an extra join, and so
        the PDF report can include it."""
        conn = AMLService._connect()
        try:
            alert = conn.execute(
                "SELECT account_id FROM aml_alerts WHERE alert_id = ? AND company_id = ?", (alert_id, company_id)
            ).fetchone()
            if alert is None:
                raise ValueError(f"No such alert: {alert_id}")

            case_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT INTO cases (case_id, account_id, status, created_at, updated_at, company_id)
                VALUES (?, ?, 'OPEN', ?, ?, ?)
            """, (case_id, alert["account_id"], now, now, company_id))
            conn.execute("""
                INSERT INTO case_alert_map (case_id, alert_id, linked_at, company_id)
                VALUES (?, ?, ?, ?)
            """, (case_id, alert_id, now, company_id))
            conn.execute("UPDATE aml_alerts SET case_id = ? WHERE alert_id = ? AND company_id = ?", (case_id, alert_id, company_id))
            conn.commit()
            return case_id
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def link_alert_to_case(company_id: str, alert_id: str, case_id: str) -> None:
        """Adds an additional alert to an existing case (idempotent — linking
        the same alert twice is a no-op, not an error). Also stamps case_id
        onto the alert (item 10) and re-syncs the case's mirrored status."""
        conn = AMLService._connect()
        try:
            case = conn.execute("SELECT 1 FROM cases WHERE case_id = ? AND company_id = ?", (case_id, company_id)).fetchone()
            if case is None:
                raise ValueError(f"No such case: {case_id}")
            alert = conn.execute(
                "SELECT 1 FROM aml_alerts WHERE alert_id = ? AND company_id = ?", (alert_id, company_id)
            ).fetchone()
            if alert is None:
                raise ValueError(f"No such alert: {alert_id}")

            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR IGNORE INTO case_alert_map (case_id, alert_id, linked_at, company_id)
                VALUES (?, ?, ?, ?)
            """, (case_id, alert_id, now, company_id))
            conn.execute("UPDATE aml_alerts SET case_id = ? WHERE alert_id = ? AND company_id = ?", (case_id, alert_id, company_id))
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ? AND company_id = ?", (now, case_id, company_id))
            AMLService._resync_case_status(conn, case_id)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _resync_case_status(conn: sqlite3.Connection, case_id: str) -> None:
        """Item 10: case status mirrors the highest-severity linked alert's
        status. Severity ranking (HIGH > MEDIUM > LOW) breaks ties when
        multiple alerts share a status; among equal severities, the most
        urgent (least-terminal) status wins."""
        status_rank = {"OPEN": 5, "UNDER_REVIEW": 4, "ESCALATED": 3, "DRAFT_SAR": 2,
                        "CLOSED_SAR": 1, "CLOSED_NO_ACTION": 1}
        severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        rows = conn.execute(
            "SELECT a.status, a.severity FROM case_alert_map cam JOIN aml_alerts a ON a.alert_id = cam.alert_id WHERE cam.case_id = ?",
            (case_id,),
        ).fetchall()
        if not rows:
            return
        best = max(rows, key=lambda r: (status_rank.get(r["status"], 0), severity_rank.get(r["severity"], 0)))
        conn.execute("UPDATE cases SET status = ? WHERE case_id = ?", (best["status"], case_id))

    @staticmethod
    def update_case_narrative(company_id: str, case_id: str, narrative: str) -> None:
        """Item 10: single overall case-assessment narrative field."""
        conn = AMLService._connect()
        try:
            conn.execute(
                "UPDATE cases SET case_narrative = ?, updated_at = ? WHERE case_id = ? AND company_id = ?",
                (narrative, datetime.now(timezone.utc).isoformat(), case_id, company_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def get_case(company_id: str, case_id: str) -> Optional[dict]:
        """Returns the case row, all linked alerts, and a combined
        transaction timeline across every linked alert (item 10), or None
        if not found."""
        conn = AMLService._connect()
        try:
            case = conn.execute(
                "SELECT * FROM cases WHERE case_id = ? AND company_id = ?", (case_id, company_id)
            ).fetchone()
            if case is None:
                return None
            alerts = conn.execute("""
                SELECT a.alert_id, a.scenario_code, a.severity, a.status, a.created_at,
                       a.typology, cam.linked_at
                FROM case_alert_map cam
                JOIN aml_alerts a ON a.alert_id = cam.alert_id
                WHERE cam.case_id = ? AND cam.company_id = ?
                ORDER BY cam.linked_at ASC
            """, (case_id, company_id)).fetchall()
            timeline = conn.execute("""
                SELECT DISTINCT t.transaction_id, t.account_id, t.amount, t.country,
                       t.transaction_date, t.counterparty_name, t.reference, at.alert_id
                FROM case_alert_map cam
                JOIN aml_alert_transactions at ON at.alert_id = cam.alert_id
                JOIN transactions t ON t.transaction_id = at.transaction_id
                WHERE cam.case_id = ? AND cam.company_id = ?
                ORDER BY t.transaction_date DESC
            """, (case_id, company_id)).fetchall()
            return {
                "case": dict(case),
                "alerts": [dict(a) for a in alerts],
                "timeline": [dict(t) for t in timeline],
            }
        finally:
            conn.close()

    @staticmethod
    def bulk_transition(company_id: str, alert_ids: list[str], action: str, analyst_id: str, analyst_role: Optional[str] = None,
                         narrative: Optional[str] = None) -> dict:
        """Applies one of the two supported bulk workflow actions
        (claim / false-positive closure) to a batch of alerts, one
        transition_alert() call per alert — NOT a single bulk SQL UPDATE.
        Each alert gets its own str_decisions audit row, and each alert's
        current status is independently validated by AMLWorkflowManager.

        Item 6: ESCALATED and CLOSED_SAR are intentionally NOT available
        as bulk actions. A SAR filing or an escalation is a per-alert
        compliance judgment that deserves its own narrative and its own
        single-alert confirmation — applying one narrative across N
        unrelated alerts risks a sloppy, undifferentiated escalation
        trail. Bulk is restricted to the two genuinely safe-to-batch
        operations: claiming (no judgment call) and closing a batch of
        alerts that have already been individually reviewed and judged
        to be false positives.

        Returns {"succeeded": [alert_id, ...], "failed": [(alert_id, reason), ...]}.
        """
        if action not in ("claim", "false_positive"):
            raise ValueError(f"bulk_transition: unsupported action {action!r}. Supported: ['claim', 'false_positive']")

        succeeded, failed = [], []
        for alert_id in alert_ids:
            try:
                if action == "claim":
                    AMLService.claim_alert(company_id, alert_id, analyst_id, analyst_role)
                else:
                    AMLService.close_alert(
                        company_id, alert_id, analyst_id,
                        narrative=narrative or "Bulk-closed as false positive after individual review.",
                        closure_reason="FALSE_POSITIVE",
                        analyst_role=analyst_role,
                    )
                succeeded.append(alert_id)
                try:
                    AMLService.log_alert_view(company_id, alert_id, analyst_id, analyst_role)
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

    # Item 2: Pre-transaction wire interdiction

    @staticmethod
    def get_correspondent_accounts(company_id: str) -> list[dict]:
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT cp.account_id, cp.customer_name, cp.swift_bic, cp.risk_rating,
                       cp.edd_required,
                       (SELECT COUNT(*) FROM aml_alerts a
                        WHERE a.account_id = cp.account_id AND a.company_id = cp.company_id
                          AND a.status IN ('OPEN','UNDER_REVIEW','ESCALATED','DRAFT_SAR')) AS open_alert_count
                FROM customer_profiles cp
                WHERE cp.account_category = 'CORRESPONDENT' AND cp.company_id = ?
            """, (company_id,)).fetchall()
            # Task 3: decrypt customer_name and sort in Python — a SQL ORDER BY would only sort ciphertext.
            accounts = [dict(r) for r in rows]
            for a in accounts:
                a["customer_name"] = pii_crypto.decrypt_pii(a.get("customer_name"))
            accounts.sort(key=lambda a: (a.get("customer_name") or "").lower())
            return accounts
        finally:
            conn.close()

    @staticmethod
    def submit_wire_transfer(
        company_id: str, account_id: str, amount: float, country: str,
        ordering_customer_name: str, beneficiary_name: str,
        originating_bank_bic: Optional[str], reference: Optional[str],
    ) -> dict:
        conn = AMLService._connect()
        try:
            result = aml_engine.submit_wire_transfer(
                conn, account_id, amount, country,
                ordering_customer_name, beneficiary_name,
                originating_bank_bic, reference, company_id,
            )
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def get_wire_interdiction_log(company_id: str, limit: int = 50) -> list[dict]:
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT t.transaction_id, t.account_id, cp.customer_name,
                       t.amount, t.country, t.transaction_date, t.reference,
                       t.ordering_customer_name, t.beneficiary_name,
                       t.originating_bank_bic, t.interdiction_status, t.interdicted_at,
                       a.alert_id, a.severity
                FROM transactions t
                JOIN customer_profiles cp ON cp.account_id = t.account_id AND cp.company_id = t.company_id
                LEFT JOIN aml_alert_transactions at ON at.transaction_id = t.transaction_id
                LEFT JOIN aml_alerts a ON a.alert_id = at.alert_id AND a.company_id = t.company_id
                WHERE cp.account_category = 'CORRESPONDENT'
                  AND t.interdicted_at IS NOT NULL
                  AND t.company_id = ?
                ORDER BY t.interdicted_at DESC
                LIMIT ?
            """, (company_id, limit)).fetchall()
            # Task 3: customer_name is encrypted at rest; wire-message ordering_customer_name/beneficiary_name stay cleartext (screening inputs).
            logs = [dict(r) for r in rows]
            for entry in logs:
                entry["customer_name"] = pii_crypto.decrypt_pii(entry.get("customer_name"))
            return logs
        finally:
            conn.close()

    # Item 7: Network / link analysis

    @staticmethod
    def get_account_network(company_id: str, account_id: str) -> dict:
        """Relationship graph centered on one account: shared counterparties,
        shared UBOs, shared high-risk corridors, and smurfing co-detection.

        Every sub-query below is scoped to company_id, not just account_id —
        this method's entire job is finding OTHER accounts that look related
        (shared counterparty name, shared country, shared UBO string), which
        is exactly the kind of query where an unscoped account_id match could
        silently link one company's account to a different company's account
        that just happens to share a counterparty name or UBO string."""
        conn = AMLService._connect()
        try:
            profile = conn.execute(
                "SELECT * FROM customer_profiles WHERE account_id = ? AND company_id = ?", (account_id, company_id)
            ).fetchone()
            if profile is None:
                return {}
            profile = dict(profile)
            pii_crypto.decrypt_profile_fields(profile)  # Task 3: cleartext for display

            alerts = [dict(r) for r in conn.execute("""
                SELECT alert_id, scenario_code, typology, severity, status, created_at, narrative
                FROM aml_alerts WHERE account_id = ? AND company_id = ?
                ORDER BY created_at DESC
            """, (account_id, company_id)).fetchall()]

            ctrs = [dict(r) for r in conn.execute("""
                SELECT ctr_id, filing_date, total_amount, transaction_count
                FROM ctr_filings WHERE account_id = ? AND company_id = ?
                ORDER BY filing_date DESC LIMIT 10
            """, (account_id, company_id)).fetchall()]

            links: list[dict] = []
            seen: set[str] = {account_id}

            # Shared counterparty names
            for r in conn.execute("""
                SELECT DISTINCT t2.account_id, cp2.customer_name, t1.counterparty_name
                FROM transactions t1
                JOIN transactions t2 ON LOWER(t2.counterparty_name) = LOWER(t1.counterparty_name)
                    AND t2.account_id != ? AND t2.company_id = ?
                JOIN customer_profiles cp2 ON cp2.account_id = t2.account_id AND cp2.company_id = t2.company_id
                WHERE t1.account_id = ? AND t1.company_id = ? AND t1.counterparty_name IS NOT NULL
                  AND t1.counterparty_name != ''
                LIMIT 30
            """, (account_id, company_id, account_id, company_id)).fetchall():
                if r[0] not in seen:
                    links.append({"account_id": r[0], "customer_name": r[1],
                                  "link_type": "SHARED_COUNTERPARTY", "link_value": r[2]})
                    seen.add(r[0])

            # Shared UBO
            if profile.get("ubo_names"):
                for ubo in profile["ubo_names"].split("|"):
                    ubo = ubo.strip()
                    if not ubo:
                        continue
                    for r in conn.execute("""
                        SELECT account_id, customer_name FROM customer_profiles
                        WHERE account_id != ? AND company_id = ? AND ubo_names IS NOT NULL
                          AND UPPER(ubo_names) LIKE UPPER(?)
                    """, (account_id, company_id, f"%{ubo}%")).fetchall():
                        if r[0] not in seen:
                            links.append({"account_id": r[0], "customer_name": r[1],
                                          "link_type": "SHARED_UBO", "link_value": ubo})
                            seen.add(r[0])

            # Shared high-risk corridor
            for r in conn.execute("""
                SELECT DISTINCT t2.account_id, cp2.customer_name, t1.country
                FROM transactions t1
                JOIN transactions t2 ON t2.country = t1.country AND t2.account_id != ? AND t2.company_id = ?
                JOIN customer_profiles cp2 ON cp2.account_id = t2.account_id AND cp2.company_id = t2.company_id
                WHERE t1.account_id = ? AND t1.company_id = ?
                  AND t1.country IN ('KP','IR','MM','SY','CU','YE','AF','HT','PK','PA','PH',
                                     'DZ','AO','BO','BG','CM','CI','CD','KE','KW','LA','LB',
                                     'MC','NA','NP','PG','SS','VE','VN','VG')
                LIMIT 20
            """, (account_id, company_id, account_id, company_id)).fetchall():
                if r[0] not in seen:
                    links.append({"account_id": r[0], "customer_name": r[1],
                                  "link_type": "SHARED_HIGH_RISK_COUNTRY", "link_value": r[2]})
                    seen.add(r[0])

            # Smurfing co-detection — strongest signal (engine already flagged these together)
            shared_alert_accounts: list[dict] = []
            for (aid,) in conn.execute("""
                SELECT alert_id FROM aml_alerts
                WHERE account_id = ? AND company_id = ? AND scenario_code = 'SCN_MULTI_ACCOUNT_STRUCTURING'
            """, (account_id, company_id)).fetchall():
                for r in conn.execute("""
                    SELECT DISTINCT a.account_id, cp.customer_name
                    FROM aml_alert_transactions aat
                    JOIN aml_alerts a ON a.alert_id = aat.alert_id
                    JOIN customer_profiles cp ON cp.account_id = a.account_id AND cp.company_id = a.company_id
                    WHERE aat.alert_id = ? AND a.account_id != ? AND a.company_id = ?
                """, (aid, account_id, company_id)).fetchall():
                    entry = {"account_id": r[0], "customer_name": r[1],
                             "link_type": "SMURFING_CO_DETECTION", "link_value": aid[:8] + "..."}
                    if r[0] not in seen:
                        links.append(entry)
                        seen.add(r[0])
                    if not any(x["account_id"] == r[0] for x in shared_alert_accounts):
                        shared_alert_accounts.append(entry)

            # Task 3: decrypt each linked account's customer_name for display (wallets aren't surfaced here).
            for entry in links:
                entry["customer_name"] = pii_crypto.decrypt_pii(entry.get("customer_name"))
            for entry in shared_alert_accounts:
                entry["customer_name"] = pii_crypto.decrypt_pii(entry.get("customer_name"))

            return {
                "profile": profile, "alerts": alerts, "ctrs": ctrs,
                "links": links, "shared_alert_accounts": shared_alert_accounts,
            }
        finally:
            conn.close()

    @staticmethod
    def get_dashboard_summary(company_id: str) -> dict:
        """Status counts + oldest still-open alert for the Dashboard
        landing block. Delegates to aml_reports.build_dashboard_summary()
        — the exact same underlying queries the full SLA Report uses for
        its own volume summary and oldest-open figure — so the Dashboard
        and /reports can never silently disagree on these numbers."""
        import aml_reports
        conn = AMLService._connect()
        try:
            return aml_reports.build_dashboard_summary(conn, company_id)
        finally:
            conn.close()

    @staticmethod
    def get_last_engine_run(company_id: str) -> Optional[dict]:
        """Most recent engine run for this workspace, for the dashboard's
        pipeline-health line. Surfaces status + errored_records_count (Task 2)
        so a PARTIAL pass — one where individual records threw and were skipped
        — is visibly flagged as incomplete rather than passing as clean."""
        conn = AMLService._connect()
        try:
            row = conn.execute("""
                SELECT run_id, run_at, scenarios_executed, alerts_generated,
                       alerts_suppressed, status, errored_records_count
                FROM aml_engine_runs
                WHERE company_id = ?
                ORDER BY run_at DESC LIMIT 1
            """, (company_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def get_open_cases_for_account(company_id: str, account_id: str) -> list[sqlite3.Row]:
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
                WHERE account_id = ? AND company_id = ? AND status = 'OPEN'
                ORDER BY created_at DESC
            """, (account_id, company_id)).fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_case_for_alert(company_id: str, alert_id: str) -> Optional[sqlite3.Row]:
        """Convenience lookup: which open case (if any) is this alert already
        linked to? Used by the UI to decide whether to show 'Create Case' or
        'View Case'."""
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT c.* FROM cases c
                JOIN case_alert_map cam ON cam.case_id = c.case_id
                WHERE cam.alert_id = ? AND c.company_id = ? AND c.status = 'OPEN'
                ORDER BY c.created_at DESC
                LIMIT 1
            """, (alert_id, company_id)).fetchone()
        finally:
            conn.close()

    @staticmethod
    def find_overlapping_alerts(company_id: str, alert_id: str) -> list[sqlite3.Row]:
        """
        Weakness fix: a customer structuring cash could plausibly trip
        both SCN_STRUCTURING_CASH and SCN_CASH_AGG_6M off the SAME
        underlying transactions, but nothing previously told an analyst
        that had happened — they'd have to notice the overlap themselves
        by comparing transaction lists across separate alerts by hand.

        This is a strictly stronger signal than find_related_open_alerts
        above: that one suggests grouping based on "same account, similar
        timing" (a heuristic that can be coincidental). This one only
        returns alerts that share at least one literal transaction_id via
        aml_alert_transactions — actual shared evidence, not a coincidence
        of timing. Both are useful for different reasons, so this is a
        separate method rather than a replacement for the other.

        Returns open alerts only (OPEN/UNDER_REVIEW/ESCALATED) — a shared
        transaction with an already-closed alert isn't actionable the same
        way, so it's excluded to keep this focused on "here's something
        you should look at together right now."
        """
        conn = AMLService._connect()
        try:
            return conn.execute("""
                SELECT DISTINCT
                    a.alert_id, a.scenario_code, a.severity, a.status, a.created_at,
                    COUNT(DISTINCT shared.transaction_id) AS shared_transaction_count
                FROM aml_alert_transactions this_alert
                JOIN aml_alert_transactions shared
                    ON shared.transaction_id = this_alert.transaction_id
                    AND shared.alert_id != this_alert.alert_id
                JOIN aml_alerts a ON a.alert_id = shared.alert_id
                WHERE this_alert.alert_id = :alert_id
                  AND a.company_id = :company_id
                  AND a.status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED')
                GROUP BY a.alert_id
                ORDER BY shared_transaction_count DESC, a.created_at DESC
            """, {"alert_id": alert_id, "company_id": company_id}).fetchall()
        finally:
            conn.close()

    @staticmethod
    def find_related_open_alerts(company_id: str, alert_id: str, window_days: int = 30) -> list[sqlite3.Row]:
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
                "SELECT account_id, created_at FROM aml_alerts WHERE alert_id = ? AND company_id = ?",
                (alert_id, company_id),
            ).fetchone()
            if target is None:
                return []
            return conn.execute("""
                SELECT alert_id, scenario_code, severity, status, created_at
                FROM aml_alerts
                WHERE account_id = :account_id
                  AND company_id = :company_id
                  AND alert_id != :alert_id
                  AND ABS(julianday(created_at) - julianday(:anchor_created_at)) <= :window_days
                ORDER BY created_at DESC
            """, {
                "account_id": target["account_id"],
                "company_id": company_id,
                "alert_id": alert_id,
                "anchor_created_at": target["created_at"],
                "window_days": window_days,
            }).fetchall()
        finally:
            conn.close()

    # SLA / Reporting (Part 3)

    @staticmethod
    def get_sla_report(company_id: str) -> dict:
        """Aggregates the SLA/reporting metrics from str_decisions and
        aml_alerts. See aml_reports.py for the underlying query
        implementations — this method just delegates and assembles the
        response dict the /reports route renders."""
        import aml_reports
        conn = AMLService._connect()
        try:
            return aml_reports.build_sla_report(conn, company_id)
        finally:
            conn.close()

    # Item 2: Time-in-review metrics for the Dashboard

    @staticmethod
    def get_time_in_review_metrics(company_id: str) -> dict:
        """Aggregates aml_engine.time_in_review_summary() across every
        alert that has at least one view logged, plus per-analyst
        productivity (alerts closed). Surfaced on the Dashboard per item 2
        — average hours per status, oldest open alert age (reuses
        aml_reports.oldest_open_alert), and closures per analyst."""
        import aml_reports
        conn = AMLService._connect()
        try:
            alert_ids = [r[0] for r in conn.execute(
                "SELECT alert_id FROM aml_alerts WHERE company_id = ?", (company_id,)
            ).fetchall()]
            durations_by_status: dict[str, list[float]] = {}
            for alert_id in alert_ids:
                status_row = conn.execute(
                    "SELECT workflow_status FROM str_decisions WHERE alert_id = ? AND company_id = ? ORDER BY decision_id DESC LIMIT 1",
                    (alert_id, company_id),
                ).fetchone()
                status = status_row[0] if status_row else "OPEN"
                summary = aml_engine.time_in_review_summary(conn, alert_id, company_id)
                if summary["time_in_review_days"] is not None:
                    durations_by_status.setdefault(status, []).append(summary["time_in_review_days"] * 24)

            avg_hours_by_status = {
                status: round(sum(vals) / len(vals), 1) for status, vals in durations_by_status.items()
            }

            productivity_rows = conn.execute("""
                WITH latest_decisions AS (
                    SELECT sd.* FROM str_decisions sd
                    INNER JOIN (SELECT alert_id, MAX(decision_id) AS max_id FROM str_decisions GROUP BY alert_id) m
                    ON m.alert_id = sd.alert_id AND m.max_id = sd.decision_id
                )
                SELECT analyst_id, COUNT(*) AS closed_count
                FROM latest_decisions
                WHERE workflow_status IN ('CLOSED_SAR', 'CLOSED_NO_ACTION') AND company_id = ?
                GROUP BY analyst_id ORDER BY closed_count DESC
            """, (company_id,)).fetchall()

            return {
                "avg_hours_by_status": avg_hours_by_status,
                "analyst_productivity": [dict(r) for r in productivity_rows],
                "oldest_open_alert": aml_reports.oldest_open_alert(conn, company_id),
            }
        finally:
            conn.close()

    # Screening hits route through SCN_SANCTION_MATCH/SCN_PEP_MATCH/SCN_INTERNAL_WATCHLIST into the Open Queue like any scenario; the standalone screening page/route was removed.

    # Item 9: Customers page

    @staticmethod
    def get_customers(company_id: str, search: Optional[str] = None, edd_only: bool = False) -> list[dict]:
        """All customer profiles with CRR, last review date, and open
        alert count, for the /customers page. `search` matches name or
        account_id (case-insensitive substring)."""
        conn = AMLService._connect()
        try:
            # Task 3: name LIKE/ORDER BY can't run against encrypted customer_name — non-encrypted filters stay in SQL; name/account_id search and sort are done in Python after decryption.
            sql = """
                SELECT cp.*,
                       (SELECT COUNT(*) FROM aml_alerts a
                        WHERE a.account_id = cp.account_id AND a.company_id = cp.company_id
                          AND a.status IN ('OPEN','UNDER_REVIEW','ESCALATED','DRAFT_SAR')) AS open_alert_count
                FROM customer_profiles cp
                WHERE cp.company_id = ?
            """
            params: list = [company_id]
            if edd_only:
                sql += " AND cp.edd_required = 1"
            # Keep HIGH-risk grouped first in SQL; within-group alphabetical order is re-applied in Python below.
            sql += " ORDER BY cp.risk_rating = 'HIGH' DESC"
            rows = conn.execute(sql, params).fetchall()
            customers = [dict(r) for r in rows]
            for c in customers:
                pii_crypto.decrypt_profile_fields(c)
                c["initial_risk"] = kyc_risk.calculate_initial_risk_rating(c)

            if search:
                needle = search.strip().lower()
                customers = [
                    c for c in customers
                    if needle in (c.get("customer_name") or "").lower()
                    or needle in (c.get("account_id") or "").lower()
                ]

            # HIGH-risk first, then case-insensitive name — a stable sort preserves the SQL-level HIGH-first grouping.
            customers.sort(key=lambda c: (c.get("customer_name") or "").lower())
            customers.sort(key=lambda c: c.get("risk_rating") != "HIGH")
            return customers
        finally:
            conn.close()

    @staticmethod
    def get_alerts_for_account(company_id: str, account_id: str) -> list[dict]:
        """Full alert history (all statuses) for one account — the customer
        detail page's alert panel. Same row shape as get_all_alerts minus
        the customer join, since the caller already holds the profile."""
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                SELECT
                    a.alert_id, a.scenario_code, s.description AS scenario_description,
                    a.typology, a.severity, a.trigger_value, a.created_at, a.status,
                    a.sla_breached, a.sla_due_date
                FROM aml_alerts a
                LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
                WHERE a.account_id = ? AND a.company_id = ?
                ORDER BY a.created_at DESC
            """, (account_id, company_id)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # Item 17: Rule performance / false-positive rate per scenario

    @staticmethod
    def get_ctr_filings(
        company_id: str,
        account_id: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 200,
    ) -> dict:
        """CTR filings page data: the filing rows themselves, plus summary
        stats (total filed, total AED reported, highest single-day filing,
        most-filed account) so a supervisor can see at a glance whether
        the month's mandatory reporting obligation was met — not just a
        raw table of rows with no context."""
        conn = AMLService._connect()
        try:
            params: list = [company_id]
            where_clauses = ["c.company_id = ?"]
            if account_id:
                where_clauses.append("c.account_id = ?")
                params.append(account_id)
            if date_from:
                where_clauses.append("c.filing_date >= ?")
                params.append(date_from)
            if date_to:
                where_clauses.append("c.filing_date <= ?")
                params.append(date_to)
            where = " AND ".join(where_clauses)

            rows = conn.execute(f"""
                SELECT c.ctr_id, c.account_id, cp.customer_name, cp.account_category,
                       cp.risk_rating, c.filing_date, c.total_amount,
                       c.transaction_count, c.threshold_applied, c.created_at
                FROM ctr_filings c
                JOIN customer_profiles cp ON cp.account_id = c.account_id AND cp.company_id = c.company_id
                WHERE {where}
                ORDER BY c.filing_date DESC, c.total_amount DESC
                LIMIT ?
            """, params + [limit]).fetchall()

            # Header summary stats (count filed + total exposure), respecting the same filters as the table.
            stats_row = conn.execute(f"""
                SELECT COUNT(*) AS total_filings,
                       COALESCE(SUM(c.total_amount), 0) AS total_amount_reported,
                       COALESCE(MAX(c.total_amount), 0) AS highest_single_filing,
                       COUNT(DISTINCT c.account_id) AS distinct_accounts
                FROM ctr_filings c
                WHERE {where}
            """, params).fetchone()

            top_account = conn.execute(f"""
                SELECT c.account_id, cp.customer_name, COUNT(*) AS filing_count,
                       SUM(c.total_amount) AS total
                FROM ctr_filings c
                JOIN customer_profiles cp ON cp.account_id = c.account_id AND cp.company_id = c.company_id
                WHERE {where}
                GROUP BY c.account_id, cp.customer_name
                ORDER BY filing_count DESC
                LIMIT 1
            """, params).fetchone()

            # Task 3: decrypt customer_name on each filing row and the top-account summary for display.
            filings = [dict(r) for r in rows]
            for f in filings:
                f["customer_name"] = pii_crypto.decrypt_pii(f.get("customer_name"))
            top = dict(top_account) if top_account else None
            if top:
                top["customer_name"] = pii_crypto.decrypt_pii(top.get("customer_name"))
            return {
                "filings": filings,
                "stats": dict(stats_row) if stats_row else {},
                "top_account": top,
                "filters": {"account_id": account_id, "date_from": date_from, "date_to": date_to},
            }
        finally:
            conn.close()

    @staticmethod
    def get_rule_performance(company_id: str) -> list[dict]:
        """One row per scenario: total alerts, total closed false-positive,
        FP rate %, and last-alert-generated date. Pure reporting query —
        no new tables, joins aml_alerts to the latest str_decisions row
        per alert the same way aml_reports.py's other metrics do.

        The company_id filter lives in the LEFT JOIN's ON clause, not a
        WHERE clause — aml_scenarios is global, and a WHERE filter on
        a.company_id would silently drop every scenario with zero alerts
        for this company (LEFT JOIN leaves a.* NULL for those rows, and
        NULL never equals company_id), which would make the page look
        like fewer than 12 scenarios exist instead of showing them at 0."""
        conn = AMLService._connect()
        try:
            rows = conn.execute("""
                WITH latest_decisions AS (
                    SELECT sd.* FROM str_decisions sd
                    INNER JOIN (SELECT alert_id, MAX(decision_id) AS max_id FROM str_decisions GROUP BY alert_id) m
                    ON m.alert_id = sd.alert_id AND m.max_id = sd.decision_id
                )
                SELECT
                    s.scenario_code, s.description,
                    COUNT(a.alert_id) AS total_alerts,
                    SUM(CASE WHEN ld.closure_reason_code = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS false_positive_count,
                    MAX(a.created_at) AS last_alert_at
                FROM aml_scenarios s
                LEFT JOIN aml_alerts a ON a.scenario_code = s.scenario_code AND a.company_id = ?
                LEFT JOIN latest_decisions ld ON ld.alert_id = a.alert_id
                GROUP BY s.scenario_code, s.description
                ORDER BY total_alerts DESC
            """, (company_id,)).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["fp_rate_pct"] = round((d["false_positive_count"] / d["total_alerts"]) * 100, 1) if d["total_alerts"] else None
                result.append(d)
            return result
        finally:
            conn.close()

    # Item 18: Regulatory reporting summary

    @staticmethod
    def get_regulatory_report(company_id: str, period_start: Optional[str] = None, period_end: Optional[str] = None) -> dict:
        """Monthly-default regulatory summary built entirely from existing
        tables — alert volume by scenario/risk, disposition breakdown,
        SAR filing summary (goAML refs redacted to last 4 digits), analyst
        productivity, and SLA compliance %."""
        conn = AMLService._connect()
        try:
            if not period_start or not period_end:
                now = datetime.now(timezone.utc)
                period_start = now.strftime("%Y-%m-01")
                period_end = now.strftime("%Y-%m-%d")

            alerts = conn.execute("""
                SELECT * FROM aml_alerts WHERE company_id = ? AND date(created_at) BETWEEN date(?) AND date(?)
            """, (company_id, period_start, period_end)).fetchall()

            by_scenario: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            for a in alerts:
                by_scenario[a["scenario_code"]] = by_scenario.get(a["scenario_code"], 0) + 1
                by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1

            latest_decisions = conn.execute("""
                WITH ld AS (
                    SELECT sd.* FROM str_decisions sd
                    INNER JOIN (SELECT alert_id, MAX(decision_id) AS max_id FROM str_decisions GROUP BY alert_id) m
                    ON m.alert_id = sd.alert_id AND m.max_id = sd.decision_id
                )
                SELECT ld.* FROM ld
                JOIN aml_alerts a ON a.alert_id = ld.alert_id
                WHERE a.company_id = ? AND date(a.created_at) BETWEEN date(?) AND date(?)
            """, (company_id, period_start, period_end)).fetchall()

            disposition = {"OPEN": 0, "UNDER_REVIEW": 0, "ESCALATED": 0, "DRAFT_SAR": 0,
                           "CLOSED_SAR": 0, "CLOSED_NO_ACTION": 0, "FALSE_POSITIVE": 0}
            sar_refs = []
            sar_lag_days = []
            analyst_counts: dict[str, int] = {}
            within_sla = total_actioned = 0

            for d in latest_decisions:
                status = d["workflow_status"]
                disposition[status] = disposition.get(status, 0) + 1
                if d["closure_reason_code"] == "FALSE_POSITIVE":
                    disposition["FALSE_POSITIVE"] += 1
                if status == "CLOSED_SAR" and d["goaml_reference_number"]:
                    ref = d["goaml_reference_number"]
                    sar_refs.append(f"...{ref[-4:]}" if len(ref) >= 4 else ref)
                    if d["created_at"] and d["closed_at"]:
                        lag = (datetime.fromisoformat(d["closed_at"].replace(" ", "T")) -
                               datetime.fromisoformat(d["created_at"].replace(" ", "T"))).days
                        sar_lag_days.append(lag)
                if status in ("CLOSED_SAR", "CLOSED_NO_ACTION"):
                    analyst_counts[d["analyst_id"]] = analyst_counts.get(d["analyst_id"], 0) + 1
                    total_actioned += 1

            for a in alerts:
                if a["status"] in ("CLOSED_SAR", "CLOSED_NO_ACTION"):
                    if not a["sla_breached"]:
                        within_sla += 1

            closed_count = disposition["CLOSED_SAR"] + disposition["CLOSED_NO_ACTION"]
            sla_compliance_pct = round((within_sla / closed_count) * 100, 1) if closed_count else None

            # CTR mandatory-reporting stats for the period — engine-filed, surfaced here so a supervisor/regulator can confirm the obligation was met.
            ctr_row = conn.execute("""
                SELECT COUNT(*) AS total_filed,
                       COALESCE(SUM(total_amount), 0) AS total_amount,
                       COUNT(DISTINCT account_id) AS distinct_accounts
                FROM ctr_filings
                WHERE company_id = ? AND filing_date BETWEEN date(?) AND date(?)
            """, (company_id, period_start, period_end)).fetchone()

            return {
                "period_start": period_start, "period_end": period_end,
                "alert_summary": {"total": len(alerts), "by_scenario": by_scenario, "by_severity": by_severity},
                "disposition_summary": disposition,
                "sar_summary": {
                    "total_sars": disposition["CLOSED_SAR"],
                    "goaml_references_redacted": sar_refs,
                    "avg_days_to_sar": round(sum(sar_lag_days) / len(sar_lag_days), 1) if sar_lag_days else None,
                },
                "ctr_summary": {
                    "total_filed": ctr_row["total_filed"] if ctr_row else 0,
                    "total_amount_reported": ctr_row["total_amount"] if ctr_row else 0,
                    "distinct_accounts": ctr_row["distinct_accounts"] if ctr_row else 0,
                },
                "analyst_productivity": analyst_counts,
                "sla_compliance_pct": sla_compliance_pct,
            }
        finally:
            conn.close()