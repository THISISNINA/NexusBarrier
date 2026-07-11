"""
aml_reports.py — SLA & Reporting Layer
------------------------------------------
Read-only aggregate queries over aml_alerts / str_decisions for the
/reports dashboard. No workflow logic, no writes — this module only ever
runs SELECT statements.

Metrics:
    - Average time to review   (created_at -> reviewed_at, str_decisions)
    - Average time to close    (created_at -> closed_at, str_decisions)
    - Alerts by scenario       (count + open/closed breakdown)
    - False positive rate      (closures with closure_reason_code = FALSE_POSITIVE
                                 as a % of all closed alerts)
    - SAR rate                 (CLOSED_SAR closures as a % of all closed alerts)

Timing note: created_at / reviewed_at / closed_at all live on str_decisions,
not aml_alerts — each row in str_decisions is a snapshot of those three
timestamps as of that transition (see AMLWorkflowManager.transition_alert,
which carries created_at/reviewed_at forward and only sets closed_at on a
terminal transition). So the timing queries here read the LATEST decision
row per alert_id, which has the final, complete picture of all three
timestamps for that alert.

Every function below takes company_id and scopes its query to it — these
are per-company reporting metrics, not cross-tenant aggregates.
"""
import sqlite3


def _latest_decision_per_alert_cte() -> str:
    """Shared CTE: the most recent str_decisions row for each alert_id.
    Used by every metric below so they're all reading the same definition
    of 'current state of this alert' as AMLWorkflowManager.get_latest_decision."""
    return """
        latest_decisions AS (
            SELECT sd.*
            FROM str_decisions sd
            INNER JOIN (
                SELECT alert_id, MAX(decision_id) AS max_id
                FROM str_decisions
                GROUP BY alert_id
            ) latest ON latest.alert_id = sd.alert_id AND latest.max_id = sd.decision_id
        )
    """


def avg_time_to_review_days(conn: sqlite3.Connection, company_id: str) -> float | None:
    """Average days between created_at and reviewed_at, across all alerts
    that have been reviewed at least once (reviewed_at IS NOT NULL)."""
    row = conn.execute(f"""
        WITH {_latest_decision_per_alert_cte()}
        SELECT AVG(julianday(reviewed_at) - julianday(created_at))
        FROM latest_decisions
        WHERE reviewed_at IS NOT NULL AND company_id = ?
    """, (company_id,)).fetchone()
    return row[0]


def avg_time_to_close_days(conn: sqlite3.Connection, company_id: str) -> float | None:
    """Average days between created_at and closed_at, across all closed alerts."""
    row = conn.execute(f"""
        WITH {_latest_decision_per_alert_cte()}
        SELECT AVG(julianday(closed_at) - julianday(created_at))
        FROM latest_decisions
        WHERE closed_at IS NOT NULL AND company_id = ?
    """, (company_id,)).fetchone()
    return row[0]


def alerts_by_scenario(conn: sqlite3.Connection, company_id: str) -> list[sqlite3.Row]:
    """Alert volume per scenario, broken down by open vs closed, most
    recently created scenarios first by volume."""
    conn.row_factory = sqlite3.Row
    return conn.execute("""
        SELECT
            a.scenario_code,
            COALESCE(s.description, a.scenario_code) AS scenario_description,
            COUNT(*) AS total_alerts,
            SUM(CASE WHEN a.status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED') THEN 1 ELSE 0 END) AS open_count,
            SUM(CASE WHEN a.status IN ('CLOSED_SAR', 'CLOSED_NO_ACTION') THEN 1 ELSE 0 END) AS closed_count
        FROM aml_alerts a
        LEFT JOIN aml_scenarios s ON s.scenario_code = a.scenario_code
        WHERE a.company_id = ?
        GROUP BY a.scenario_code
        ORDER BY total_alerts DESC
    """, (company_id,)).fetchall()


def false_positive_rate(conn: sqlite3.Connection, company_id: str) -> float | None:
    """Percentage of CLOSED alerts whose closure_reason_code was
    FALSE_POSITIVE specifically (not the broader CLOSED_NO_ACTION bucket —
    see alert_filter.py's docstring for why these are distinct fields).
    Returns None if there are no closed alerts yet (avoids a misleading 0%)."""
    row = conn.execute(f"""
        WITH {_latest_decision_per_alert_cte()}
        SELECT
            SUM(CASE WHEN closure_reason_code = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS fp_count,
            SUM(CASE WHEN workflow_status IN ('CLOSED_SAR', 'CLOSED_NO_ACTION') THEN 1 ELSE 0 END) AS closed_count
        FROM latest_decisions
        WHERE company_id = ?
    """, (company_id,)).fetchone()
    fp_count, closed_count = row
    if not closed_count:
        return None
    return (fp_count / closed_count) * 100.0


def sar_rate(conn: sqlite3.Connection, company_id: str) -> float | None:
    """Percentage of CLOSED alerts that resulted in CLOSED_SAR (a SAR filed),
    as a fraction of all closed alerts. Returns None if there are no closed
    alerts yet."""
    row = conn.execute(f"""
        WITH {_latest_decision_per_alert_cte()}
        SELECT
            SUM(CASE WHEN workflow_status = 'CLOSED_SAR' THEN 1 ELSE 0 END) AS sar_count,
            SUM(CASE WHEN workflow_status IN ('CLOSED_SAR', 'CLOSED_NO_ACTION') THEN 1 ELSE 0 END) AS closed_count
        FROM latest_decisions
        WHERE company_id = ?
    """, (company_id,)).fetchone()
    sar_count, closed_count = row
    if not closed_count:
        return None
    return (sar_count / closed_count) * 100.0


def alert_volume_summary(conn: sqlite3.Connection, company_id: str) -> dict:
    """High-level counts for the top of the reports page."""
    row = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) AS open_count,
            SUM(CASE WHEN status = 'UNDER_REVIEW' THEN 1 ELSE 0 END) AS under_review_count,
            SUM(CASE WHEN status = 'ESCALATED' THEN 1 ELSE 0 END) AS escalated_count,
            SUM(CASE WHEN status = 'CLOSED_SAR' THEN 1 ELSE 0 END) AS closed_sar_count,
            SUM(CASE WHEN status = 'CLOSED_NO_ACTION' THEN 1 ELSE 0 END) AS closed_no_action_count
        FROM aml_alerts
        WHERE company_id = ?
    """, (company_id,)).fetchone()
    return dict(row) if row else {}


def oldest_open_alert(conn: sqlite3.Connection, company_id: str) -> dict | None:
    """The single longest-waiting alert that hasn't reached a terminal
    state yet (OPEN, UNDER_REVIEW, or ESCALATED) — the headline 'what
    needs attention most' figure for the Dashboard summary block. Lives
    here rather than in aml_service.py so the Dashboard and the SLA
    Report draw from the same reporting layer instead of two parallel
    implementations of 'what counts as open' drifting apart over time."""
    conn.row_factory = sqlite3.Row
    row = conn.execute("""
        SELECT alert_id, scenario_code, severity, account_id, status, created_at, case_id
        FROM aml_alerts
        WHERE status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED') AND company_id = ?
        ORDER BY created_at ASC
        LIMIT 1
    """, (company_id,)).fetchone()
    return dict(row) if row else None


def build_sla_report(conn: sqlite3.Connection, company_id: str) -> dict:
    """Assembles every metric into one dict for the /reports route to render
    or return as JSON. This is the single function aml_service.get_sla_report()
    delegates to."""
    conn.row_factory = sqlite3.Row
    return {
        "summary": alert_volume_summary(conn, company_id),
        "avg_time_to_review_days": avg_time_to_review_days(conn, company_id),
        "avg_time_to_close_days": avg_time_to_close_days(conn, company_id),
        "alerts_by_scenario": [dict(r) for r in alerts_by_scenario(conn, company_id)],
        "false_positive_rate_pct": false_positive_rate(conn, company_id),
        "sar_rate_pct": sar_rate(conn, company_id),
        "oldest_open_alert": oldest_open_alert(conn, company_id),
    }


def build_dashboard_summary(conn: sqlite3.Connection, company_id: str) -> dict:
    """Lightweight subset of build_sla_report(), for the Dashboard landing
    page: status counts + oldest open alert only — no scenario breakdown,
    no avg-time/false-positive/SAR-rate metrics, since those are reporting
    detail that belongs on the full /reports page, not a glance-and-go
    summary. Reuses the exact same underlying queries as the SLA report so
    the two pages can never silently disagree on what 'X alerts open'
    means."""
    conn.row_factory = sqlite3.Row
    return {
        "summary": alert_volume_summary(conn, company_id),
        "oldest_open_alert": oldest_open_alert(conn, company_id),
    }
