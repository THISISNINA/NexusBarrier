import sqlite3
from typing import Optional, Sequence

DEFAULT_SUPPRESSION_WINDOW_DAYS = 30
DEFAULT_NO_ACTION_REASON_CODES = (
    "FALSE_POSITIVE",
    "LEGITIMATE_BUSINESS",
    "DATA_ERROR",
    "BELOW_REGULATORY_THRESHOLD",
    "MONITORING_ONLY",
)

def is_recently_cleared(
    conn: sqlite3.Connection,
    account_id: str,
    scenario_code: str,
    company_id: str,
    window_days: int = DEFAULT_SUPPRESSION_WINDOW_DAYS,
    closure_reason_codes: Optional[Sequence[str]] = None,
) -> bool:
    """
    Checks the database for the single most recent decision on this account and scenario.
    Returns True only if that latest decision was closed with no action within the allowed day window.

    Scoped by company_id — account_id alone isn't guaranteed unique across
    tenants, so without this a closure at one company could suppress an
    unrelated new alert at another company that just happens to share an
    account_id string.
    """
    params = {
        "account_id": account_id,
        "scenario_code": scenario_code,
        "company_id": company_id,
        "window_days": window_days,
    }

    reason_filter_sql = ""
    if closure_reason_codes:
        placeholders = ", ".join(f":reason_{i}" for i in range(len(closure_reason_codes)))
        reason_filter_sql = f"AND sd.closure_reason_code IN ({placeholders})"
        for i, code in enumerate(closure_reason_codes):
            params[f"reason_{i}"] = code

    row = conn.execute(f"""
        SELECT sd.workflow_status, sd.closure_reason_code, sd.closed_at
        FROM str_decisions sd
        JOIN aml_alerts a ON a.alert_id = sd.alert_id
        WHERE a.account_id = :account_id
          AND a.scenario_code = :scenario_code
          AND a.company_id = :company_id
        ORDER BY sd.decision_id DESC
        LIMIT 1
    """, params).fetchone()

    if row is None:
        return False

    workflow_status, closure_reason_code, closed_at = row

    if workflow_status != "CLOSED_NO_ACTION" or not closed_at:
        return False

    if closure_reason_codes and closure_reason_code not in closure_reason_codes:
        return False

    age_check = conn.execute(
        "SELECT julianday(:now) - julianday(:closed_at) <= :window",
        {"now": _now_iso(), "closed_at": closed_at, "window": window_days},
    ).fetchone()[0]

    return bool(age_check)


def should_suppress(
    conn: sqlite3.Connection,
    account_id: str,
    scenario_code: str,
    company_id: str,
    window_days: int = DEFAULT_SUPPRESSION_WINDOW_DAYS,
    closure_reason_codes: Optional[Sequence[str]] = DEFAULT_NO_ACTION_REASON_CODES,
) -> bool:
    """Checks if a new alert should be skipped because a matching alert was recently closed with no action."""
    return is_recently_cleared(
        conn, account_id, scenario_code, company_id,
        window_days=window_days,
        closure_reason_codes=closure_reason_codes,
    )


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()