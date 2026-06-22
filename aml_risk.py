"""
aml_risk.py — Weighted Risk Scoring Engine
-------------------------------------------
Read-only scoring layer that sits alongside the rule-based scenarios in
aml_engine.py. It does NOT replace the threshold rules — FATF-aligned
monitoring still needs deterministic, auditable triggers ("this account
crossed AED 55,000 in 6 months" must always fire, full stop, or you have
a regulatory gap). What this module adds is a *risk score* layered on top,
used for two things:

    1. Dynamic severity: scenarios that already fire (cash agg, structuring,
       high-risk jurisdiction, behaviour change) can use the score to set
       severity instead of a single hardcoded amount cutoff, so a HIGH-risk
       PEP tripping a MEDIUM-typology rule still surfaces as urgent.
    2. Prioritisation: feeds case_priority_score so the queue can be sorted
       by something more informative than created_at.

This module performs NO writes to aml_alerts or str_decisions — exactly
like alert_filter.py and aml_reports.py, scoring is advisory input to
raise_alert(), not a workflow decision. Only AMLWorkflowManager writes
alert/decision state.

Score components (0-100 each, weighted, summed, capped at 100):

    velocity_score       — transaction count/volume acceleration vs. the
                            account's own recent history (not a fixed
                            multiple like SCN_BEHAVIOUR_CHANGE; this is a
                            continuous score so two accounts both "above
                            the 3x line" can still be told apart)
    jurisdiction_score    — destination/origin country risk, tiered rather
                            than binary in/out of HIGH_RISK_JURISDICTIONS
    structuring_score     — proximity to the just-below-threshold band,
                            scaled by clustering (closer to the ceiling +
                            more transactions = higher)
    segment_score         — customer_type / risk_rating / is_pep baseline,
                            since the same transaction means more risk on
                            a flagged PEP than an established retail client

Weights are configurable constants below, not hardcoded inline, so they
can be tuned/retrained against real disposition outcomes later (see
feedback-loop note at the bottom of this file).
"""
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

# ── Weights (must sum to 1.0) ─────────────────────────────────────────────
WEIGHT_VELOCITY      = 0.30
WEIGHT_JURISDICTION   = 0.30
WEIGHT_STRUCTURING    = 0.25
WEIGHT_SEGMENT        = 0.15

assert abs((WEIGHT_VELOCITY + WEIGHT_JURISDICTION + WEIGHT_STRUCTURING + WEIGHT_SEGMENT) - 1.0) < 1e-9

# ── Jurisdiction risk tiers (finer-grained than the binary HIGH_RISK set
# aml_engine.py uses for trigger purposes — this is scoring input only,
# it does NOT change which transactions trigger SCN_HIGH_RISK_JURISDICTION) ──
JURISDICTION_TIER_SCORES = {
    # FATF black list / DPRK-style sanctions-adjacent — maximum score
    "KP": 100, "IR": 100, "SY": 95, "CU": 90,
    # FATF grey list / increased monitoring
    "MM": 80, "YE": 80, "AF": 80, "HT": 75, "PK": 75, "PA": 70, "PH": 70,
    "VE": 75, "SS": 80, "LB": 70, "CD": 70,
    # Elevated but not listed — common typology corridors
    "VG": 55, "MC": 45, "KW": 35,
}
DEFAULT_JURISDICTION_SCORE = 10  # NORMAL-list countries not otherwise scored

# ── Segment baseline scores ───────────────────────────────────────────────
RISK_RATING_SCORE = {"HIGH": 80, "MEDIUM": 40, "LOW": 15}
PEP_SCORE_BONUS = 20
CUSTOMER_TYPE_SCORE = {"HIGH_RISK": 70, "BUSINESS": 35, "INDIVIDUAL": 20, "RETAIL": 20}

VELOCITY_LOOKBACK_DAYS = 90
VELOCITY_RECENT_DAYS = 14

STRUCTURING_BAND_LOW = 8_500
STRUCTURING_BAND_HIGH = 9_999


@dataclass
class RiskScoreBreakdown:
    account_id: str
    velocity_score: float
    jurisdiction_score: float
    structuring_score: float
    segment_score: float
    composite_score: float
    risk_tier: str            # LOW / MEDIUM / HIGH
    computed_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def _tier_from_score(score: float) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def _velocity_score(conn: sqlite3.Connection, account_id: str, as_of_date: str) -> float:
    """Compares recent transaction velocity (count + volume, last 14 days)
    against the account's own 90-day baseline rate. Returns a 0-100 score
    via a smooth ratio curve rather than a single trigger multiple, so an
    account at 2.5x baseline and one at 6x baseline don't score identically
    the way a flat 3x cutoff would treat them."""
    row = conn.execute("""
        WITH recent AS (
            SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS vol
            FROM transactions
            WHERE account_id = :acct
              AND date(transaction_date) BETWEEN date(:as_of, :recent_start) AND date(:as_of)
        ),
        baseline AS (
            SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS vol
            FROM transactions
            WHERE account_id = :acct
              AND date(transaction_date) BETWEEN date(:as_of, :baseline_start) AND date(:as_of, :recent_start)
        )
        SELECT recent.cnt, recent.vol, baseline.cnt, baseline.vol
        FROM recent, baseline
    """, {
        "acct": account_id,
        "as_of": as_of_date,
        "recent_start": f"-{VELOCITY_RECENT_DAYS} days",
        "baseline_start": f"-{VELOCITY_LOOKBACK_DAYS} days",
    }).fetchone()

    recent_cnt, recent_vol, base_cnt, base_vol = row
    if not recent_cnt:
        return 0.0

    # Normalise baseline to the same 14-day window length for a fair ratio
    baseline_window_days = max(VELOCITY_LOOKBACK_DAYS - VELOCITY_RECENT_DAYS, 1)
    base_vol_per_period = (base_vol / baseline_window_days) * VELOCITY_RECENT_DAYS if base_vol else 0.0

    if base_vol_per_period <= 0:
        # No real baseline to compare against (new/dormant account suddenly
        # active) — scale on absolute recent volume instead, capped.
        return min(100.0, (recent_vol / 50_000) * 100)

    ratio = recent_vol / base_vol_per_period
    # Smooth curve: 1x baseline -> ~0, 3x -> ~50, 6x+ -> 100
    return max(0.0, min(100.0, (ratio - 1.0) * 20.0))


def _jurisdiction_score(conn: sqlite3.Connection, account_id: str, as_of_date: str, lookback_days: int = 365) -> float:
    """Highest jurisdiction-tier score among the account's transactions in
    the lookback window. Uses MAX rather than an average so a single
    transaction to a black-listed jurisdiction can't be diluted by a long
    history of clean domestic activity.

    Default window is 365 days, not a shorter "recent activity" window —
    deliberately. A single AED 400k transfer to a FATF black-list
    jurisdiction 7 months ago is still material to an account's risk
    profile today; the velocity/structuring components already cover
    *recent* behaviour, so jurisdiction exposure is intentionally the
    longest-memory component of the four. (An earlier 180-day default was
    found during testing to silently drop real high-risk exposure out of
    the score once `as_of_date` moved past that window — see
    scoring_accuracy_summary() for how to spot this kind of gap from
    real outcome data instead of by inspection.)
    """
    rows = conn.execute("""
        SELECT DISTINCT country FROM transactions
        WHERE account_id = ? AND date(transaction_date) BETWEEN date(?, ?) AND date(?)
    """, (account_id, as_of_date, f"-{lookback_days} days", as_of_date)).fetchall()

    if not rows:
        return 0.0
    return max(JURISDICTION_TIER_SCORES.get(c, DEFAULT_JURISDICTION_SCORE) for (c,) in rows)


def _structuring_score(conn: sqlite3.Connection, account_id: str, as_of_date: str, window_days: int = 30) -> float:
    """Scores proximity to the just-below-threshold structuring band,
    scaled by transaction count in that band. A single AED 8,600 transaction
    scores low; three AED 9,900 transactions in 30 days scores high — this
    is deliberately a continuous precursor signal to SCN_STRUCTURING_CASH's
    hard 3-transaction trigger, useful for accounts at 1-2 transactions that
    don't yet meet the rule but are trending toward it."""
    row = conn.execute("""
        SELECT COUNT(*), COALESCE(AVG(amount), 0), COALESCE(MAX(amount), 0)
        FROM transactions
        WHERE account_id = ?
          AND amount BETWEEN ? AND ?
          AND date(transaction_date) BETWEEN date(?, ?) AND date(?)
    """, (account_id, STRUCTURING_BAND_LOW, STRUCTURING_BAND_HIGH,
          as_of_date, f"-{window_days} days", as_of_date)).fetchone()

    count, avg_amt, max_amt = row
    if not count:
        return 0.0

    # Proximity component: how close to the AED 9,999 ceiling (0 at 8,500, 100 at 9,999)
    band_width = STRUCTURING_BAND_HIGH - STRUCTURING_BAND_LOW
    proximity = ((max_amt - STRUCTURING_BAND_LOW) / band_width) * 100 if band_width else 0.0

    # Clustering component: count of 1 -> low weight, 3+ -> full weight
    clustering = min(count / 3.0, 1.0) * 100

    return max(0.0, min(100.0, (proximity * 0.4) + (clustering * 0.6)))


def _segment_score(conn: sqlite3.Connection, account_id: str) -> float:
    """Static customer-segment baseline: risk_rating + PEP flag + customer_type.
    Unlike the other three components this doesn't look at transaction
    behaviour at all — it reflects who the customer is on file, which is
    why it carries the lowest weight (15%) of the four: KYC risk rating
    alone shouldn't dominate a transaction-monitoring score, but it should
    nudge it."""
    row = conn.execute("""
        SELECT risk_rating, is_pep, customer_type FROM customer_profiles
        WHERE account_id = ?
    """, (account_id,)).fetchone()

    if row is None:
        return RISK_RATING_SCORE["MEDIUM"]  # unknown customer = treat as medium, not zero

    risk_rating, is_pep, customer_type = row
    score = RISK_RATING_SCORE.get(risk_rating, RISK_RATING_SCORE["MEDIUM"])
    score = max(score, CUSTOMER_TYPE_SCORE.get(customer_type, 0))
    if is_pep:
        score = min(100.0, score + PEP_SCORE_BONUS)
    return float(score)


def compute_risk_score(conn: sqlite3.Connection, account_id: str, as_of_date: Optional[str] = None) -> RiskScoreBreakdown:
    """Computes the full weighted composite score for one account. Pure
    read — callers decide whether/how to persist it (see persist_risk_score)."""
    as_of = as_of_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    velocity = _velocity_score(conn, account_id, as_of)
    jurisdiction = _jurisdiction_score(conn, account_id, as_of)
    structuring = _structuring_score(conn, account_id, as_of)
    segment = _segment_score(conn, account_id)

    composite = (
        velocity * WEIGHT_VELOCITY
        + jurisdiction * WEIGHT_JURISDICTION
        + structuring * WEIGHT_STRUCTURING
        + segment * WEIGHT_SEGMENT
    )
    composite = round(min(100.0, composite), 2)

    return RiskScoreBreakdown(
        account_id=account_id,
        velocity_score=round(velocity, 2),
        jurisdiction_score=round(jurisdiction, 2),
        structuring_score=round(structuring, 2),
        segment_score=round(segment, 2),
        composite_score=composite,
        risk_tier=_tier_from_score(composite),
        computed_at=datetime.now(timezone.utc).isoformat(),
    )


def severity_from_score(score: float, floor_severity: str = "LOW") -> str:
    """Maps a composite score to an alert severity, with a floor so a
    scenario's own minimum severity (e.g. SCN_STRUCTURING_CASH's MEDIUM)
    is never *downgraded* by a low score — the score can only escalate
    severity above what the rule itself already implies, never suppress it.
    This keeps the deterministic rule layer authoritative for "should this
    fire at all", while letting the score sharpen "how urgent is it"."""
    order = ["LOW", "MEDIUM", "HIGH"]
    tier = _tier_from_score(score)
    floor_idx = order.index(floor_severity) if floor_severity in order else 0
    tier_idx = order.index(tier)
    return order[max(floor_idx, tier_idx)]


def persist_risk_score(conn: sqlite3.Connection, breakdown: RiskScoreBreakdown) -> None:
    """Writes a risk_scores row. This table is an append-only history (one
    row per computation), not an upsert-in-place table — see SCHEMA_ADDITIONS
    in aml_engine.py for why: it's the input data for the future feedback
    loop (Section 5 of the roadmap) that compares scores-at-alert-time
    against eventual analyst dispositions."""
    conn.execute("""
        INSERT INTO risk_scores
            (account_id, velocity_score, jurisdiction_score, structuring_score,
             segment_score, composite_score, risk_tier, computed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        breakdown.account_id, breakdown.velocity_score, breakdown.jurisdiction_score,
        breakdown.structuring_score, breakdown.segment_score, breakdown.composite_score,
        breakdown.risk_tier, breakdown.computed_at,
    ))


# ── Feedback-loop hook (read-only summary, not an auto-tuner) ────────────
def scoring_accuracy_summary(conn: sqlite3.Connection) -> dict:
    """Compares the composite_score recorded at alert-creation time against
    the eventual closure outcome, as a first step toward threshold tuning.
    This does NOT change any weights automatically — it surfaces the data
    (e.g. 'alerts scored CRITICAL that closed FALSE_POSITIVE: 4') so a human
    can decide whether WEIGHT_* constants or JURISDICTION_TIER_SCORES need
    adjusting. Auto-tuning weights from outcomes is a meaningful modelling
    decision (risk of feedback loops suppressing real risk) and is
    deliberately left as a human-in-the-loop step, not automated here.
    """
    rows = conn.execute("""
        WITH latest_decisions AS (
            SELECT sd.* FROM str_decisions sd
            INNER JOIN (
                SELECT alert_id, MAX(decision_id) AS max_id FROM str_decisions GROUP BY alert_id
            ) m ON m.alert_id = sd.alert_id AND m.max_id = sd.decision_id
        )
        SELECT a.risk_tier_at_alert, ld.closure_reason_code, COUNT(*) AS n
        FROM aml_alerts a
        JOIN latest_decisions ld ON ld.alert_id = a.alert_id
        WHERE a.risk_tier_at_alert IS NOT NULL AND ld.closure_reason_code IS NOT NULL
        GROUP BY a.risk_tier_at_alert, ld.closure_reason_code
        ORDER BY a.risk_tier_at_alert, n DESC
    """).fetchall()

    summary: dict = {}
    for tier, reason, n in rows:
        summary.setdefault(tier, {})[reason] = n
    return summary