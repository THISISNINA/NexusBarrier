import difflib
import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Tuple, Optional, Dict
import alert_filter
import aml_risk
import auth_security
import pii_crypto

# Configuration — paths anchored to this file's location, not the working directory, so a different launch dir can't silently open a second empty database.
_BASE_DIR = Path(__file__).resolve().parent
DB_PATH = _BASE_DIR / "data" / "database" / "aml_monitoring.db"
SCREENING_DB_PATH = _BASE_DIR / "data" / "database" / "screening.db"  # Separate DB — mirrors real-life separation

# Thresholds (AED) — aligned to CBUAE AML/CFT Guidelines and FATF RBA
CASH_AGG_6M_THRESHOLD = 55_000

# Cash-channel discrimination: which transaction_type values count as physical currency for the cash-exclusive rules; NULL (untyped/legacy) is fail-safe cash-eligible, and only positively-non-cash rows are excluded.
CASH_TRANSACTION_TYPES = ("CASH_DEPOSIT", "CASH_WITHDRAWAL")
CASH_TYPE_SQL_PREDICATE = (
    "(transaction_type IS NULL OR transaction_type IN ('CASH_DEPOSIT', 'CASH_WITHDRAWAL'))"
)

# Expected-volume-aware SCN_CASH_AGG_6M: effective = MAX(flat 55k, MIN(EMV*6*RATIO, CEILING)) * risk-tier multiplier, so a customer's own declared volume avoids guaranteed false positives; RATIO/CEILING are institutional calibration, not statutory.
CASH_AGG_WINDOW_MONTHS = 6
CASH_AGG_EXPECTED_VOLUME_RATIO = 0.5
CASH_AGG_EXPECTED_VOLUME_CEILING = 500_000

STRUCTURING_WINDOW_DAYS = 30
STRUCTURING_TX_COUNT = 3
STRUCTURING_BAND_LOW = 8_500
STRUCTURING_BAND_HIGH = 9_999
HIGH_RISK_STANDARD_LIMIT = 10_000
HIGH_RISK_ELEVATED_LIMIT = 5_000
BEHAVIOUR_MULTIPLIER = 3.0
BEHAVIOUR_BASELINE_DAYS = 90
BEHAVIOUR_REVIEW_DAYS = 30
DORMANT_MONTHS = 6
DORMANT_INACTIVITY_DAYS = 180
DORMANT_REACT_MIN_AMOUNT = 15_000
# Weakness fix: a second, relative reactivation path — N-times the account's own pre-dormancy average, even below the flat floor — mirroring SCN_BEHAVIOUR_CHANGE's ratio-vs-own-baseline approach.
DORMANT_REACT_RELATIVE_MULTIPLIER = 3.0
DORMANT_REACT_HISTORY_LOOKBACK_DAYS = 365
RAPID_LAYERING_WINDOW_HRS = 72
RAPID_LAYERING_MIN_LEGS = 3
RAPID_LAYERING_MIN_VOLUME = 20_000
SMURFING_MIN_ACCOUNTS = 3
SMURFING_WINDOW_DAYS = 14
SMURFING_BAND_LOW = 8_500
SMURFING_BAND_HIGH = 9_999
CROSS_BORDER_MIN_COUNTRIES = 4
CROSS_BORDER_WINDOW_DAYS = 30
PEP_SINGLE_TX_THRESHOLD = 50_000
PEP_AGGREGATE_MULTIPLIER = 1.5

# Item 16: SLA business-day limits (weekends only skipped, no holiday calendar)
SLA_L1_BUSINESS_DAYS = 5
SLA_MLRO_BUSINESS_DAYS = 10

# FATF/CBUAE High-Risk Jurisdictions
HIGH_RISK_JURISDICTIONS = {
    "IR", "KP", "MM", "SY", "CU", "YE", "LY",
    "AF", "HT", "PK", "PA", "PH",
}

# Typology map: scenario → FATF typology tag
SCENARIO_TYPOLOGY_MAP = {
    "SCN_CASH_AGG_6M":               "CASH_INTENSIVE",
    "SCN_STRUCTURING_CASH":          "STRUCTURING",
    "SCN_HIGH_RISK_JURISDICTION":    "HIGH_RISK_JURISDICTION",
    "SCN_BEHAVIOUR_CHANGE":          "UNUSUAL_BEHAVIOUR",
    "SCN_PEP_EXPOSURE":              "PEP_EXPOSURE",
    "SCN_DORMANT_REACTIVATION":      "DORMANT_REACTIVATION",
    "SCN_RAPID_LAYERING":            "LAYERING",
    "SCN_MULTI_ACCOUNT_STRUCTURING": "SMURFING",
    "SCN_CROSS_BORDER_ANOMALY":      "TRADE_BASED_ML",
    # Screening-match scenarios: screening.db hits routed into the same alert queue/workflow as any scenario (see run_scn_sanction_match / run_scn_pep_match / run_scn_internal_watchlist_match).
    "SCN_SANCTION_MATCH":            "SANCTIONS_MATCH",
    "SCN_PEP_MATCH":                 "PEP_MATCH",
    "SCN_INTERNAL_WATCHLIST":        "INTERNAL_WATCHLIST",
}

# Logging — path anchored like DB_PATH so a different launch dir can't crash at import with a missing logs/ directory.
_LOG_DIR = _BASE_DIR / "logs"
_LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler(_LOG_DIR / "aml_engine.log"), logging.StreamHandler()],
)
log = logging.getLogger(__name__)


# Task 2: per-record robustness counter — raise_alert() swallows a single malformed/transient record failure, bumps this, and returns None so the scenario continues; module-level (not a per-scenario param) since runs are single-threaded and sequential.
_errored_records_count = 0


def _reset_errored_records() -> None:
    global _errored_records_count
    _errored_records_count = 0


def _note_errored_record() -> None:
    global _errored_records_count
    _errored_records_count += 1


def get_errored_records_count() -> int:
    return _errored_records_count


# CUSTOM WORKFLOW EXCEPTIONS
class WorkflowError(Exception):
    """Raised when an invalid state transition or compliance guardrail is breached."""
    pass


# Database bootstrap
SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS aml_scenarios (
    scenario_code TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    typology TEXT NOT NULL,
    threshold_value REAL,
    window_days INTEGER,
    default_severity TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_versions (
    version_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_code TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    threshold_value REAL,
    window_days INTEGER,
    default_severity TEXT NOT NULL,
    parameters_json TEXT,
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    changed_by TEXT NOT NULL,
    change_reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scenario_code) REFERENCES aml_scenarios(scenario_code)
);

CREATE INDEX IF NOT EXISTS idx_rule_versions_scenario ON rule_versions(scenario_code, effective_from);

CREATE TRIGGER IF NOT EXISTS trg_rule_versions_no_delete
BEFORE DELETE ON rule_versions
BEGIN
    SELECT RAISE(ABORT, 'rule_versions is an append-only ledger: DELETE is not permitted.');
END;

CREATE TRIGGER IF NOT EXISTS trg_rule_versions_restrict_update
BEFORE UPDATE OF version_id, scenario_code, version_number, threshold_value, window_days,
    default_severity, parameters_json, effective_from, changed_by, change_reason, created_at
ON rule_versions
BEGIN
    SELECT RAISE(ABORT, 'rule_versions: only effective_to may be updated (to close out a superseded version).');
END;

CREATE TABLE IF NOT EXISTS aml_alerts (
    alert_id TEXT PRIMARY KEY,
    scenario_code TEXT NOT NULL,
    account_id TEXT NOT NULL,
    trigger_value REAL NOT NULL,
    detection_period_start TEXT NOT NULL,
    detection_period_end TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    narrative TEXT,
    created_at TEXT NOT NULL,
    typology TEXT,
    FOREIGN KEY (scenario_code) REFERENCES aml_scenarios(scenario_code)
);

-- GAP 2: ANALYST WORKFLOW & AUDIT TRAIL LAYER
CREATE TABLE IF NOT EXISTS str_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    analyst_id TEXT NOT NULL,
    workflow_status TEXT NOT NULL,
    risk_justification_narrative TEXT,
    mlro_rationale TEXT,           -- IMPROVEMENT 1: separate MLRO independent assessment
    closure_reason_code TEXT,
    goaml_reference_number TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    FOREIGN KEY (alert_id) REFERENCES aml_alerts(alert_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS aml_alert_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES aml_alerts(alert_id),
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
);

-- GAP 5: CASE MANAGEMENT LAYER
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_alert_map (
    case_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (case_id, alert_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (alert_id) REFERENCES aml_alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_case_alert_map_alert ON case_alert_map(alert_id);
CREATE INDEX IF NOT EXISTS idx_cases_account ON cases(account_id, status);

CREATE TABLE IF NOT EXISTS aml_alert_views (
    view_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    analyst_id TEXT NOT NULL,
    analyst_role TEXT,
    viewed_at TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES aml_alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_views_alert ON aml_alert_views(alert_id, viewed_at);

CREATE TRIGGER IF NOT EXISTS trg_alert_views_no_update
BEFORE UPDATE ON aml_alert_views
BEGIN
    SELECT RAISE(ABORT, 'aml_alert_views is append-only: UPDATE is not permitted.');
END;

CREATE TRIGGER IF NOT EXISTS trg_alert_views_no_delete
BEFORE DELETE ON aml_alert_views
BEGIN
    SELECT RAISE(ABORT, 'aml_alert_views is append-only: DELETE is not permitted.');
END;

CREATE TABLE IF NOT EXISTS risk_scores (
    score_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    velocity_score REAL NOT NULL,
    jurisdiction_score REAL NOT NULL,
    structuring_score REAL NOT NULL,
    segment_score REAL NOT NULL,
    composite_score REAL NOT NULL,
    risk_tier TEXT NOT NULL,
    computed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_account ON risk_scores(account_id, computed_at);

CREATE TRIGGER IF NOT EXISTS trg_risk_scores_no_update
BEFORE UPDATE ON risk_scores
BEGIN
    SELECT RAISE(ABORT, 'risk_scores is append-only history: UPDATE is not permitted.');
END;

CREATE TRIGGER IF NOT EXISTS trg_risk_scores_no_delete
BEFORE DELETE ON risk_scores
BEGIN
    SELECT RAISE(ABORT, 'risk_scores is append-only history: DELETE is not permitted.');
END;

-- NOTE: sanctions_list and pep_list now live in screening.db (separate database).
-- This table is kept for backwards compatibility only and will be empty.
-- All screening now goes through _get_screening_conn().
CREATE TABLE IF NOT EXISTS sanctions_list (
    entity_id TEXT PRIMARY KEY,
    entity_name TEXT NOT NULL,
    entity_name_normalized TEXT NOT NULL,
    list_source TEXT NOT NULL,
    account_id_hint TEXT,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS aml_engine_runs (
    run_id TEXT PRIMARY KEY,
    run_at TEXT NOT NULL,
    scenarios_executed TEXT NOT NULL,
    alerts_generated INTEGER NOT NULL,
    alerts_suppressed INTEGER NOT NULL,
    status TEXT NOT NULL
);

-- Item 5: Mandatory Currency Transaction Reports. Deliberately separate
-- from aml_alerts — a CTR is auto-filed on crossing a fixed threshold,
-- not investigated/adjudicated, so it has no workflow_status, no
-- analyst decision, nothing to "close". Append-only for the same audit
-- reason as str_decisions/risk_scores: a mandatory regulatory filing
-- record should never be editable or deletable after the fact.
CREATE TABLE IF NOT EXISTS ctr_filings (
    ctr_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    filing_date TEXT NOT NULL,
    total_amount REAL NOT NULL,
    transaction_count INTEGER NOT NULL,
    transaction_ids TEXT,
    threshold_applied REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ctr_filings_account ON ctr_filings(account_id, filing_date);

CREATE TRIGGER IF NOT EXISTS trg_ctr_filings_no_update
BEFORE UPDATE ON ctr_filings
BEGIN
    SELECT RAISE(ABORT, 'ctr_filings is an append-only mandatory-reporting record: UPDATE is not permitted.');
END;

CREATE TRIGGER IF NOT EXISTS trg_ctr_filings_no_delete
BEFORE DELETE ON ctr_filings
BEGIN
    SELECT RAISE(ABORT, 'ctr_filings is an append-only mandatory-reporting record: DELETE is not permitted.');
END;

-- RBA Customer Layer
CREATE TABLE IF NOT EXISTS customer_profiles (
    account_id TEXT PRIMARY KEY,
    customer_name TEXT NOT NULL,
    customer_type TEXT NOT NULL DEFAULT 'INDIVIDUAL',
    account_category TEXT NOT NULL DEFAULT 'RETAIL',   -- RETAIL / CORPORATE / CORRESPONDENT
    risk_rating TEXT NOT NULL DEFAULT 'MEDIUM',
    risk_rating_date TEXT,
    risk_rating_reason TEXT,
    is_pep INTEGER NOT NULL DEFAULT 0,
    expected_monthly_volume REAL NOT NULL DEFAULT 50000.00,
    ubo_names TEXT,       -- pipe-separated UBO names for CORPORATE accounts
    swift_bic TEXT        -- BIC for CORRESPONDENT accounts
);

CREATE INDEX IF NOT EXISTS idx_alerts_account ON aml_alerts(account_id, status);
CREATE INDEX IF NOT EXISTS idx_str_decisions_alert ON str_decisions(alert_id);
CREATE INDEX IF NOT EXISTS idx_str_decisions_status ON str_decisions(workflow_status);

CREATE TRIGGER IF NOT EXISTS trg_str_decisions_no_update
BEFORE UPDATE ON str_decisions
BEGIN
    SELECT RAISE(ABORT, 'str_decisions is append-only: UPDATE is not permitted. Insert a new decision row instead.');
END;

CREATE TRIGGER IF NOT EXISTS trg_str_decisions_no_delete
BEFORE DELETE ON str_decisions
BEGIN
    SELECT RAISE(ABORT, 'str_decisions is append-only: DELETE is not permitted. The audit trail cannot be erased.');
END;
"""

SCENARIO_SEED = [
    ("SCN_CASH_AGG_6M", f"Cumulative CASH-channel transactions exceed the greater of AED {CASH_AGG_6M_THRESHOLD:,.0f} or {CASH_AGG_EXPECTED_VOLUME_RATIO:.0%} of the customer's own 6-month expected volume, over a rolling 6-month window (scaled by risk tier — see aml_risk.RISK_TIER_THRESHOLD_MULTIPLIER)", "CASH_INTENSIVE", CASH_AGG_6M_THRESHOLD, 180, "MEDIUM"),
    ("SCN_STRUCTURING_CASH", "Repeated cash-channel transactions in the just-below-threshold band (AED 8,500–9,999) within 30 days", "STRUCTURING", STRUCTURING_BAND_HIGH, STRUCTURING_WINDOW_DAYS, "HIGH"),
    ("SCN_HIGH_RISK_JURISDICTION", "Transaction above AED 10,000 whose endpoint OR any intermediary routing hop touches a FATF/CBUAE high-risk jurisdiction", "HIGH_RISK_JURISDICTION", HIGH_RISK_STANDARD_LIMIT, None, "HIGH"),
    ("SCN_BEHAVIOUR_CHANGE", "Current-period transaction volume is 3x or more than the 90-day historical baseline", "UNUSUAL_BEHAVIOUR", BEHAVIOUR_MULTIPLIER, BEHAVIOUR_REVIEW_DAYS, "MEDIUM"),
    ("SCN_PEP_EXPOSURE", "PEP-flagged account exceeds an elevated single-transaction threshold or aggregates 1.5x+ their own expected monthly volume within 30 days", "PEP_EXPOSURE", PEP_SINGLE_TX_THRESHOLD, 30, "HIGH"),
    ("SCN_SANCTION_MATCH", "Account holder, beneficial owner, or wire-message counterparty matches an active sanctions list entry", "SANCTIONS_MATCH", None, None, "HIGH"),
    ("SCN_PEP_MATCH", "Account holder or beneficial owner matches an active politically-exposed-person list entry", "PEP_MATCH", None, None, "MEDIUM"),
    ("SCN_INTERNAL_WATCHLIST", "Account holder or beneficial owner matches the bank's internal watchlist", "INTERNAL_WATCHLIST", None, None, "MEDIUM"),
    ("SCN_DORMANT_REACTIVATION", f"Account silent for {DORMANT_INACTIVITY_DAYS}+ days reactivates with a transaction above AED {DORMANT_REACT_MIN_AMOUNT:,.0f}, OR at {DORMANT_REACT_RELATIVE_MULTIPLIER:.0f}x+ its own pre-dormancy average transaction size", "DORMANT_REACTIVATION", DORMANT_REACT_MIN_AMOUNT, DORMANT_INACTIVITY_DAYS, "MEDIUM"),
    ("SCN_RAPID_LAYERING", f"AED {RAPID_LAYERING_MIN_VOLUME:,.0f}+ moved across {RAPID_LAYERING_MIN_LEGS}+ transactions within {RAPID_LAYERING_WINDOW_HRS} hours", "LAYERING", RAPID_LAYERING_MIN_VOLUME, None, "MEDIUM"),
    ("SCN_MULTI_ACCOUNT_STRUCTURING", f"{SMURFING_MIN_ACCOUNTS}+ distinct accounts transact in the structuring band within {SMURFING_WINDOW_DAYS} days", "SMURFING", SMURFING_BAND_HIGH, SMURFING_WINDOW_DAYS, "HIGH"),
    ("SCN_CROSS_BORDER_ANOMALY", f"Account transacts across {CROSS_BORDER_MIN_COUNTRIES}+ distinct countries within {CROSS_BORDER_WINDOW_DAYS} days", "TRADE_BASED_ML", float(CROSS_BORDER_MIN_COUNTRIES), CROSS_BORDER_WINDOW_DAYS, "MEDIUM"),
]


# Screening DB connection
def _get_screening_conn() -> sqlite3.Connection:
    """Opens a connection to the separate screening.db file.
    This database holds sanctions_list, pep_list, and internal_watchlist —
    kept separate from aml_monitoring.db to mirror the real-world pattern
    where sanctions/PEP data is maintained by an external provider and
    queried (not owned) by the TM system.

    Creates the three tables if they don't exist yet (idempotent —
    CREATE TABLE IF NOT EXISTS is a no-op after the first call). This
    means any code path that reads screening.db works even if
    sanctions_pep_seed.py hasn't been run yet — it'll just see empty
    tables rather than crashing with "no such table". Seeding still
    needs sanctions_pep_seed.py; this only guarantees the schema exists."""
    SCREENING_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SCREENING_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sanctions_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            list_source TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            country TEXT,
            added_date TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS pep_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            pep_category TEXT NOT NULL,
            country TEXT,
            start_date TEXT,
            end_date TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS internal_watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            account_id TEXT,
            watch_reason TEXT NOT NULL,
            added_by TEXT NOT NULL,
            added_date TEXT NOT NULL,
            review_date TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            notes TEXT
        );
    """)
    # internal_watchlist is each bank's own list (unlike global sanctions_list/pep_list) — see _add_column_if_missing for why it needs the additive-migration guard.
    _add_column_if_missing(conn, "internal_watchlist", "company_id", f"TEXT NOT NULL DEFAULT '{auth_security.LEGACY_COMPANY_ID}'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_internal_watchlist_company ON internal_watchlist(company_id)")
    conn.commit()
    return conn


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, ddl_type: str) -> None:
    """SQLite has no ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so additive
    schema changes to existing tables need this guard to stay idempotent."""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")
        log.info("Migrated: added column %s.%s", table, column)


def _apply_additive_migrations(conn: sqlite3.Connection) -> None:
    """All ALTER TABLE statements live here, not in SCHEMA_DDL."""
    _add_column_if_missing(conn, "str_decisions", "analyst_role", "TEXT")
    _add_column_if_missing(conn, "str_decisions", "mlro_rationale", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "risk_score_at_alert", "REAL")
    _add_column_if_missing(conn, "aml_alerts", "risk_tier_at_alert", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "priority_rank", "INTEGER")
    _add_column_if_missing(conn, "aml_alerts", "rule_version_id", "INTEGER")
    _add_column_if_missing(conn, "aml_alerts", "typology", "TEXT")
    _add_column_if_missing(conn, "customer_profiles", "risk_rating_date", "TEXT")
    _add_column_if_missing(conn, "customer_profiles", "risk_rating_reason", "TEXT")
    _add_column_if_missing(conn, "customer_profiles", "account_category", "TEXT DEFAULT 'RETAIL'")
    _add_column_if_missing(conn, "customer_profiles", "ubo_names", "TEXT")
    _add_column_if_missing(conn, "customer_profiles", "swift_bic", "TEXT")
    # Item 10: case linkage directly on aml_alerts
    _add_column_if_missing(conn, "aml_alerts", "case_id", "TEXT")
    # Item 13: DRAFT_SAR support — when the draft was created and by whom
    _add_column_if_missing(conn, "str_decisions", "draft_sar_created_at", "TEXT")
    # Item 15: EDD flag on customer
    _add_column_if_missing(conn, "customer_profiles", "edd_required", "INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "customer_profiles", "edd_reason", "TEXT")
    # Expanded KYC identity schema (inputs to kyc_risk); must agree with _rebuild_customer_profiles_with_composite_pk's CREATE TABLE, which copies every column by name.
    _add_column_if_missing(conn, "customer_profiles", "nationality", "TEXT")
    _add_column_if_missing(conn, "customer_profiles", "country_of_residence", "TEXT")
    _add_column_if_missing(conn, "customer_profiles", "date_of_birth", "TEXT")
    # Item 16: SLA tracking on alerts
    _add_column_if_missing(conn, "aml_alerts", "sla_due_date", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "sla_breached", "INTEGER DEFAULT 0")
    # Item 12: wire/counterparty fields live on transactions (see aml_loader.py); the cases table gets a narrative for item 10.
    _add_column_if_missing(conn, "cases", "case_narrative", "TEXT")
    # Screening-match scenarios: structured hit details so alert_detail.html can render the matched target without parsing the narrative.
    _add_column_if_missing(conn, "aml_alerts", "screening_match_name", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "screening_match_source", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "screening_match_field", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "screening_match_type", "TEXT")
    _add_column_if_missing(conn, "aml_alerts", "screening_match_score", "REAL")

    # Item 2: add interdiction columns that submit_wire_transfer() writes; transactions is owned by aml_loader.init_db(), so this one guards on the table existing first (brand-new DBs haven't ingested yet).
    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='transactions'"
    ).fetchone():
        _add_column_if_missing(conn, "transactions", "interdiction_status", "TEXT")
        _add_column_if_missing(conn, "transactions", "interdicted_at", "TEXT")
        # Channel/virtual-asset/routing metadata (canonical comments in aml_loader.py), added here too so init_schema before the next ingestion doesn't hit "no such column: transaction_type".
        _add_column_if_missing(conn, "transactions", "transaction_type", "TEXT")
        _add_column_if_missing(conn, "transactions", "counterparty_type", "TEXT")
        _add_column_if_missing(conn, "transactions", "counterparty_wallet_address", "TEXT")
        _add_column_if_missing(conn, "transactions", "intermediary_countries", "TEXT")
        _add_column_if_missing(conn, "transactions", "company_id", f"TEXT NOT NULL DEFAULT '{auth_security.LEGACY_COMPANY_ID}'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_transactions_company ON transactions(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_priority ON aml_alerts(status, priority_rank)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_case ON aml_alerts(case_id)")

    # Multi-tenant retrofit: company_id on every per-company table (aml_scenarios/rule_versions and sanctions_list/pep_list stay global), backfilling pre-migration rows onto LEGACY_COMPANY_ID.
    _legacy = auth_security.LEGACY_COMPANY_ID
    _add_column_if_missing(conn, "aml_alerts", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "str_decisions", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "cases", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "case_alert_map", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "aml_alert_views", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "risk_scores", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "ctr_filings", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "customer_profiles", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")
    _add_column_if_missing(conn, "aml_engine_runs", "company_id", f"TEXT NOT NULL DEFAULT '{_legacy}'")

    # Task 1 (four-eyes): audit flag for a sole-MLRO self-attested close; a dedicated column so a regulator can pull it cleanly, defaulting 0 for normal dual-controlled decisions.
    _add_column_if_missing(conn, "str_decisions", "self_reviewed", "INTEGER NOT NULL DEFAULT 0")

    # Task 2 (robustness): per-run count of skipped records that threw during alert-raising/scoring; >0 marks a PARTIAL pass, surfaced on the dashboard.
    _add_column_if_missing(conn, "aml_engine_runs", "errored_records_count", "INTEGER NOT NULL DEFAULT 0")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_company ON aml_alerts(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_str_decisions_company ON str_decisions(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_company ON cases(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_case_alert_map_company ON case_alert_map(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_views_company ON aml_alert_views(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_scores_company ON risk_scores(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctr_filings_company ON ctr_filings(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_customer_profiles_company ON customer_profiles(company_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_engine_runs_company ON aml_engine_runs(company_id)")
    conn.commit()

    _rebuild_customer_profiles_with_composite_pk(conn)


def _rebuild_customer_profiles_with_composite_pk(conn: sqlite3.Connection) -> None:
    """customer_profiles originally had `account_id TEXT PRIMARY KEY` — a
    single-column key. generator.py deterministically produces the same
    account_id set (see _account_number / build_customer_profiles) for
    every company, so a second company's profile rows would collide with
    the first's under that key instead of coexisting alongside them.

    SQLite has no ALTER TABLE for changing a PRIMARY KEY, so this rebuilds
    the table with PRIMARY KEY (company_id, account_id) the same way any
    other structural SQLite migration does: rename, recreate, copy, drop.
    Must run after the company_id column above already exists on every
    row (so the copy has real values to build the composite key from) —
    idempotent, skips once already rebuilt."""
    pk_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(customer_profiles)").fetchall()
        if row[5] > 0  # row[5] is the PK ordinal position; 0 means "not part of the PK"
    }
    if pk_columns == {"company_id", "account_id"}:
        return

    old_cols = [row[1] for row in conn.execute("PRAGMA table_info(customer_profiles)").fetchall()]
    conn.execute("ALTER TABLE customer_profiles RENAME TO customer_profiles_old_pk")
    conn.execute("""
        CREATE TABLE customer_profiles (
            account_id TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            customer_type TEXT NOT NULL DEFAULT 'INDIVIDUAL',
            account_category TEXT NOT NULL DEFAULT 'RETAIL',
            risk_rating TEXT NOT NULL DEFAULT 'MEDIUM',
            risk_rating_date TEXT,
            risk_rating_reason TEXT,
            is_pep INTEGER NOT NULL DEFAULT 0,
            expected_monthly_volume REAL NOT NULL DEFAULT 50000.00,
            ubo_names TEXT,
            swift_bic TEXT,
            edd_required INTEGER DEFAULT 0,
            edd_reason TEXT,
            nationality TEXT,
            country_of_residence TEXT,
            date_of_birth TEXT,
            company_id TEXT NOT NULL,
            PRIMARY KEY (company_id, account_id)
        )
    """)
    col_list = ", ".join(old_cols)
    conn.execute(f"INSERT INTO customer_profiles ({col_list}) SELECT {col_list} FROM customer_profiles_old_pk")
    conn.execute("DROP TABLE customer_profiles_old_pk")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_customer_profiles_company ON customer_profiles(company_id)")
    conn.commit()
    log.info("Migrated customer_profiles to composite PRIMARY KEY (company_id, account_id).")


def _seed_initial_rule_versions(conn: sqlite3.Connection) -> None:
    """Seeds version 1 of every scenario into rule_versions on first run only."""
    now = datetime.now(timezone.utc).isoformat()
    for code, desc, typo, thresh, window, sev in SCENARIO_SEED:
        conn.execute("""
            INSERT OR IGNORE INTO aml_scenarios
            (scenario_code, description, typology, threshold_value, window_days, default_severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (code, desc, typo, thresh, window, sev, now))
        has_version = conn.execute(
            "SELECT 1 FROM rule_versions WHERE scenario_code = ? LIMIT 1", (code,)
        ).fetchone()
        if has_version:
            continue
        conn.execute("""
            INSERT INTO rule_versions
            (scenario_code, version_number, threshold_value, window_days, default_severity,
             parameters_json, effective_from, effective_to, changed_by, change_reason, created_at)
            VALUES (?, 1, ?, ?, ?, NULL, ?, NULL, 'SYSTEM', 'Initial rule version, seeded at first deployment.', ?)
        """, (code, thresh, window, sev, now, now))
    conn.commit()


def get_active_rule_version(conn: sqlite3.Connection, scenario_code: str, as_of_date: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Returns the rule version active on as_of_date (defaults to now)."""
    as_of = as_of_date or datetime.now(timezone.utc).isoformat()
    conn.row_factory = sqlite3.Row
    row = conn.execute("""
        SELECT * FROM rule_versions
        WHERE scenario_code = ?
          AND effective_from <= ?
          AND (effective_to IS NULL OR effective_to > ?)
        ORDER BY version_number DESC LIMIT 1
    """, (scenario_code, as_of, as_of)).fetchone()
    return dict(row) if row else None


def publish_rule_version(
    conn: sqlite3.Connection, scenario_code: str, changed_by: str, change_reason: str,
    threshold_value: Optional[float] = None, window_days: Optional[int] = None,
    default_severity: Optional[str] = None, parameters: Optional[dict] = None,
) -> int:
    """The ONLY supported way to change a scenario threshold/window/severity.
    Closes the current version and inserts a new one. Returns new version_id."""
    current = get_active_rule_version(conn, scenario_code)
    if current is None:
        raise ValueError(f"No active rule version found for scenario_code={scenario_code!r}")
    if not change_reason or not change_reason.strip():
        raise ValueError("change_reason is required to publish a new rule version.")
    now = datetime.now(timezone.utc).isoformat()
    new_threshold = threshold_value if threshold_value is not None else current["threshold_value"]
    new_window = window_days if window_days is not None else current["window_days"]
    new_severity = default_severity if default_severity is not None else current["default_severity"]
    new_params_json = json.dumps(parameters) if parameters is not None else current["parameters_json"]
    conn.execute(
        "UPDATE rule_versions SET effective_to = ? WHERE version_id = ?",
        (now, current["version_id"]),
    )
    new_version_number = current["version_number"] + 1
    cur = conn.execute("""
        INSERT INTO rule_versions
        (scenario_code, version_number, threshold_value, window_days, default_severity,
         parameters_json, effective_from, effective_to, changed_by, change_reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
    """, (scenario_code, new_version_number, new_threshold, new_window, new_severity,
          new_params_json, now, changed_by, change_reason, now))
    new_version_id = cur.lastrowid
    conn.execute("""
        UPDATE aml_scenarios SET threshold_value = ?, window_days = ?, default_severity = ?
        WHERE scenario_code = ?
    """, (new_threshold, new_window, new_severity, scenario_code))
    conn.commit()
    log.info("Rule version published: %s v%d by %s — %s", scenario_code, new_version_number, changed_by, change_reason)
    return new_version_id


def rule_version_history(conn: sqlite3.Connection, scenario_code: str) -> list[dict]:
    """Full version history for one scenario, most recent first."""
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM rule_versions WHERE scenario_code = ? ORDER BY version_number DESC", (scenario_code,)
    ).fetchall()
    return [dict(r) for r in rows]


def init_schema(conn: sqlite3.Connection) -> None:
    # Creates companies/users (and their auth tables) before the additive migrations backfill company_id onto LEGACY_COMPANY_ID, which must already be a real companies row.
    auth_security.ensure_auth_schema(conn)
    conn.executescript(SCHEMA_DDL)
    _apply_additive_migrations(conn)
    _seed_initial_rule_versions(conn)
    log.info("Schema and scenario registry initialised.")
    # Item 3: customer_profiles is now owned by generator.py — this is a near-no-op that only backfills placeholder profiles for transactions loaded without ever running generator.py.
    seed_profiles_from_existing_data(conn)
    seed_sanctions_list(conn)


# WORKFLOW STATE MACHINE ENGINE
class AMLWorkflowManager:
    """Manages the lifecycle, audit logs, and state transitions of alerts."""

    # Item 13: DRAFT_SAR inserted between ESCALATED and CLOSED_SAR; both steps are MLRO-only, gated by the extended "only MLRO may act on ESCALATED" guard.
    VALID_TRANSITIONS = {
        'OPEN':             ['UNDER_REVIEW'],
        'UNDER_REVIEW':     ['ESCALATED', 'CLOSED_SAR', 'CLOSED_NO_ACTION'],
        'ESCALATED':        ['UNDER_REVIEW', 'DRAFT_SAR', 'CLOSED_SAR', 'CLOSED_NO_ACTION'],
        'DRAFT_SAR':        ['CLOSED_SAR'],
        'CLOSED_SAR':       [],
        'CLOSED_NO_ACTION': [],
    }

    VALID_CLOSURE_CODES = {
        'LEGITIMATE_BUSINESS', 'DATA_ERROR', 'STRUCTURING_CONFIRMED',
        'HIGH_RISK_CONFIRMED', 'FALSE_POSITIVE', 'BELOW_REGULATORY_THRESHOLD', 'MONITORING_ONLY'
    }

    @staticmethod
    def get_latest_decision(conn: sqlite3.Connection, alert_id: str) -> Optional[Dict[str, Any]]:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT workflow_status, reviewed_at, created_at FROM str_decisions
            WHERE alert_id = ? ORDER BY decision_id DESC LIMIT 1
        """, (alert_id,)).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _count_active_mlros(conn: sqlite3.Connection, company_id: str) -> int:
        """How many approved, active MLROs this tenant has — the input to the
        Task 1 dual-control decision. The identity `users` table lives in the
        same aml_monitoring.db as alerts (see auth_security.require_auth's live
        standing check), so it's reachable on this connection. Guarded: if the
        auth schema hasn't been created yet (e.g. an engine-only test DB), we
        can't prove a second MLRO exists, so we return 1 — the conservative
        value that keeps the sole-MLRO attestation path in force rather than
        silently waving a self-close through as if a second reviewer existed."""
        try:
            row = conn.execute(
                """SELECT COUNT(*) FROM users
                   WHERE company_id = ? AND role = 'MLRO'
                     AND status = 'ACTIVE' AND is_approved = 1""",
                (company_id,),
            ).fetchone()
            return int(row[0]) if row else 0
        except sqlite3.OperationalError:
            return 1

    @classmethod
    def transition_alert(
        cls,
        conn: sqlite3.Connection,
        alert_id: str,
        analyst_id: str,
        target_status: str,
        narrative: Optional[str] = None,
        closure_code: Optional[str] = None,
        goaml_ref: Optional[str] = None,
        analyst_role: Optional[str] = None,
        mlro_rationale: Optional[str] = None,
        self_attested: bool = False,
    ) -> None:
        """Enforces workflow constraints, logs changes, and updates aml_alerts.

        `self_attested` (Task 1 — four-eyes): set only by the closing UI when a
        SOLE-MLRO tenant ticks the on-screen self-review attestation to close
        an alert that same MLRO escalated. Ignored on every other path; the
        engine decides whether it is permitted (and required) below."""
        now = datetime.now(timezone.utc).isoformat()
        current_record = cls.get_latest_decision(conn, alert_id)
        # Every str_decisions row carries its alert's company_id, looked up here (not a parameter) since a passed value could only duplicate or contradict the alert's authoritative one.
        alert_company_row = conn.execute(
            "SELECT company_id FROM aml_alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        alert_company_id = alert_company_row[0] if alert_company_row else auth_security.LEGACY_COMPANY_ID

        if not current_record:
            current_status = 'OPEN'
            created_at = now
            reviewed_at = None
        else:
            current_status = current_record['workflow_status']
            created_at = current_record['created_at']
            reviewed_at = current_record['reviewed_at']

        if target_status not in cls.VALID_TRANSITIONS[current_status]:
            raise WorkflowError(f"Compliance Violation: Cannot change state from {current_status} to {target_status}.")

        # Item 13: MLRO-only gate covers ESCALATED and DRAFT_SAR — both are MLRO-owned work.
        if current_status in ('ESCALATED', 'DRAFT_SAR') and analyst_role != 'MLRO':
            raise WorkflowError(
                "Compliance Violation: Only an MLRO may act on an escalated or "
                "draft-SAR alert (return it, draft it, or file it)."
            )

        if target_status == 'CLOSED_SAR' and current_status not in ('ESCALATED', 'DRAFT_SAR'):
            raise WorkflowError(
                "Compliance Violation: A SAR filing (CLOSED_SAR) can only be "
                "confirmed after this alert has been escalated (and, ideally, "
                "drafted) and reviewed by an MLRO."
            )

        if target_status == 'CLOSED_SAR' and current_status == 'DRAFT_SAR' and not goaml_ref:
            raise WorkflowError("Filing Failure: Submitting a drafted SAR requires a goaml_reference_number.")

        # Four-Eyes / Dual Control (Task 1): self_reviewed on the closing str_decisions row is 1 only on the audited sole-MLRO self-close path, else 0.
        self_reviewed = False
        if target_status in ('CLOSED_SAR', 'CLOSED_NO_ACTION') and current_status in ('ESCALATED', 'DRAFT_SAR'):
            # Who escalated this alert (most recent ESCALATED decision)?
            escalation_row = conn.execute("""
                SELECT analyst_id, analyst_role FROM str_decisions
                WHERE alert_id = ? AND workflow_status = 'ESCALATED'
                ORDER BY decision_id DESC LIMIT 1
            """, (alert_id,)).fetchone()
            escalator_id = escalation_row[0] if escalation_row else None
            escalator_role = escalation_row[1] if escalation_row else None

            # No magic-ID backdoor: escalation authority is decided purely by the escalator's recorded role, never a hardcoded identity.
            escalated_by_mlro = escalator_role == 'MLRO'

            if not escalated_by_mlro:
                # Rule 1 (Standard flow): analyst escalated, so any MLRO closes; only need the closer distinct from the escalator.
                if escalator_id is not None and analyst_id == escalator_id:
                    raise WorkflowError(
                        "Compliance Violation (Four-Eyes / Dual Control): the user who "
                        "escalated this alert cannot also close it. A separate MLRO must "
                        "review and close an analyst-escalated alert."
                    )
            else:
                # An MLRO escalated — four-eyes now depends on how many MLROs the tenant has.
                mlro_count = cls._count_active_mlros(conn, alert_company_id)
                closer_is_escalator = escalator_id is not None and analyst_id == escalator_id

                if closer_is_escalator and mlro_count >= 2:
                    # Rule 2 (Dual-MLRO flow): a second distinct MLRO exists and must close it (closer_id != escalator_id).
                    raise WorkflowError(
                        "Compliance Violation (Four-Eyes / Dual Control): you escalated "
                        "this alert and another MLRO is available in this workspace. A "
                        "second, distinct MLRO must review and close it."
                    )
                if closer_is_escalator and mlro_count < 2:
                    # Rule 3 (Sole-MLRO override): the only MLRO may close their own escalation, but only under explicit self-attestation stamped self_reviewed = 1.
                    if not self_attested:
                        raise WorkflowError(
                            "Self-review attestation required: you are the only MLRO in "
                            "this workspace and you escalated this alert. To close it "
                            "yourself you must confirm the self-review attestation; the "
                            "decision will be flagged as self-reviewed for audit."
                        )
                    self_reviewed = True
                    log.warning(
                        "SELF-REVIEWED CLOSURE: sole MLRO %s is closing alert %s that they "
                        "escalated (company_id=%s). Recorded self_reviewed=1 for audit.",
                        analyst_id, alert_id, alert_company_id,
                    )

        if target_status == 'UNDER_REVIEW' and not reviewed_at:
            reviewed_at = now

        if target_status == 'ESCALATED':
            if not narrative or len(narrative.strip()) < 15:
                raise WorkflowError("Audit Failure: A detailed narrative (minimum 15 characters) is required for escalation.")

        closed_at = now if target_status in ['CLOSED_SAR', 'CLOSED_NO_ACTION'] else None

        # Execution of your truncated block logic
        if target_status in ['CLOSED_SAR', 'CLOSED_NO_ACTION']:
            if not narrative or len(narrative.strip()) < 15:
                raise WorkflowError("Audit Failure: Detailed risk_justification_narrative is required for case closure.")
            if not closure_code or closure_code not in cls.VALID_CLOSURE_CODES:
                raise WorkflowError(f"Audit Failure: A valid closure_code is required for case closure. Choose from {cls.VALID_CLOSURE_CODES}.")

        draft_sar_time = now if target_status == 'DRAFT_SAR' else None

        # 1. Write the new state change into the append-only audit trail ledger
        conn.execute("""
            INSERT INTO str_decisions (
                alert_id, analyst_id, workflow_status, risk_justification_narrative,
                mlro_rationale, closure_reason_code, goaml_reference_number,
                analyst_role, draft_sar_created_at, created_at, reviewed_at, updated_at, closed_at,
                company_id, self_reviewed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id, analyst_id, target_status, narrative,
            mlro_rationale, closure_code, goaml_ref,
            analyst_role, draft_sar_time, created_at, reviewed_at, now, closed_at,
            alert_company_id, 1 if self_reviewed else 0,
        ))

        # 2. Synchronize the active working status on the parent alert table
        conn.execute("""
            UPDATE aml_alerts
            SET status = ?
            WHERE alert_id = ?
        """, (target_status, alert_id))

        log.info("Alert %s transitioned from %s to %s by %s (%s)", 
                 alert_id, current_status, target_status, analyst_id, analyst_role or "N/A")

def _resync_case_for_alert(conn: sqlite3.Connection, alert_id: str) -> None:
    """See aml_service.AMLService._resync_case_status — duplicated here
    (rather than imported, to avoid a circular import between aml_engine
    and aml_service) so it fires on every transition_alert() call site,
    not just the ones aml_service happens to wrap with its own resync."""
    status_rank = {"OPEN": 5, "UNDER_REVIEW": 4, "ESCALATED": 3, "DRAFT_SAR": 2,
                    "CLOSED_SAR": 1, "CLOSED_NO_ACTION": 1}
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    case_row = conn.execute("SELECT case_id FROM aml_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not case_row:
        return
    case_id = case_row[0] if not isinstance(case_row, sqlite3.Row) else case_row["case_id"]
    if not case_id:
        return
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT a.status, a.severity FROM case_alert_map cam JOIN aml_alerts a ON a.alert_id = cam.alert_id WHERE cam.case_id = ?",
        (case_id,),
    ).fetchall()
    if not rows:
        return
    best = max(rows, key=lambda r: (status_rank.get(r["status"], 0), severity_rank.get(r["severity"], 0)))
    conn.execute("UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                 (best["status"], datetime.now(timezone.utc).isoformat(), case_id))


def _add_business_days(start_iso: str, n_days: int) -> str:
    """Item 16: adds n business days (Mon-Fri only, no holiday calendar per
    spec) to an ISO timestamp and returns an ISO timestamp."""
    current = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    added = 0
    while added < n_days:
        current += timedelta(days=1)
        if current.weekday() < 5:  # Mon=0 .. Fri=4
            added += 1
    return current.isoformat()


def compute_sla_due_date(created_at_iso: str) -> str:
    """Item 16: initial SLA due date at alert creation — 5 business days
    for the L1 analyst tier."""
    return _add_business_days(created_at_iso, SLA_L1_BUSINESS_DAYS)


def refresh_sla_breach_flags(conn: sqlite3.Connection) -> int:
    """Item 16: marks any still-open alert past its sla_due_date as
    breached. Called opportunistically (dashboard load, alert queue load)
    rather than on a background scheduler, since this is a local demo app
    with no task runner — cheap enough to run on every read."""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("""
        UPDATE aml_alerts
        SET sla_breached = 1
        WHERE status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'DRAFT_SAR')
          AND sla_due_date IS NOT NULL
          AND sla_due_date < ?
          AND sla_breached = 0
    """, (now,))
    conn.commit()
    return cur.rowcount


def _apply_post_sar_effects(conn: sqlite3.Connection, alert_id: str, now: str) -> None:
    """Item 15 + 14: once a SAR is filed, the customer is flagged for EDD
    on this system going forward, and added to screening.db's
    internal_watchlist with watch_reason='PRIOR_SAR' so future onboarding/
    screening runs surface it. Idempotent — re-filing additional SARs on
    an already-EDD customer just refreshes the reason text."""
    row = conn.execute("SELECT account_id FROM aml_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not row:
        return
    account_id = row[0] if not isinstance(row, sqlite3.Row) else row["account_id"]

    customer = conn.execute(
        "SELECT customer_name FROM customer_profiles WHERE account_id = ?", (account_id,)
    ).fetchone()

    reason = f"Prior SAR filed {now[:10]}"
    conn.execute("""
        UPDATE customer_profiles SET edd_required = 1, edd_reason = ? WHERE account_id = ?
    """, (reason, account_id))
    conn.commit()

    if not customer:
        return
    customer_name = customer[0] if not isinstance(customer, sqlite3.Row) else customer["customer_name"]
    # Task 3: decrypt before normalising/matching and before copying into the internal watchlist, which stores the real name.
    customer_name = pii_crypto.decrypt_pii(customer_name)

    try:
        s_conn = _get_screening_conn()
        norm = _normalize_name(customer_name)
        existing = s_conn.execute(
            "SELECT 1 FROM internal_watchlist WHERE normalized_name = ? AND account_id = ?",
            (norm, account_id),
        ).fetchone()
        if not existing:
            s_conn.execute("""
                INSERT INTO internal_watchlist
                (full_name, normalized_name, account_id, watch_reason, added_by, added_date, review_date, is_active, notes)
                VALUES (?, ?, ?, 'PRIOR_SAR', 'SYSTEM', ?, NULL, 1, ?)
            """, (customer_name, norm, account_id, now[:10], f"Auto-added on SAR filing for alert {alert_id}"))
            s_conn.commit()
        s_conn.close()
    except Exception:
        log.warning("Could not write internal_watchlist entry for account %s — screening.db unavailable.", account_id)


def check_internal_watchlist(conn: sqlite3.Connection, account_id: str, company_id: str) -> Optional[dict]:
    """Item 14: returns the internal_watchlist entry for this account (by
    account_id OR by normalized customer name), or None. Used by the alert
    detail page to render the red WATCHLIST banner.

    internal_watchlist is each bank's own list (unlike sanctions_list/
    pep_list in the same screening.db, which stay global) — see the
    company_id migration on that table — so both lookups below are scoped
    to company_id too, not just account_id/name."""
    customer = conn.execute(
        "SELECT customer_name FROM customer_profiles WHERE account_id = ? AND company_id = ?",
        (account_id, company_id),
    ).fetchone()
    customer_name = pii_crypto.decrypt_pii(customer[0]) if customer else None  # Task 3
    norm = _normalize_name(customer_name) if customer_name else None

    try:
        s_conn = _get_screening_conn()
        s_conn.row_factory = sqlite3.Row
        row = None
        if norm:
            row = s_conn.execute(
                "SELECT * FROM internal_watchlist WHERE normalized_name = ? AND company_id = ? AND is_active = 1 LIMIT 1",
                (norm, company_id),
            ).fetchone()
        if row is None:
            row = s_conn.execute(
                "SELECT * FROM internal_watchlist WHERE account_id = ? AND company_id = ? AND is_active = 1 LIMIT 1",
                (account_id, company_id),
            ).fetchone()
        s_conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def record_alert_view(conn: sqlite3.Connection, alert_id: str, analyst_id: str, company_id: str, analyst_role: Optional[str] = None) -> None:
    """Logs that an analyst opened this alert's detail page."""
    conn.execute("""
        INSERT INTO aml_alert_views (alert_id, analyst_id, analyst_role, viewed_at, company_id)
        VALUES (?, ?, ?, ?, ?)
    """, (alert_id, analyst_id, analyst_role, datetime.now(timezone.utc).isoformat(), company_id))
    conn.commit()


def time_in_review_summary(conn: sqlite3.Connection, alert_id: str, company_id: str) -> Dict[str, Any]:
    """Derives a time-spent-investigating estimate from aml_alert_views.
    Measures from first view to closure (or now if still open).
    Use as a relative/comparative signal, not a precise time-tracker."""
    views = conn.execute("""
        SELECT analyst_id, viewed_at FROM aml_alert_views
        WHERE alert_id = ? AND company_id = ? ORDER BY viewed_at ASC
    """, (alert_id, company_id)).fetchall()

    if not views:
        return {
            "view_count": 0, "first_viewed_at": None, "last_viewed_at": None,
            "distinct_analysts": [], "time_in_review_days": None,
        }

    first_viewed_at = views[0][1]
    last_viewed_at = views[-1][1]
    distinct_analysts = sorted({v[0] for v in views})

    latest_decision_row = conn.execute("""
        SELECT workflow_status, closed_at FROM str_decisions
        WHERE alert_id = ? AND company_id = ? ORDER BY decision_id DESC LIMIT 1
    """, (alert_id, company_id)).fetchone()

    closed_at = latest_decision_row[1] if latest_decision_row else None
    end_point = closed_at or datetime.now(timezone.utc).isoformat()

    duration_row = conn.execute(
        "SELECT julianday(:end) - julianday(:start)",
        {"end": end_point, "start": first_viewed_at},
    ).fetchone()

    return {
        "view_count": len(views),
        "first_viewed_at": first_viewed_at,
        "last_viewed_at": last_viewed_at,
        "distinct_analysts": distinct_analysts,
        "time_in_review_days": round(duration_row[0], 3) if duration_row and duration_row[0] is not None else None,
        "currently_closed": closed_at is not None,
    }


# RBA Customer Layer (Item 3): profile generation moved to generator.py; this is a fallback only, inserting a bare MEDIUM/RETAIL placeholder for account_ids with no profile, never overwriting generator.py's rich profiles.
def seed_profiles_from_existing_data(conn: sqlite3.Connection) -> int:
    try:
        discovered = conn.execute("SELECT DISTINCT account_id, company_id FROM transactions").fetchall()
    except sqlite3.OperationalError:
        return 0  # transactions table doesn't exist yet — nothing to backfill

    now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    seeded = 0
    for account_id, company_id in discovered:
        cur = conn.execute("""
            INSERT OR IGNORE INTO customer_profiles
            (account_id, customer_name, customer_type, account_category,
             risk_rating, risk_rating_date, risk_rating_reason, is_pep,
             expected_monthly_volume, ubo_names, swift_bic, company_id)
            VALUES (?, ?, 'INDIVIDUAL', 'RETAIL', 'MEDIUM', ?, ?, 0, 50000.00, NULL, NULL, ?)
        """, (account_id, pii_crypto.encrypt_pii(f"Unprofiled Account {account_id}"), now_date,
              "Placeholder profile — run generator.py to seed a real customer profile.", company_id))
        if cur.rowcount > 0:
            seeded += 1
    if seeded:
        conn.commit()
        log.info("Backfilled %d placeholder customer profiles (generator.py not run for these accounts).", seeded)
    return seeded


# IMPROVEMENT 5: Duplicate alert deduplication fix
def _existing_open_alert(conn: sqlite3.Connection, scenario_code: str, account_id: str,
                          period_start: str, period_end: str, company_id: str) -> bool:
    """Returns True if an open/active alert already exists for this scenario+account
    whose detection period overlaps with [period_start, period_end]. Scoped by
    company_id — account_id alone isn't guaranteed unique across tenants, so
    without this a same-named account at a different company could suppress
    (or be suppressed by) an unrelated alert that isn't actually a duplicate."""
    row = conn.execute("""
        SELECT 1 FROM aml_alerts
        WHERE scenario_code = ? AND account_id = ? AND company_id = ?
          AND status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'DRAFT_SAR')
          AND detection_period_start < ? AND detection_period_end > ?
        LIMIT 1
    """, (scenario_code, account_id, company_id, period_end, period_start)).fetchone()
    return row is not None


def raise_alert(conn: sqlite3.Connection, scenario_code: str, account_id: str, trigger_value: float,
                period_start: str, period_end: str, severity: str, narrative: str,
                tx_ids: list[str], company_id: str = auth_security.LEGACY_COMPANY_ID,
                match_name: Optional[str] = None,
                match_source: Optional[str] = None, match_field: Optional[str] = None,
                match_type: Optional[str] = None, match_score: Optional[float] = None) -> Optional[str]:
    """
    `match_name` / `match_source` / `match_field` (screening-match
    scenarios only — SCN_SANCTION_MATCH, SCN_PEP_MATCH,
    SCN_INTERNAL_WATCHLIST): the exact watchlist target that was hit,
    which list/source it came from, and which field on the customer/
    transaction matched it (e.g. "Beneficial owner", "Beneficiary name").
    Persisted as structured columns — not just folded into the narrative —
    so alert_detail.html can render them directly without parsing text.

    `match_type` / `match_score` (item 1): 'EXACT' (score 1.0), 'PHONETIC',
    or 'FUZZY' plus the similarity score that produced it — so a fuzzy hit
    is visibly distinguishable from a literal exact match on the alert
    detail page, not presented with false certainty.
    """
    if _existing_open_alert(conn, scenario_code, account_id, period_start, period_end, company_id):
        log.debug("Suppressed duplicate alert: %s / %s", scenario_code, account_id)
        return None
    if alert_filter.should_suppress(conn, account_id, scenario_code, company_id=company_id):
        log.info("Suppressed alert (recently cleared): %s / %s", scenario_code, account_id)
        return None

    # Task 2: per-record robustness net — this record's scoring + alert INSERTs run in a SAVEPOINT, so a single failure rolls back only its partial writes, logs, bumps the error count, and returns None (loop continues).
    conn.execute("SAVEPOINT raise_alert")
    try:
        as_of = period_end[:10] if period_end else datetime.now(timezone.utc).strftime("%Y-%m-%d")
        score_breakdown = aml_risk.compute_risk_score(conn, account_id, company_id, as_of_date=as_of)
        aml_risk.persist_risk_score(conn, score_breakdown, company_id)
        # severity_from_score only returns LOW/MEDIUM/HIGH — the score can raise the scenario's floor but the 3-tier ceiling is enforced there, so no "CRITICAL" path exists.
        severity = aml_risk.severity_from_score(score_breakdown.composite_score, floor_severity=severity)

        # Item 15: customers under EDD get their severity floor bumped (LOW -> MEDIUM) and a narrative note, regardless of scenario.
        edd_row = conn.execute(
            "SELECT edd_required FROM customer_profiles WHERE account_id = ? AND company_id = ?", (account_id, company_id)
        ).fetchone()
        is_edd = bool(edd_row and edd_row[0])
        if is_edd:
            if severity == "LOW":
                severity = "MEDIUM"
            narrative = f"{narrative} CUSTOMER UNDER EDD — prior SAR on record."

        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        active_version = get_active_rule_version(conn, scenario_code, as_of_date=now)
        rule_version_id = active_version["version_id"] if active_version else None

        typology = SCENARIO_TYPOLOGY_MAP.get(scenario_code)
        sla_due_date = compute_sla_due_date(now)  # Item 16

        conn.execute("""
            INSERT INTO aml_alerts
            (alert_id, scenario_code, account_id, trigger_value,
             detection_period_start, detection_period_end, severity, status,
             narrative, created_at, risk_score_at_alert, risk_tier_at_alert,
             rule_version_id, typology, sla_due_date, sla_breached,
             screening_match_name, screening_match_source, screening_match_field,
             screening_match_type, screening_match_score, company_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
        """, (alert_id, scenario_code, account_id, round(trigger_value, 2),
              period_start, period_end, severity, narrative, now,
              score_breakdown.composite_score, score_breakdown.risk_tier,
              rule_version_id, typology, sla_due_date, match_name, match_source, match_field,
              match_type, match_score, company_id))

        conn.execute("""
            INSERT INTO str_decisions (alert_id, analyst_id, workflow_status, created_at, updated_at, company_id)
            VALUES (?, 'SYSTEM', 'OPEN', ?, ?, ?)
        """, (alert_id, now, now, company_id))

        conn.executemany("""
            INSERT OR IGNORE INTO aml_alert_transactions (alert_id, transaction_id)
            VALUES (?, ?)
        """, [(alert_id, tx_id) for tx_id in tx_ids])

        conn.execute("RELEASE SAVEPOINT raise_alert")
    except Exception:
        # Undo any partial writes for this one record, then keep the run going.
        conn.execute("ROLLBACK TO SAVEPOINT raise_alert")
        conn.execute("RELEASE SAVEPOINT raise_alert")
        _note_errored_record()
        log.exception(
            "raise_alert failed for scenario=%s account=%s company_id=%s "
            "trigger=%s period=%s..%s — record skipped, run continues.",
            scenario_code, account_id, company_id, trigger_value, period_start, period_end,
        )
        return None

    log.info("Alert raised %-30s account=%-10s severity=%s trigger=%.2f risk_score=%.1f (%s) typology=%s edd=%s",
             scenario_code, account_id, severity, trigger_value,
             score_breakdown.composite_score, score_breakdown.risk_tier, typology, is_edd)
    return alert_id


# Scenario 1: SCN_CASH_AGG_6M
def run_scn_cash_agg_6m(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    """Two weakness fixes live here:

    1. Channel discrimination — this rule is CASH-exclusive by its own
       typology (CASH_INTENSIVE), but previously aggregated every
       transaction on the account: international wires, crypto-exchange
       outflows, salary credits. An account with one minor ATM deposit and
       a stack of "contract payment" wires would fire a high-severity
       cash-aggregation alert whose evidence was almost entirely non-cash.
       Now filtered via CASH_TYPE_SQL_PREDICATE (NULL-tolerant — see the
       constant for why untyped legacy rows still count).

    2. Expected-volume awareness — the flat threshold ignored each
       customer's own KYC-declared expected_monthly_volume, so a customer
       expected to move AED 50k/month tripped the 55k six-month aggregate
       in week five of perfectly normal behaviour, every cycle. The
       effective threshold is now MAX(flat floor, EMV-derived floor),
       still scaled by the risk-tier/PEP multiplier — see
       CASH_AGG_EXPECTED_VOLUME_RATIO for the calibration rationale."""
    log.info("Running SCN_CASH_AGG_6M as_of=%s company_id=%s", as_of_date, company_id)
    rows = conn.execute(f"""
        WITH agg AS (
            SELECT account_id, SUM(amount) AS total_cash, MIN(transaction_date) AS period_start,
                   MAX(transaction_date) AS period_end, GROUP_CONCAT(transaction_id) AS tx_ids
            FROM transactions
            WHERE amount >= 1000 AND company_id = :company_id
              AND {CASH_TYPE_SQL_PREDICATE}
              AND date(transaction_date) BETWEEN date(:as_of, '-6 months') AND date(:as_of)
            GROUP BY account_id
        ),
        risk AS (
            SELECT a.*,
                   COALESCE(cp.risk_rating, 'MEDIUM') AS risk_rating,
                   COALESCE(cp.is_pep, 0) AS is_pep,
                   COALESCE(cp.expected_monthly_volume, 0) AS expected_monthly_volume,
                   (CASE COALESCE(cp.risk_rating, 'MEDIUM')
                        WHEN 'HIGH' THEN :mult_high WHEN 'LOW' THEN :mult_low ELSE :mult_medium END
                   ) AS rating_multiplier
            FROM agg a
            LEFT JOIN customer_profiles cp ON cp.account_id = a.account_id AND cp.company_id = :company_id
        ),
        thresholds AS (
            SELECT *,
                   MAX(:base_threshold,
                       MIN(expected_monthly_volume * :window_months * :emv_ratio, :emv_ceiling))
                   * (CASE WHEN is_pep = 1 THEN MIN(rating_multiplier, :pep_cap) ELSE rating_multiplier END)
                   AS effective_threshold
            FROM risk
        )
        SELECT account_id, total_cash, period_start, period_end, tx_ids, risk_rating, is_pep,
               expected_monthly_volume, effective_threshold
        FROM thresholds
        WHERE total_cash > effective_threshold
    """, {
        "as_of": as_of_date,
        "company_id": company_id,
        "base_threshold": CASH_AGG_6M_THRESHOLD,
        "window_months": CASH_AGG_WINDOW_MONTHS,
        "emv_ratio": CASH_AGG_EXPECTED_VOLUME_RATIO,
        "emv_ceiling": CASH_AGG_EXPECTED_VOLUME_CEILING,
        "mult_high": aml_risk.RISK_TIER_THRESHOLD_MULTIPLIER["HIGH"],
        "mult_medium": aml_risk.RISK_TIER_THRESHOLD_MULTIPLIER["MEDIUM"],
        "mult_low": aml_risk.RISK_TIER_THRESHOLD_MULTIPLIER["LOW"],
        "pep_cap": aml_risk.PEP_THRESHOLD_MULTIPLIER_CAP,
    }).fetchall()

    raised = suppressed = 0
    for row in rows:
        (account_id, total, p_start, p_end, tx_ids_str, risk_rating, is_pep,
         expected_monthly_volume, effective_threshold) = row
        tx_ids = tx_ids_str.split(",") if tx_ids_str else []
        basis = "PEP status" if is_pep else f"{risk_rating} risk rating"
        narrative = (f"Account {account_id} accumulated AED {total:,.2f} in cash-channel transactions "
                     f"over {p_start[:10]} to {p_end[:10]}, above this account's effective threshold of "
                     f"AED {effective_threshold:,.2f} (base AED {CASH_AGG_6M_THRESHOLD:,.0f}, "
                     f"expected monthly volume AED {expected_monthly_volume:,.0f}, adjusted for {basis}).")
        severity = "HIGH" if total > effective_threshold * 2 else "MEDIUM"
        aid = raise_alert(conn, "SCN_CASH_AGG_6M", account_id, total, p_start, p_end, severity, narrative, tx_ids, company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1
    return raised, suppressed


# Scenario 2: SCN_STRUCTURING_CASH
def run_scn_structuring_cash(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_STRUCTURING_CASH as_of=%s company_id=%s", as_of_date, company_id)
    # Cash-channel only — structuring evades CASH reporting thresholds; a wire in the 8.5k-10k band is unremarkable.
    rows = conn.execute(f"""
        SELECT account_id, COUNT(*) AS tx_count, SUM(amount) AS total_amount,
               MIN(transaction_date) AS period_start, MAX(transaction_date) AS period_end,
               GROUP_CONCAT(transaction_id) AS tx_ids
        FROM transactions
        WHERE amount BETWEEN :low AND :high AND company_id = :company_id
          AND {CASH_TYPE_SQL_PREDICATE}
          AND date(transaction_date) BETWEEN date(:as_of, :window) AND date(:as_of)
        GROUP BY account_id HAVING COUNT(*) >= :min_count
    """, {"low": STRUCTURING_BAND_LOW, "high": STRUCTURING_BAND_HIGH, "as_of": as_of_date, "company_id": company_id,
          "window": f"-{STRUCTURING_WINDOW_DAYS} days", "min_count": STRUCTURING_TX_COUNT}).fetchall()

    raised = suppressed = 0
    for row in rows:
        account_id, tx_count, total, p_start, p_end, tx_ids_str = row
        tx_ids = tx_ids_str.split(",") if tx_ids_str else []
        narrative = f"Account {account_id} conducted {tx_count} clustered transactions between AED {STRUCTURING_BAND_LOW} and {STRUCTURING_BAND_HIGH}."
        severity = "HIGH" if tx_count >= 5 else "MEDIUM"
        aid = raise_alert(conn, "SCN_STRUCTURING_CASH", account_id, total, p_start, p_end, severity, narrative, tx_ids, company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1
    return raised, suppressed


# Scenario 3: SCN_HIGH_RISK_JURISDICTION
def run_scn_high_risk_jurisdiction(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_HIGH_RISK_JURISDICTION as_of=%s company_id=%s", as_of_date, company_id)
    params = {"elevated_limit": HIGH_RISK_ELEVATED_LIMIT, "standard_limit": HIGH_RISK_STANDARD_LIMIT,
              "as_of": as_of_date, "company_id": company_id}
    country_list = sorted(list(HIGH_RISK_JURISDICTIONS))
    placeholders = []
    for idx, country in enumerate(country_list):
        p_name = f"country_{idx}"
        placeholders.append(f":{p_name}")
        params[p_name] = country

    rows = conn.execute(f"""
        SELECT t.transaction_id, t.account_id, t.amount, t.country, t.transaction_date,
               COALESCE(cp.risk_rating, 'MEDIUM') AS risk_rating,
               COALESCE(cp.is_pep, 0) AS is_pep,
               CASE WHEN COALESCE(cp.risk_rating, 'MEDIUM') = 'HIGH' OR COALESCE(cp.is_pep, 0) = 1
                    THEN :elevated_limit ELSE :standard_limit END AS applicable_threshold
        FROM transactions t
        LEFT JOIN customer_profiles cp ON cp.account_id = t.account_id AND cp.company_id = t.company_id
        WHERE t.country IN ({", ".join(placeholders)})
          AND t.company_id = :company_id
          AND t.amount >= CASE WHEN COALESCE(cp.risk_rating, 'MEDIUM') = 'HIGH' OR COALESCE(cp.is_pep, 0) = 1
                               THEN :elevated_limit ELSE :standard_limit END
          AND date(t.transaction_date) <= date(:as_of)
        ORDER BY t.transaction_date DESC
    """, params).fetchall()

    raised = suppressed = 0
    for row in rows:
        tx_id, account_id, amount, country, tx_date, risk_rating, is_pep, threshold = row
        severity = "HIGH" if amount >= HIGH_RISK_STANDARD_LIMIT else "MEDIUM"
        narrative = f"Transaction of AED {amount} involving country {country} processed for account {account_id}."
        aid = raise_alert(conn, "SCN_HIGH_RISK_JURISDICTION", account_id, amount, tx_date, tx_date, severity, narrative, [tx_id], company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1

    # Routing-path leg: the endpoint query only sees declared t.country, so this pass screens every intermediary_countries hop (pipe-separated) against HIGH_RISK_JURISDICTIONS in Python, skipping transactions whose endpoint is already high-risk.
    routing_rows = conn.execute("""
        SELECT t.transaction_id, t.account_id, t.amount, t.country, t.transaction_date,
               t.intermediary_countries, t.transaction_type,
               t.counterparty_name, t.counterparty_wallet_address,
               CASE WHEN COALESCE(cp.risk_rating, 'MEDIUM') = 'HIGH' OR COALESCE(cp.is_pep, 0) = 1
                    THEN :elevated_limit ELSE :standard_limit END AS applicable_threshold
        FROM transactions t
        LEFT JOIN customer_profiles cp ON cp.account_id = t.account_id AND cp.company_id = t.company_id
        WHERE t.intermediary_countries IS NOT NULL
          AND t.company_id = :company_id
          AND t.amount >= CASE WHEN COALESCE(cp.risk_rating, 'MEDIUM') = 'HIGH' OR COALESCE(cp.is_pep, 0) = 1
                               THEN :elevated_limit ELSE :standard_limit END
          AND date(t.transaction_date) <= date(:as_of)
        ORDER BY t.transaction_date DESC
    """, {"elevated_limit": HIGH_RISK_ELEVATED_LIMIT, "standard_limit": HIGH_RISK_STANDARD_LIMIT,
          "as_of": as_of_date, "company_id": company_id}).fetchall()

    for (tx_id, account_id, amount, country, tx_date, hops_str, tx_type,
         counterparty_name, wallet_address, threshold) in routing_rows:
        if country in HIGH_RISK_JURISDICTIONS:
            continue  # endpoint loop above already covers this transaction
        hops = [h.strip() for h in hops_str.split("|") if h.strip()]
        hot_hops = sorted({h for h in hops if h in HIGH_RISK_JURISDICTIONS})
        if not hot_hops:
            continue
        severity = "HIGH" if amount >= HIGH_RISK_STANDARD_LIMIT else "MEDIUM"
        wallet_address = pii_crypto.decrypt_pii(wallet_address)  # Task 3: encrypted at rest
        va_note = ""
        if tx_type == "CRYPTO":
            wallet_desc = f", wallet {wallet_address}" if wallet_address else ""
            va_note = (f" This is a VIRTUAL-ASSET transfer to "
                       f"{counterparty_name or 'an unidentified VASP'}{wallet_desc}.")
        narrative = (f"Transaction of AED {amount:,.2f} on account {account_id} was routed through "
                     f"high-risk jurisdiction(s) {', '.join(hot_hops)} (full path: {' -> '.join(hops)}) "
                     f"en route to declared endpoint {country}.{va_note}")
        aid = raise_alert(conn, "SCN_HIGH_RISK_JURISDICTION", account_id, amount, tx_date, tx_date, severity, narrative, [tx_id], company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1
    return raised, suppressed


# Scenario 4: SCN_BEHAVIOUR_CHANGE
def run_scn_behaviour_change(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_BEHAVIOUR_CHANGE as_of=%s company_id=%s", as_of_date, company_id)
    rows = conn.execute("""
        WITH baseline AS (
            SELECT account_id, COUNT(*) AS baseline_tx_count, SUM(amount) AS baseline_volume
            FROM transactions
            WHERE company_id = :company_id
              AND date(transaction_date) BETWEEN date(:as_of, :baseline_start) AND date(:as_of, :review_start)
            GROUP BY account_id
        ), current_period AS (
            SELECT account_id, COUNT(*) AS current_tx_count, SUM(amount) AS current_volume,
                   MIN(transaction_date) AS period_start, MAX(transaction_date) AS period_end,
                   GROUP_CONCAT(transaction_id) AS tx_ids
            FROM transactions
            WHERE company_id = :company_id
              AND date(transaction_date) BETWEEN date(:as_of, :review_start) AND date(:as_of)
            GROUP BY account_id
        )
        SELECT cp.account_id, cp.current_tx_count, cp.current_volume, bl.baseline_tx_count,
               bl.baseline_volume, cp.period_start, cp.period_end, cp.tx_ids
        FROM current_period cp
        INNER JOIN baseline bl ON cp.account_id = bl.account_id
        WHERE bl.baseline_volume > 0 AND cp.current_volume >= bl.baseline_volume * :multiplier
    """, {
        "as_of": as_of_date,
        "company_id": company_id,
        "baseline_start": f"-{BEHAVIOUR_BASELINE_DAYS + BEHAVIOUR_REVIEW_DAYS} days",
        "review_start": f"-{BEHAVIOUR_REVIEW_DAYS} days",
        "multiplier": BEHAVIOUR_MULTIPLIER,
    }).fetchall()

    raised = suppressed = 0
    for row in rows:
        account_id, cur_count, cur_vol, base_count, base_vol, p_start, p_end, tx_ids_str = row
        tx_ids = tx_ids_str.split(",") if tx_ids_str else []
        ratio = cur_vol / base_vol
        narrative = (f"Account {account_id} moved AED {cur_vol:,.2f} in the current {BEHAVIOUR_REVIEW_DAYS}-day "
                     f"period, {ratio:.1f}x its {BEHAVIOUR_BASELINE_DAYS}-day historical baseline of AED {base_vol:,.2f}.")
        aid = raise_alert(conn, "SCN_BEHAVIOUR_CHANGE", account_id, ratio, p_start, p_end, "MEDIUM", narrative, tx_ids, company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1
    return raised, suppressed


# Scenario 5: SCN_PEP_EXPOSURE
def run_scn_pep_exposure(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_PEP_EXPOSURE as_of=%s company_id=%s", as_of_date, company_id)
    _sync_pep_flags_from_screening_db(conn, company_id)

    single_tx_rows = conn.execute("""
        SELECT t.transaction_id, t.account_id, t.amount, t.transaction_date
        FROM transactions t
        JOIN customer_profiles cp ON cp.account_id = t.account_id AND cp.company_id = t.company_id
        WHERE cp.is_pep = 1 AND t.amount >= :single_threshold AND t.company_id = :company_id
          AND date(t.transaction_date) <= date(:as_of)
        ORDER BY t.transaction_date DESC
    """, {"single_threshold": PEP_SINGLE_TX_THRESHOLD, "as_of": as_of_date, "company_id": company_id}).fetchall()

    agg_rows = conn.execute("""
        SELECT t.account_id, SUM(t.amount) AS total, MIN(t.transaction_date) AS p_start,
               MAX(t.transaction_date) AS p_end, GROUP_CONCAT(t.transaction_id) AS tx_ids,
               cp.expected_monthly_volume
        FROM transactions t
        JOIN customer_profiles cp ON cp.account_id = t.account_id AND cp.company_id = t.company_id
        WHERE cp.is_pep = 1 AND t.company_id = :company_id
          AND date(t.transaction_date) BETWEEN date(:as_of, '-30 days') AND date(:as_of)
        GROUP BY t.account_id
        HAVING SUM(t.amount) >= cp.expected_monthly_volume * :multiplier
    """, {"as_of": as_of_date, "multiplier": PEP_AGGREGATE_MULTIPLIER, "company_id": company_id}).fetchall()

    raised = suppressed = 0
    seen_accounts: set[str] = set()

    for tx_id, account_id, amount, tx_date in single_tx_rows:
        narrative = (f"PEP-flagged account {account_id} processed a single transaction of AED {amount:,.2f}, "
                     f"above the PEP single-transaction threshold of AED {PEP_SINGLE_TX_THRESHOLD:,.0f}.")
        aid = raise_alert(conn, "SCN_PEP_EXPOSURE", account_id, amount, tx_date, tx_date, "HIGH", narrative, [tx_id], company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1
        seen_accounts.add(account_id)

    for account_id, total, p_start, p_end, tx_ids_str, expected_monthly in agg_rows:
        if account_id in seen_accounts:
            continue
        tx_ids = tx_ids_str.split(",") if tx_ids_str else []
        narrative = (f"PEP-flagged account {account_id} aggregated AED {total:,.2f} over a 30-day window, "
                     f"{total / expected_monthly:.1f}x their expected monthly volume of AED {expected_monthly:,.2f}.")
        aid = raise_alert(conn, "SCN_PEP_EXPOSURE", account_id, total, p_start, p_end, "HIGH", narrative, tx_ids, company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1

    return raised, suppressed


def _sync_pep_flags_from_screening_db(conn: sqlite3.Connection, company_id: str) -> None:
    """Cross-references customer_profiles.customer_name (and, for
    CORPORATE accounts, each UBO name in ubo_names) against pep_list in
    screening.db and updates is_pep accordingly."""
    try:
        s_conn = _get_screening_conn()
        pep_names = {
            row[0] for row in
            s_conn.execute("SELECT normalized_name FROM pep_list WHERE is_active = 1").fetchall()
        }
        s_conn.close()
    except Exception:
        log.warning("Could not read pep_list from screening.db — is_pep flags not updated.")
        return

    if not pep_names:
        return

    customers = conn.execute(
        "SELECT account_id, customer_name, ubo_names FROM customer_profiles WHERE company_id = ?", (company_id,)
    ).fetchall()
    updated = 0
    for account_id, customer_name, ubo_names in customers:
        customer_name = pii_crypto.decrypt_pii(customer_name)  # Task 3: match on cleartext
        names_to_check = [customer_name]
        if ubo_names:
            names_to_check += ubo_names.split("|")
        is_pep = 1 if any(_normalize_name(n) in pep_names for n in names_to_check if n) else 0
        conn.execute(
            "UPDATE customer_profiles SET is_pep = ? WHERE account_id = ? AND company_id = ?",
            (is_pep, account_id, company_id),
        )
        updated += 1
    conn.commit()
    log.info("PEP flags synced from screening.db for %d customer profiles.", updated)


# Scenarios 6a/6b/6c: Screening-match scenarios — a screening hit is a rule-based scenario like any other, going into the same Open Queue, workflow, and severity model, not a standalone reference page.
def _normalize_name(name: str) -> str:
    """Uppercase, strip punctuation/whitespace — the baseline normaliser
    used for exact-match lookups (still the fast path; most real hits are
    exact). Fuzzy matching below is the fallback for everything exact
    matching misses."""
    return re.sub(r"[^A-Z0-9 ]", "", name.upper()).strip()


# Item 1: fuzzy/phonetic name matching to catch transliteration variants exact-string screening misses; a stdlib-only combination of Soundex (sound-alike) and difflib similarity (near-identical spelling), matching if EITHER clears its threshold.
FUZZY_MATCH_THRESHOLD = 0.86  # difflib ratio, 0-1; tuned to catch real
                              # transliteration variants without flooding the queue on coincidentally-similar names


def _soundex(name: str) -> str:
    """Classic Soundex phonetic key, computed per word and concatenated —
    so multi-word names compare word-for-word rather than as one blob,
    which keeps "Khalid Al Mansoori" from collapsing onto every other
    "K... A... M..." name in the list."""
    codes = {
        "B": "1", "F": "1", "P": "1", "V": "1",
        "C": "2", "G": "2", "J": "2", "K": "2", "Q": "2", "S": "2", "X": "2", "Z": "2",
        "D": "3", "T": "3",
        "L": "4",
        "M": "5", "N": "5",
        "R": "6",
    }

    def _word_soundex(word: str) -> str:
        word = re.sub(r"[^A-Z]", "", word.upper())
        if not word:
            return ""
        first = word[0]
        digits = []
        prev = codes.get(first, "")
        for ch in word[1:]:
            code = codes.get(ch, "")
            if code and code != prev:
                digits.append(code)
            prev = code
        return (first + "".join(digits) + "000")[:4]

    return " ".join(_word_soundex(w) for w in name.upper().split() if w)


def _similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _find_best_fuzzy_match(name: str, candidates: dict) -> Optional[Tuple[str, float, str]]:
    """Scans every candidate normalized-name key for a fuzzy hit. Returns
    (matched_normalized_key, similarity_score, match_method) for the
    single best match above threshold, or None. `candidates` is the same
    {normalized_name: row} dict the exact-match path already builds, so
    this is purely an additional pass over the same data — no separate
    list to keep in sync.

    O(n) per name against the screening list size (tens to low hundreds
    of entries here), called per customer/UBO/wire-field name — entirely
    fine at this scale; would need indexing (e.g. precomputed phonetic
    buckets) at real-world list sizes of hundreds of thousands."""
    norm = _normalize_name(name)
    if not norm:
        return None
    name_soundex = _soundex(norm)

    best_key, best_score, best_method = None, 0.0, None
    for cand_key in candidates:
        if cand_key == norm:
            continue  # exact matches are handled by the fast path already
        if _soundex(cand_key) == name_soundex:
            # Phonetic hit — strong match even if spelling differs more than the ratio threshold allows.
            score = max(_similarity_ratio(norm, cand_key), 0.90)
            if score > best_score:
                best_key, best_score, best_method = cand_key, score, "PHONETIC"
            continue
        ratio = _similarity_ratio(norm, cand_key)
        if ratio >= FUZZY_MATCH_THRESHOLD and ratio > best_score:
            best_key, best_score, best_method = cand_key, ratio, "FUZZY"

    if best_key is None:
        return None
    return best_key, round(best_score, 3), best_method


def _resolve_match(name: str, candidates: dict) -> Optional[Tuple[Any, str, float]]:
    """Single entry point every screening loop below should call instead
    of a bare dict lookup: tries the exact-match fast path first, falls
    back to fuzzy/phonetic. Returns (matched_row, match_type, score) where
    match_type is 'EXACT' (score 1.0), 'PHONETIC', or 'FUZZY' — surfaced
    to the analyst on the alert detail page so a fuzzy hit is visibly
    flagged as "review this name carefully" rather than presented with
    the same confidence as a literal exact match."""
    norm = _normalize_name(name)
    exact = candidates.get(norm)
    if exact is not None:
        return exact, "EXACT", 1.0
    fuzzy = _find_best_fuzzy_match(name, candidates)
    if fuzzy is None:
        return None
    matched_key, score, method = fuzzy
    return candidates[matched_key], method, score


def _screen_customers_against_list(
    conn: sqlite3.Connection, as_of_date: str, scenario_code: str,
    list_by_norm: dict, severity_for_match, narrative_for_match, company_id: str,
) -> Tuple[int, int]:
    """Shared account-holder + UBO screening loop used by both
    run_scn_sanction_match and run_scn_pep_match — the two scenarios screen
    different lists but identically: check customer_name, then each UBO
    name on CORPORATE accounts, against a normalized-name lookup table
    (exact match first, fuzzy/phonetic fallback — see _resolve_match).
    `severity_for_match(match_row)` and `narrative_for_match(role_label, name,
    match_row, account_id, match_type, score)` are scenario-specific
    callbacks so this loop isn't sanctions- or PEP-specific itself."""
    raised = suppressed = 0
    customers = conn.execute(
        "SELECT account_id, customer_name, ubo_names FROM customer_profiles WHERE company_id = ?", (company_id,)
    ).fetchall()
    for account_id, customer_name, ubo_names in customers:
        customer_name = pii_crypto.decrypt_pii(customer_name)  # Task 3: match on cleartext
        candidates = [("Account holder", customer_name)]
        if ubo_names:
            candidates += [("Beneficial owner", u) for u in ubo_names.split("|") if u]

        for role_label, name in candidates:
            resolved = _resolve_match(name, list_by_norm)
            if resolved is None:
                continue
            match, match_type, score = resolved

            last_tx = conn.execute("""
                SELECT transaction_id, transaction_date FROM transactions
                WHERE account_id = ? AND company_id = ? AND date(transaction_date) <= date(?)
                ORDER BY transaction_date DESC LIMIT 1
            """, (account_id, company_id, as_of_date)).fetchone()
            if last_tx:
                tx_id, tx_date = last_tx
                tx_ids = [tx_id]
            else:
                tx_date = as_of_date
                tx_ids = []

            narrative, match_source = narrative_for_match(role_label, name, match, account_id, match_type, score)
            severity = severity_for_match(match, match_type)
            aid = raise_alert(
                conn, scenario_code, account_id, 0.0, tx_date, tx_date, severity, narrative, tx_ids,
                company_id=company_id, match_name=name, match_source=match_source, match_field=role_label,
                match_type=match_type, match_score=score,
            )
            if aid:
                raised += 1
            else:
                suppressed += 1
            break  # one alert per account per run — don't double-fire across multiple UBOs
    return raised, suppressed


def run_scn_sanction_match(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    """SCN_SANCTION_MATCH — replaces the old SCN_SANCTIONS_SCREENING.
    Screens, per Category 1/2/3:
      - account holder's customer_name (all categories)
      - each UBO name for CORPORATE accounts (category 2)
      - wire-message ordering_customer_name / beneficiary_name on
        individual transactions for CORRESPONDENT accounts (category 3) —
        screened at the TRANSACTION level since those names live on the
        transaction itself, not on customer_profiles.
    Floor severity is always HIGH — sanctions hits are never downgraded —
    but the 3-tier ceiling (LOW/MEDIUM/HIGH) still applies; raise_alert's
    risk-score layer can only confirm HIGH here, never invent a 4th tier.
    """
    log.info("Running SCN_SANCTION_MATCH as_of=%s", as_of_date)
    try:
        s_conn = _get_screening_conn()
        sanctioned = s_conn.execute(
            "SELECT full_name, normalized_name, list_source FROM sanctions_list WHERE is_active = 1"
        ).fetchall()
        s_conn.close()
    except Exception:
        log.warning("Could not connect to screening.db — sanctions screening skipped.")
        return 0, 0

    if not sanctioned:
        log.info("sanctions_list in screening.db is empty — run sanctions_pep_seed.py first.")
        return 0, 0

    sanctioned_by_norm = {row[1]: row for row in sanctioned}

    def _severity(match, match_type):
        return "HIGH"

    def _narrative(role_label, name, match, account_id, match_type, score):
        entity_name, _, list_source = match
        confidence = "" if match_type == "EXACT" else f" [{match_type} match, similarity {score:.0%} — verify before acting]"
        text = (f"{role_label} name '{name}' on account {account_id} matches "
                f"sanctions entry '{entity_name}' ({list_source}){confidence}.")
        return text, list_source

    raised, suppressed = _screen_customers_against_list(
        conn, as_of_date, "SCN_SANCTION_MATCH", sanctioned_by_norm, _severity, _narrative, company_id,
    )

    # Category 3: wire-message ordering/beneficiary names (transaction-level, not covered by the account-holder/UBO loop above).
    wire_rows = conn.execute("""
        SELECT t.transaction_id, t.account_id, t.transaction_date,
               t.ordering_customer_name, t.beneficiary_name
        FROM transactions t
        JOIN customer_profiles cp ON cp.account_id = t.account_id AND cp.company_id = t.company_id
        WHERE cp.account_category = 'CORRESPONDENT' AND t.company_id = ?
          AND (t.ordering_customer_name IS NOT NULL OR t.beneficiary_name IS NOT NULL)
          AND date(t.transaction_date) <= date(?)
    """, (company_id, as_of_date)).fetchall()

    for tx_id, account_id, tx_date, ordering_name, beneficiary_name in wire_rows:
        for field_label, name in (("Ordering customer", ordering_name), ("Beneficiary", beneficiary_name)):
            if not name:
                continue
            resolved = _resolve_match(name, sanctioned_by_norm)
            if resolved is None:
                continue
            match, match_type, score = resolved
            entity_name, _, list_source = match
            confidence = "" if match_type == "EXACT" else f" [{match_type} match, similarity {score:.0%} — verify before acting]"
            narrative = (f"{field_label} name match: {name} — wire transaction {tx_id} on correspondent "
                         f"account {account_id} matches sanctions entry '{entity_name}' ({list_source}){confidence}.")
            aid = raise_alert(
                conn, "SCN_SANCTION_MATCH", account_id, 0.0, tx_date, tx_date, "HIGH", narrative, [tx_id],
                company_id=company_id, match_name=name, match_source=list_source, match_field=field_label,
                match_type=match_type, match_score=score,
            )
            if aid:
                raised += 1
            else:
                suppressed += 1
            break  # one alert per transaction is enough
    return raised, suppressed


def run_scn_pep_match(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    """SCN_PEP_MATCH — a screening-list HIT (this name is on the PEP list),
    distinct from SCN_PEP_EXPOSURE (a TRANSACTIONAL pattern: a known PEP
    moving unusually large amounts). Both can fire independently on the
    same account; they answer different questions. Floor severity is
    MEDIUM — being a PEP isn't itself wrongdoing, just elevated-monitoring
    posture, so it doesn't default to HIGH the way a sanctions hit does.
    """
    log.info("Running SCN_PEP_MATCH as_of=%s", as_of_date)
    try:
        s_conn = _get_screening_conn()
        pep_rows = s_conn.execute(
            "SELECT full_name, normalized_name, pep_category FROM pep_list WHERE is_active = 1"
        ).fetchall()
        s_conn.close()
    except Exception:
        log.warning("Could not connect to screening.db — PEP match screening skipped.")
        return 0, 0

    if not pep_rows:
        log.info("pep_list in screening.db is empty — run sanctions_pep_seed.py first.")
        return 0, 0

    pep_by_norm = {row[1]: row for row in pep_rows}

    def _severity(match, match_type):
        return "MEDIUM"

    def _narrative(role_label, name, match, account_id, match_type, score):
        entity_name, _, category = match
        confidence = "" if match_type == "EXACT" else f" [{match_type} match, similarity {score:.0%} — verify before acting]"
        text = (f"{role_label} name '{name}' on account {account_id} matches "
                f"PEP list entry '{entity_name}' (category: {category}){confidence}.")
        return text, category

    return _screen_customers_against_list(
        conn, as_of_date, "SCN_PEP_MATCH", pep_by_norm, _severity, _narrative, company_id,
    )


def run_scn_internal_watchlist_match(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    """SCN_INTERNAL_WATCHLIST — matches against the bank's own watchlist
    (prior SARs, EDD flags, inter-bank typology intel), not an external
    regulator list. Severity floor depends on watch_reason: a prior SAR is
    the strongest signal (HIGH); EDD/intel-sharing entries default MEDIUM,
    since those reflect heightened monitoring rather than a confirmed
    filing. Still strictly LOW/MEDIUM/HIGH — no separate tier for this
    scenario."""
    log.info("Running SCN_INTERNAL_WATCHLIST as_of=%s", as_of_date)
    try:
        s_conn = _get_screening_conn()
        watch_rows = s_conn.execute(
            "SELECT full_name, normalized_name, account_id, watch_reason FROM internal_watchlist "
            "WHERE is_active = 1 AND company_id = ?", (company_id,)
        ).fetchall()
        s_conn.close()
    except Exception:
        log.warning("Could not connect to screening.db — internal watchlist screening skipped.")
        return 0, 0

    if not watch_rows:
        return 0, 0

    watch_by_norm: dict[str, tuple] = {}
    watch_by_account: dict[str, tuple] = {}
    for full_name, norm, account_id, watch_reason in watch_rows:
        watch_by_norm[norm] = (full_name, watch_reason)
        if account_id:
            watch_by_account[account_id] = (full_name, watch_reason)

    def _severity(match, match_type):
        _, watch_reason = match
        return "HIGH" if watch_reason == "PRIOR_SAR" else "MEDIUM"

    def _narrative(role_label, name, match, account_id, match_type, score):
        entity_name, watch_reason = match
        confidence = "" if match_type in ("EXACT", "ACCOUNT_ID") else f" [{match_type} match, similarity {score:.0%} — verify before acting]"
        text = (f"{role_label} name '{name}' on account {account_id} matches the bank's internal "
                f"watchlist entry '{entity_name}' (reason: {watch_reason.replace('_', ' ')}){confidence}.")
        return text, f"Internal Watchlist ({watch_reason})"

    raised = suppressed = 0
    customers = conn.execute(
        "SELECT account_id, customer_name, ubo_names FROM customer_profiles WHERE company_id = ?", (company_id,)
    ).fetchall()
    for account_id, customer_name, ubo_names in customers:
        customer_name = pii_crypto.decrypt_pii(customer_name)  # Task 3: match on cleartext
        # Direct account_id match (e.g. auto-added on a prior SAR) takes priority over name matching and is never fuzzy — an account_id is an exact identifier.
        match = watch_by_account.get(account_id)
        role_label, name, match_type, score = "Account", account_id, "ACCOUNT_ID", 1.0
        if not match:
            candidates = [("Account holder", customer_name)]
            if ubo_names:
                candidates += [("Beneficial owner", u) for u in ubo_names.split("|") if u]
            for r, n in candidates:
                resolved = _resolve_match(n, watch_by_norm)
                if resolved:
                    match, match_type, score = resolved
                    role_label, name = r, n
                    break
        if not match:
            continue

        last_tx = conn.execute("""
            SELECT transaction_id, transaction_date FROM transactions
            WHERE account_id = ? AND company_id = ? AND date(transaction_date) <= date(?)
            ORDER BY transaction_date DESC LIMIT 1
        """, (account_id, company_id, as_of_date)).fetchone()
        if last_tx:
            tx_id, tx_date = last_tx
            tx_ids = [tx_id]
        else:
            tx_date = as_of_date
            tx_ids = []

        narrative, match_source = _narrative(role_label, name, match, account_id, match_type, score)
        aid = raise_alert(
            conn, "SCN_INTERNAL_WATCHLIST", account_id, 0.0, tx_date, tx_date, _severity(match, match_type), narrative, tx_ids,
            company_id=company_id, match_name=name, match_source=match_source, match_field=role_label,
            match_type=match_type, match_score=score,
        )
        if aid:
            raised += 1
        else:
            suppressed += 1

    return raised, suppressed


# Item 2: pre-transaction wire interdiction — unlike the batch screening scenarios (which detect after posting), this synchronously screens one submitted wire's three names and returns a blocked/cleared decision immediately.
def screen_names_for_interdiction(for_screening: list[Tuple[str, str]]) -> Optional[dict]:
    """Screens a small set of (field_label, name) pairs against sanctions,
    PEP, and internal watchlist data, using the same exact-then-fuzzy
    matching as the batch scenarios (see _resolve_match). Returns the
    single best/highest-priority match found as a dict, or None if every
    name is clean. Sanctions hits are checked first and win over PEP/
    watchlist hits if multiple lists happen to match, since a sanctions
    hit is the most severe possible reason to block a wire."""
    try:
        s_conn = _get_screening_conn()
        sanctioned = {row[1]: row for row in s_conn.execute(
            "SELECT full_name, normalized_name, list_source FROM sanctions_list WHERE is_active = 1"
        ).fetchall()}
        pep = {row[1]: row for row in s_conn.execute(
            "SELECT full_name, normalized_name, pep_category FROM pep_list WHERE is_active = 1"
        ).fetchall()}
        watch_rows = s_conn.execute(
            "SELECT full_name, normalized_name, watch_reason FROM internal_watchlist WHERE is_active = 1"
        ).fetchall()
        watch = {row[1]: (row[0], row[2]) for row in watch_rows}
        s_conn.close()
    except Exception:
        # FAIL CLOSED: on a screening-DB error, return a synthetic HIGH/EXACT match (not None) so the wire is held BLOCKED for manual review rather than released unscreened.
        log.error("Could not connect to screening.db — FAILING CLOSED: wire held for manual review.")
        return {
            "field": "Screening system", "name": "(wire could not be screened)",
            "list": "SCREENING_UNAVAILABLE", "entity_name": "Screening system unavailable",
            "source": "SYSTEM — manual sanctions review required before release",
            "match_type": "EXACT", "score": 1.0,
            "scenario_code": "SCN_INTERNAL_WATCHLIST", "severity": "HIGH",
        }

    for field_label, name in for_screening:
        if not name or not name.strip():
            continue
        resolved = _resolve_match(name, sanctioned)
        if resolved:
            match, match_type, score = resolved
            entity_name, _, list_source = match
            return {
                "field": field_label, "name": name, "list": "SANCTIONS",
                "entity_name": entity_name, "source": list_source,
                "match_type": match_type, "score": score, "scenario_code": "SCN_SANCTION_MATCH",
                "severity": "HIGH",
            }

    for field_label, name in for_screening:
        if not name or not name.strip():
            continue
        resolved = _resolve_match(name, pep)
        if resolved:
            match, match_type, score = resolved
            entity_name, _, category = match
            return {
                "field": field_label, "name": name, "list": "PEP",
                "entity_name": entity_name, "source": category,
                "match_type": match_type, "score": score, "scenario_code": "SCN_PEP_MATCH",
                "severity": "MEDIUM",
            }

    for field_label, name in for_screening:
        if not name or not name.strip():
            continue
        resolved = _resolve_match(name, watch)
        if resolved:
            match, match_type, score = resolved
            entity_name, watch_reason = match
            return {
                "field": field_label, "name": name, "list": "INTERNAL_WATCHLIST",
                "entity_name": entity_name, "source": f"Internal Watchlist ({watch_reason})",
                "match_type": match_type, "score": score, "scenario_code": "SCN_INTERNAL_WATCHLIST",
                "severity": "HIGH" if watch_reason == "PRIOR_SAR" else "MEDIUM",
            }

    return None


def submit_wire_transfer(
    conn: sqlite3.Connection, account_id: str, amount: float, country: str,
    ordering_customer_name: str, beneficiary_name: str,
    originating_bank_bic: Optional[str], reference: Optional[str], company_id: str,
) -> dict:
    """The live, single-wire equivalent of the batch loader — simulates a
    teller/ops user releasing one correspondent-banking wire right now.
    Screens the account holder, ordering customer, and beneficiary names
    BEFORE the transaction is committed. A match means the wire is
    inserted with interdiction_status='BLOCKED' and an alert is raised
    immediately (same scenario codes, same queue, same workflow as
    everything else) — it does not wait for the next batch engine run.
    A clean screen inserts the transaction as interdiction_status='CLEARED'
    and it behaves like any other posted transaction from then on.

    Returns a dict describing the outcome for the calling route to render:
    {"blocked": bool, "transaction_id": str, "match": dict|None, "alert_id": str|None}
    """
    customer = conn.execute(
        "SELECT customer_name, account_category FROM customer_profiles WHERE account_id = ? AND company_id = ?",
        (account_id, company_id),
    ).fetchone()
    if customer is None:
        raise ValueError(f"No such account: {account_id}")
    customer_name, account_category = customer
    customer_name = pii_crypto.decrypt_pii(customer_name)  # Task 3: screen on cleartext
    if account_category != "CORRESPONDENT":
        raise ValueError(
            f"Account {account_id} is {account_category}, not CORRESPONDENT — pre-transaction wire "
            "interdiction only applies to correspondent-banking wire transfers (Category 3)."
        )

    candidates = [
        ("Account holder", customer_name),
        ("Ordering customer", ordering_customer_name),
        ("Beneficiary", beneficiary_name),
    ]
    match = screen_names_for_interdiction(candidates)

    now = datetime.now(timezone.utc).isoformat()
    tx_id = str(uuid.uuid4())
    tx_date = now[:19].replace("T", " ")

    if match:
        conn.execute("""
            INSERT INTO transactions
            (transaction_id, account_id, amount, country, transaction_date, loaded_at,
             ordering_customer_name, beneficiary_name, originating_bank_bic, reference,
             transaction_type, interdiction_status, interdicted_at, company_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'WIRE_TRANSFER', 'BLOCKED', ?, ?)
        """, (tx_id, account_id, amount, country, tx_date, now,
              ordering_customer_name, beneficiary_name, originating_bank_bic, reference, now, company_id))
        conn.commit()

        confidence = "" if match["match_type"] == "EXACT" else f" [{match['match_type']} match, similarity {match['score']:.0%}]"
        narrative = (
            f"WIRE BLOCKED PRE-RELEASE: {match['field']} name '{match['name']}' on wire transaction "
            f"{tx_id} (account {account_id}, AED {amount:,.2f} to/from {country}) matched "
            f"{match['list'].replace('_', ' ').title()} entry '{match['entity_name']}' "
            f"({match['source']}){confidence}. Wire held — not released."
        )
        alert_id = raise_alert(
            conn, match["scenario_code"], account_id, amount, tx_date, tx_date,
            match["severity"], narrative, [tx_id], company_id=company_id,
            match_name=match["name"], match_source=match["source"], match_field=match["field"],
            match_type=match["match_type"], match_score=match["score"],
        )
        log.info("Wire INTERDICTED: account=%s amount=%.2f matched %s (%s)",
                  account_id, amount, match["list"], match["match_type"])
        return {"blocked": True, "transaction_id": tx_id, "match": match, "alert_id": alert_id}

    conn.execute("""
        INSERT INTO transactions
        (transaction_id, account_id, amount, country, transaction_date, loaded_at,
         ordering_customer_name, beneficiary_name, originating_bank_bic, reference,
         transaction_type, interdiction_status, interdicted_at, company_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'WIRE_TRANSFER', 'CLEARED', ?, ?)
    """, (tx_id, account_id, amount, country, tx_date, now,
          ordering_customer_name, beneficiary_name, originating_bank_bic, reference, now, company_id))
    conn.commit()
    log.info("Wire CLEARED: account=%s amount=%.2f", account_id, amount)
    return {"blocked": False, "transaction_id": tx_id, "match": None, "alert_id": None}


def seed_sanctions_list(conn: sqlite3.Connection) -> int:
    """Legacy stub — sanctions data now lives in screening.db.
    Run data/sanctions_pep_seed.py to seed the screening database."""
    log.info("seed_sanctions_list: sanctions data now lives in screening.db — run sanctions_pep_seed.py.")
    return 0


# Scenario 7: SCN_DORMANT_REACTIVATION
def run_scn_dormant_reactivation(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_DORMANT_REACTIVATION as_of=%s company_id=%s", as_of_date, company_id)

    raised = suppressed = 0

    # Path 1: flat absolute threshold — unchanged from before.
    rows = conn.execute("""
        WITH last_before_gap AS (
            SELECT account_id, MAX(transaction_date) AS last_dormant_tx
            FROM transactions
            WHERE company_id = :company_id AND date(transaction_date) < date(:as_of, :gap_start)
            GROUP BY account_id
        ),
        reactivation AS (
            SELECT t.account_id, t.transaction_id, t.amount, t.transaction_date
            FROM transactions t
            WHERE t.company_id = :company_id AND t.amount >= :min_amount
              AND date(t.transaction_date) BETWEEN date(:as_of, :gap_start) AND date(:as_of)
        )
        SELECT r.account_id, r.transaction_id, r.amount, r.transaction_date, lbg.last_dormant_tx
        FROM reactivation r
        JOIN last_before_gap lbg ON lbg.account_id = r.account_id
        WHERE julianday(r.transaction_date) - julianday(lbg.last_dormant_tx) >= :gap_days
          AND NOT EXISTS (
              SELECT 1 FROM transactions mid
              WHERE mid.account_id = r.account_id AND mid.company_id = :company_id
                AND mid.transaction_date > lbg.last_dormant_tx
                AND mid.transaction_date < r.transaction_date
          )
        ORDER BY r.transaction_date DESC
    """, {
        "as_of": as_of_date,
        "company_id": company_id,
        "gap_start": f"-{DORMANT_INACTIVITY_DAYS} days",
        "gap_days": DORMANT_INACTIVITY_DAYS,
        "min_amount": DORMANT_REACT_MIN_AMOUNT,
    }).fetchall()

    for account_id, tx_id, amount, tx_date, last_dormant_tx in rows:
        gap_days = None
        try:
            gap_days = (datetime.fromisoformat(tx_date.replace(" ", "T")) -
                        datetime.fromisoformat(last_dormant_tx.replace(" ", "T"))).days
        except ValueError:
            pass
        gap_desc = f"{gap_days} days" if gap_days is not None else f"since {last_dormant_tx[:10]}"
        narrative = f"Account {account_id} was inactive for {gap_desc} then reactivated with AED {amount:,.2f}."
        aid = raise_alert(conn, "SCN_DORMANT_REACTIVATION", account_id, amount, tx_date, tx_date, "MEDIUM", narrative, [tx_id], company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1

    # Path 2 (weakness fix): relative to the account's own pre-dormancy average; `t.amount < :min_amount` keeps it mutually exclusive with path 1, so no double-counting.
    relative_rows = conn.execute("""
        WITH last_before_gap AS (
            SELECT account_id, MAX(transaction_date) AS last_dormant_tx
            FROM transactions
            WHERE company_id = :company_id AND date(transaction_date) < date(:as_of, :gap_start)
            GROUP BY account_id
        ),
        own_history AS (
            SELECT t.account_id, AVG(t.amount) AS avg_amount
            FROM transactions t
            JOIN last_before_gap lbg ON lbg.account_id = t.account_id
            WHERE t.company_id = :company_id
              AND date(t.transaction_date) BETWEEN date(lbg.last_dormant_tx, :lookback_start) AND lbg.last_dormant_tx
            GROUP BY t.account_id
        ),
        reactivation AS (
            SELECT t.account_id, t.transaction_id, t.amount, t.transaction_date
            FROM transactions t
            WHERE t.company_id = :company_id AND t.amount < :min_amount
              AND date(t.transaction_date) BETWEEN date(:as_of, :gap_start) AND date(:as_of)
        )
        SELECT r.account_id, r.transaction_id, r.amount, r.transaction_date, lbg.last_dormant_tx, oh.avg_amount
        FROM reactivation r
        JOIN last_before_gap lbg ON lbg.account_id = r.account_id
        JOIN own_history oh ON oh.account_id = r.account_id
        WHERE julianday(r.transaction_date) - julianday(lbg.last_dormant_tx) >= :gap_days
          AND oh.avg_amount > 0
          AND r.amount >= oh.avg_amount * :relative_multiplier
          AND NOT EXISTS (
              SELECT 1 FROM transactions mid
              WHERE mid.account_id = r.account_id AND mid.company_id = :company_id
                AND mid.transaction_date > lbg.last_dormant_tx
                AND mid.transaction_date < r.transaction_date
          )
        ORDER BY r.transaction_date DESC
    """, {
        "as_of": as_of_date,
        "company_id": company_id,
        "gap_start": f"-{DORMANT_INACTIVITY_DAYS} days",
        "gap_days": DORMANT_INACTIVITY_DAYS,
        "min_amount": DORMANT_REACT_MIN_AMOUNT,
        "lookback_start": f"-{DORMANT_REACT_HISTORY_LOOKBACK_DAYS} days",
        "relative_multiplier": DORMANT_REACT_RELATIVE_MULTIPLIER,
    }).fetchall()

    for account_id, tx_id, amount, tx_date, last_dormant_tx, avg_amount in relative_rows:
        gap_days = None
        try:
            gap_days = (datetime.fromisoformat(tx_date.replace(" ", "T")) -
                        datetime.fromisoformat(last_dormant_tx.replace(" ", "T"))).days
        except ValueError:
            pass
        gap_desc = f"{gap_days} days" if gap_days is not None else f"since {last_dormant_tx[:10]}"
        ratio = amount / avg_amount
        narrative = (f"Account {account_id} was inactive for {gap_desc} then reactivated with AED {amount:,.2f} — "
                     f"{ratio:.1f}x its own AED {avg_amount:,.2f} average transaction size before going dormant. "
                     f"Below the flat AED {DORMANT_REACT_MIN_AMOUNT:,.0f} threshold, but unusual relative to this account's own history.")
        aid = raise_alert(conn, "SCN_DORMANT_REACTIVATION", account_id, amount, tx_date, tx_date, "MEDIUM", narrative, [tx_id], company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1

    return raised, suppressed


# Scenario 8: SCN_RAPID_LAYERING
def run_scn_rapid_layering(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_RAPID_LAYERING as_of=%s company_id=%s", as_of_date, company_id)
    rows = conn.execute("""
        SELECT account_id, transaction_id, amount, transaction_date
        FROM transactions
        WHERE company_id = :company_id AND date(transaction_date) <= date(:as_of)
        ORDER BY account_id, transaction_date
    """, {"as_of": as_of_date, "company_id": company_id}).fetchall()

    by_account: dict[str, list] = {}
    for account_id, tx_id, amount, tx_date in rows:
        by_account.setdefault(account_id, []).append((tx_id, amount, tx_date))

    raised = suppressed = 0
    window = timedelta(hours=RAPID_LAYERING_WINDOW_HRS)

    for account_id, txs in by_account.items():
        n = len(txs)
        i = 0
        while i < n:
            window_start = datetime.fromisoformat(txs[i][2].replace(" ", "T"))
            cluster = [txs[i]]
            j = i + 1
            while j < n:
                tx_time = datetime.fromisoformat(txs[j][2].replace(" ", "T"))
                if tx_time - window_start <= window:
                    cluster.append(txs[j])
                    j += 1
                else:
                    break

            total = sum(t[1] for t in cluster)
            if len(cluster) >= RAPID_LAYERING_MIN_LEGS and total >= RAPID_LAYERING_MIN_VOLUME:
                tx_ids = [t[0] for t in cluster]
                p_start, p_end = cluster[0][2], cluster[-1][2]
                narrative = (f"Account {account_id} moved AED {total:,.2f} across {len(cluster)} transactions "
                             f"within a {RAPID_LAYERING_WINDOW_HRS}-hour window, consistent with rapid layering.")
                severity = "HIGH" if len(cluster) >= RAPID_LAYERING_MIN_LEGS * 2 else "MEDIUM"
                aid = raise_alert(conn, "SCN_RAPID_LAYERING", account_id, total, p_start, p_end, severity, narrative, tx_ids, company_id=company_id)
                if aid:
                    raised += 1
                else:
                    suppressed += 1
                i = j
            else:
                i += 1

    return raised, suppressed


# Scenario 9: SCN_MULTI_ACCOUNT_STRUCTURING
def run_scn_multi_account_structuring(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_MULTI_ACCOUNT_STRUCTURING as_of=%s company_id=%s", as_of_date, company_id)
    # Cash-channel only (as SCN_STRUCTURING_CASH) — smurfing is coordinated CASH placement across accounts.
    rows = conn.execute(f"""
        SELECT transaction_id, account_id, amount, transaction_date
        FROM transactions
        WHERE company_id = :company_id AND amount BETWEEN :low AND :high
          AND {CASH_TYPE_SQL_PREDICATE}
          AND date(transaction_date) BETWEEN date(:as_of, :window) AND date(:as_of)
        ORDER BY transaction_date
    """, {
        "low": SMURFING_BAND_LOW, "high": SMURFING_BAND_HIGH, "company_id": company_id,
        "as_of": as_of_date, "window": f"-{SMURFING_WINDOW_DAYS} days",
    }).fetchall()

    if not rows:
        return 0, 0

    window = timedelta(days=SMURFING_WINDOW_DAYS)
    rows_sorted = sorted(rows, key=lambda r: r[3])
    raised = suppressed = 0
    i = 0
    n = len(rows_sorted)

    while i < n:
        window_start = datetime.fromisoformat(rows_sorted[i][3].replace(" ", "T"))
        cluster = [rows_sorted[i]]
        j = i + 1
        while j < n:
            tx_time = datetime.fromisoformat(rows_sorted[j][3].replace(" ", "T"))
            if tx_time - window_start <= window:
                cluster.append(rows_sorted[j])
                j += 1
            else:
                break

        accounts_in_cluster = sorted({r[1] for r in cluster})
        if len(accounts_in_cluster) >= SMURFING_MIN_ACCOUNTS:
            p_start, p_end = cluster[0][3], cluster[-1][3]
            total = sum(r[2] for r in cluster)
            other_accounts_desc = ", ".join(accounts_in_cluster)
            for acct in accounts_in_cluster:
                acct_tx_ids = [r[0] for r in cluster if r[1] == acct]
                narrative = (f"Account {acct} transacted in the just-below-threshold band alongside "
                             f"{len(accounts_in_cluster) - 1} other account(s) ({other_accounts_desc}) "
                             f"within a {SMURFING_WINDOW_DAYS}-day window — possible coordinated structuring.")
                aid = raise_alert(conn, "SCN_MULTI_ACCOUNT_STRUCTURING", acct, total, p_start, p_end, "HIGH", narrative, acct_tx_ids, company_id=company_id)
                if aid:
                    raised += 1
                else:
                    suppressed += 1
            i = j
        else:
            i += 1

    return raised, suppressed


# Scenario 10: SCN_CROSS_BORDER_ANOMALY
def run_scn_cross_border_anomaly(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> Tuple[int, int]:
    log.info("Running SCN_CROSS_BORDER_ANOMALY as_of=%s company_id=%s", as_of_date, company_id)
    rows = conn.execute("""
        SELECT account_id, COUNT(DISTINCT country) AS n_countries,
               GROUP_CONCAT(DISTINCT country) AS countries,
               SUM(amount) AS total, MIN(transaction_date) AS p_start,
               MAX(transaction_date) AS p_end, GROUP_CONCAT(transaction_id) AS tx_ids
        FROM transactions
        WHERE company_id = :company_id AND date(transaction_date) BETWEEN date(:as_of, :window) AND date(:as_of)
        GROUP BY account_id
        HAVING COUNT(DISTINCT country) >= :min_countries
    """, {"as_of": as_of_date, "company_id": company_id, "window": f"-{CROSS_BORDER_WINDOW_DAYS} days",
          "min_countries": CROSS_BORDER_MIN_COUNTRIES}).fetchall()

    raised = suppressed = 0
    for account_id, n_countries, countries, total, p_start, p_end, tx_ids_str in rows:
        tx_ids = tx_ids_str.split(",") if tx_ids_str else []
        narrative = f"Account {account_id} transacted across {n_countries} distinct countries ({countries}) within {CROSS_BORDER_WINDOW_DAYS} days."
        severity = "HIGH" if n_countries >= CROSS_BORDER_MIN_COUNTRIES + 2 else "MEDIUM"
        aid = raise_alert(conn, "SCN_CROSS_BORDER_ANOMALY", account_id, float(n_countries), p_start, p_end, severity, narrative, tx_ids, company_id=company_id)
        if aid:
            raised += 1
        else:
            suppressed += 1
    return raised, suppressed


# Item 3: dynamic customer risk re-rating from post-onboarding events (alerts/SARs); escalates only, never auto-downgrades — de-risking is a deliberate human decision.
RERATE_HIGH_OPEN_ALERT_COUNT = 3   # 3+ open alerts of any kind -> at least MEDIUM
RERATE_HIGH_SCREENING_HIT = True   # any open SCN_SANCTION_MATCH/PEP_MATCH/WATCHLIST -> HIGH


def recalculate_customer_risk_ratings(conn: sqlite3.Connection, company_id: str) -> int:
    """Re-evaluates every customer's risk_rating against their actual
    alert/SAR/screening history and bumps it upward where warranted.
    Returns the number of customers actually changed. Called at the end
    of every run_engine() pass, so CRR reflects the alerts just raised
    in that same run, not a stale prior-run snapshot.

    Also enforces the EDD flag's regulatory floor: a PEP (FATF R.12 /
    Art. 15, Cabinet Decision 10/2019 — mandatory EDD) or a customer
    whose rating lands at HIGH (enhanced measures under the risk-based
    approach) must never show edd_required=0. Same one-way rule as the
    rating itself: this sets the flag, never clears it — removing EDD is
    a deliberate human decision, and an existing edd_reason (e.g. 'Prior
    SAR filed ...') is left untouched."""
    customers = conn.execute(
        "SELECT account_id, risk_rating, is_pep, edd_required FROM customer_profiles WHERE company_id = ?",
        (company_id,),
    ).fetchall()

    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    changed = 0
    edd_flagged = 0

    for account_id, current_rating, is_pep, edd_required in customers:
        open_alert_count = conn.execute("""
            SELECT COUNT(*) FROM aml_alerts
            WHERE account_id = ? AND company_id = ? AND status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'DRAFT_SAR')
        """, (account_id, company_id)).fetchone()[0]

        sar_count = conn.execute("""
            WITH latest AS (
                SELECT sd.* FROM str_decisions sd
                INNER JOIN (SELECT alert_id, MAX(decision_id) AS m FROM str_decisions GROUP BY alert_id) x
                ON x.alert_id = sd.alert_id AND x.m = sd.decision_id
            )
            SELECT COUNT(*) FROM latest l
            JOIN aml_alerts a ON a.alert_id = l.alert_id
            WHERE a.account_id = ? AND a.company_id = ? AND l.workflow_status = 'CLOSED_SAR'
        """, (account_id, company_id)).fetchone()[0]

        screening_hit = conn.execute("""
            SELECT 1 FROM aml_alerts
            WHERE account_id = ? AND company_id = ? AND status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'DRAFT_SAR')
              AND scenario_code IN ('SCN_SANCTION_MATCH', 'SCN_PEP_MATCH', 'SCN_INTERNAL_WATCHLIST')
            LIMIT 1
        """, (account_id, company_id)).fetchone() is not None

        # Determine the rating the customer's current facts justify, independent of today's rating.
        if sar_count > 0:
            justified, reason = "HIGH", f"{sar_count} SAR(s) filed against this customer"
        elif screening_hit and RERATE_HIGH_SCREENING_HIT:
            justified, reason = "HIGH", "Open sanctions/PEP/internal-watchlist match on this account"
        elif edd_required:
            justified, reason = "HIGH", "Customer is under Enhanced Due Diligence"
        elif is_pep:
            justified, reason = "MEDIUM", "Customer is a Politically Exposed Person"
        elif open_alert_count >= RERATE_HIGH_OPEN_ALERT_COUNT:
            justified, reason = "MEDIUM", f"{open_alert_count} open alerts on this account"
        else:
            justified, reason = current_rating, None  # nothing to escalate to

        if reason and rank.get(justified, 0) > rank.get(current_rating, 0):
            conn.execute("""
                UPDATE customer_profiles
                SET risk_rating = ?, risk_rating_date = ?,
                    risk_rating_reason = ?
                WHERE account_id = ? AND company_id = ?
            """, (justified, now_date,
                  f"Auto re-rated from {current_rating} to {justified}: {reason}.", account_id, company_id))
            changed += 1
            final_rating = justified
        else:
            final_rating = current_rating

        # EDD floor (see docstring): a PEP or HIGH rating without the flag is a contradiction the register must never show.
        if not edd_required and (is_pep or final_rating == "HIGH"):
            edd_reason = (
                "PEP status — enhanced due diligence mandatory (FATF R.12 / Art. 15, Cabinet Decision 10/2019)"
                if is_pep else
                "HIGH customer risk rating — enhanced due diligence under the risk-based approach"
            )
            conn.execute("""
                UPDATE customer_profiles SET edd_required = 1, edd_reason = ?
                WHERE account_id = ? AND company_id = ?
            """, (edd_reason, account_id, company_id))
            edd_flagged += 1

    if changed or edd_flagged:
        conn.commit()
        log.info("Customer risk re-rating: %d customer(s) escalated, %d flagged for EDD.",
                 changed, edd_flagged)
    return changed


# Item 5: mandatory CTRs — a non-discretionary obligation to report cash above a statutory threshold (unlike a SAR's judgment call), so it just gets filed into its own ctr_filings table, never the alert workflow.
CTR_SINGLE_DAY_THRESHOLD = 40_000  # AED, deliberately distinct from the
                                    # CTR is a same-day trigger, not the 6-month CASH_AGG_6M rolling window


def run_ctr_threshold_filings(conn: sqlite3.Connection, as_of_date: str, company_id: str) -> int:
    """Finds every account/day combination where same-day transaction
    volume crosses CTR_SINGLE_DAY_THRESHOLD and auto-files a CTR record
    for it. Idempotent — re-running skips account/day pairs already
    filed, so this is safe to call on every engine run.

    Scans every day up to and including as_of_date, not just the literal
    calendar day equal to as_of — consistent with how every other
    scenario in this file treats as_of as a cutoff (`date(...) <= date(:as_of)`),
    not a single-day equality filter. A real production deployment runs
    this as a daily job against that day's live postings, so in practice
    it would only ever see "today"; this demo replays a full year of
    backdated transactions in one go, so scanning the whole history up to
    as_of is what makes a freshly-loaded backlog get its overdue CTRs
    filed correctly, the same way a new system catching up on historical
    data would."""
    # A CTR triggers on same-day physical cash, not total throughput — the NULL-tolerant cash predicate stops filings off wire/crypto activity no CTR regime covers.
    rows = conn.execute(f"""
        SELECT account_id, date(transaction_date) AS tx_day,
               SUM(amount) AS day_total, GROUP_CONCAT(transaction_id) AS tx_ids,
               COUNT(*) AS tx_count
        FROM transactions
        WHERE company_id = ? AND date(transaction_date) <= date(?)
          AND {CASH_TYPE_SQL_PREDICATE}
        GROUP BY account_id, date(transaction_date)
        HAVING SUM(amount) >= ?
    """, (company_id, as_of_date, CTR_SINGLE_DAY_THRESHOLD)).fetchall()

    filed = 0
    now = datetime.now(timezone.utc).isoformat()
    for account_id, tx_day, day_total, tx_ids_str, tx_count in rows:
        existing = conn.execute(
            "SELECT 1 FROM ctr_filings WHERE account_id = ? AND filing_date = ? AND company_id = ? LIMIT 1",
            (account_id, tx_day, company_id),
        ).fetchone()
        if existing:
            continue
        ctr_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO ctr_filings
            (ctr_id, account_id, filing_date, total_amount, transaction_count,
             transaction_ids, threshold_applied, created_at, company_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ctr_id, account_id, tx_day, round(day_total, 2), tx_count,
              tx_ids_str, CTR_SINGLE_DAY_THRESHOLD, now, company_id))
        filed += 1

    if filed:
        conn.commit()
        log.info("CTR filings: %d new mandatory report(s) auto-filed for %s.", filed, as_of_date)
    return filed



SCENARIOS = {
    "SCN_CASH_AGG_6M":               run_scn_cash_agg_6m,
    "SCN_STRUCTURING_CASH":          run_scn_structuring_cash,
    "SCN_HIGH_RISK_JURISDICTION":    run_scn_high_risk_jurisdiction,
    "SCN_BEHAVIOUR_CHANGE":          run_scn_behaviour_change,
    "SCN_PEP_EXPOSURE":              run_scn_pep_exposure,
    "SCN_SANCTION_MATCH":            run_scn_sanction_match,
    "SCN_PEP_MATCH":                 run_scn_pep_match,
    "SCN_INTERNAL_WATCHLIST":        run_scn_internal_watchlist_match,
    "SCN_DORMANT_REACTIVATION":      run_scn_dormant_reactivation,
    "SCN_RAPID_LAYERING":            run_scn_rapid_layering,
    "SCN_MULTI_ACCOUNT_STRUCTURING": run_scn_multi_account_structuring,
    "SCN_CROSS_BORDER_ANOMALY":      run_scn_cross_border_anomaly,
}


def run_engine(company_id: str = auth_security.LEGACY_COMPANY_ID, as_of_date: str | None = None) -> None:
    as_of = as_of_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_id = str(uuid.uuid4())
    total_new = total_suppressed = 0
    executed = []
    engine_status = "COMPLETED"
    # Task 2: start each run with a clean per-record error tally (raise_alert bumps it via _note_errored_record).
    _reset_errored_records()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        init_schema(conn)
        active = {r[0] for r in conn.execute("SELECT scenario_code FROM aml_scenarios WHERE is_active = 1").fetchall()}

        for code, fn in SCENARIOS.items():
            if code not in active:
                continue
            try:
                new, suppressed = fn(conn, as_of, company_id)
                total_new += new
                total_suppressed += suppressed
                executed.append(code)
            except Exception:
                log.exception("Scenario %s failed", code)
                engine_status = "PARTIAL"

        # Item 3: re-rate customers on this run's alerts/SARs (see recalculate_customer_risk_ratings), not a stale onboarding snapshot.
        try:
            recalculate_customer_risk_ratings(conn, company_id)
        except Exception:
            log.exception("Customer risk re-rating failed")

        # Item 5: auto-filed CTRs, run after the scenario loop so they see the same as_of_date transaction set.
        try:
            run_ctr_threshold_filings(conn, as_of, company_id)
        except Exception:
            log.exception("CTR threshold filing failed")

        # Item 16: refresh SLA breach flags after every run so the dashboard reflects newly-breached alerts immediately.
        try:
            refresh_sla_breach_flags(conn)
        except Exception:
            log.exception("SLA breach refresh failed")

        # Task 2: any skipped records mark the run PARTIAL (not a falsely-clean COMPLETED) even if every scenario returned cleanly.
        errored_records = get_errored_records_count()
        if errored_records > 0 and engine_status == "COMPLETED":
            engine_status = "PARTIAL"

        conn.execute("""
            INSERT INTO aml_engine_runs
            (run_id, run_at, scenarios_executed, alerts_generated, alerts_suppressed,
             status, company_id, errored_records_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, datetime.now(timezone.utc).isoformat(), ",".join(executed),
              total_new, total_suppressed, engine_status, company_id, errored_records))
        conn.commit()
        if errored_records:
            log.warning("Engine run %s completed as PARTIAL: %d record(s) errored and were skipped.",
                        run_id, errored_records)

        # NOTE: a workflow self-test that mutated live alert state on every pipeline run was removed — transitions are covered by the test suite against a throwaway DB.


if __name__ == "__main__":
    import sys
    # Load .env for direct terminal runs so screening decryption uses the same PII key the web app encrypted with (see generator.py).
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    cli_company_id = sys.argv[1] if len(sys.argv) > 1 else auth_security.LEGACY_COMPANY_ID
    cli_as_of = sys.argv[2] if len(sys.argv) > 2 else None
    run_engine(cli_company_id, cli_as_of)