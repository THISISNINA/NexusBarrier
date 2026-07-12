import csv
import logging
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

import pii_crypto

# Configuration
DB_PATH        = Path("data/database/aml_monitoring.db")
INCOMING_DIR   = Path("data/incoming")
PROCESSED_DIR  = Path("data/processed")
REQUIRED_FIELDS = {"transaction_id", "account_id", "amount", "country", "transaction_date"}
# Item 12: optional wire/channel/routing metadata — older CSVs load without them, but when present they feed screening, cash-channel discrimination, and per-hop jurisdiction checks (intermediary_countries is a pipe-separated path, e.g. "AE|MM|SG").
OPTIONAL_FIELDS = (
    "counterparty_name", "reference",
    "ordering_customer_name", "beneficiary_name", "originating_bank_bic",
    "transaction_type", "counterparty_type",
    "counterparty_wallet_address", "intermediary_countries",
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler("logs/aml_loader.log"), logging.StreamHandler()],
)
log = logging.getLogger(__name__)


# Database bootstrap
def init_db(conn: sqlite3.Connection) -> None:
    # Build aml_engine's schema first so `transactions` isn't race-created by a bare CREATE TABLE missing company_id.
    import aml_engine
    aml_engine.init_schema(conn)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id   TEXT PRIMARY KEY,   -- enforces idempotency at DB level
            account_id       TEXT    NOT NULL,
            amount           REAL    NOT NULL,
            country          TEXT    NOT NULL,
            transaction_date TEXT    NOT NULL,
            loaded_at        TEXT    NOT NULL,    -- audit: when this row was ingested
            counterparty_name      TEXT,          -- item 12: who the money went to/came from
            reference               TEXT,          -- item 12: payment purpose/memo
            ordering_customer_name  TEXT,          -- item 12: CORRESPONDENT wire ordering party
            beneficiary_name        TEXT,          -- item 12: CORRESPONDENT wire beneficiary
            originating_bank_bic    TEXT,          -- item 12: BIC of the sending bank
            transaction_type        TEXT,          -- channel: CASH_DEPOSIT/CASH_WITHDRAWAL/WIRE_TRANSFER/CRYPTO/SALARY/RETAIL
            counterparty_type       TEXT,          -- BANK/CORPORATE/MERCHANT/EMPLOYER/VASP
            counterparty_wallet_address TEXT,      -- virtual-asset wallet on CRYPTO legs
            intermediary_countries  TEXT           -- pipe-separated routing path, e.g. "AE|MM|SG"
        )
    """)
    # Additive migration guard (mirrors aml_engine._add_column_if_missing) so pre-item-12 DBs pick up new columns.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(transactions)").fetchall()}
    for col in OPTIONAL_FIELDS:
        if col not in existing:
            conn.execute(f"ALTER TABLE transactions ADD COLUMN {col} TEXT")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ingestion_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name     TEXT    NOT NULL,
            ingested_at   TEXT    NOT NULL,
            rows_accepted INTEGER NOT NULL,
            rows_skipped  INTEGER NOT NULL,
            status        TEXT    NOT NULL        -- COMPLETED | PARTIAL | FAILED
        )
    """)
    conn.commit()
    # transactions now exists — backfill company_id/interdiction_status that the earlier init_schema() couldn't reach.
    aml_engine._apply_additive_migrations(conn)


# Row validation
def validate_row(row: dict) -> tuple[bool, str]:
    if not REQUIRED_FIELDS.issubset(row.keys()):
        return False, f"Missing fields: {REQUIRED_FIELDS - row.keys()}"
    try:
        amount = float(row["amount"])
        if amount <= 0:
            return False, f"Non-positive amount: {row['amount']}"
    except ValueError:
        return False, f"Invalid amount: {row['amount']}"
    try:
        datetime.strptime(row["transaction_date"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False, f"Invalid date format: {row['transaction_date']}"
    if not row["transaction_id"].strip() or not row["account_id"].strip():
        return False, "Blank transaction_id or account_id"
    return True, ""


# Single-file loader
def load_file(conn: sqlite3.Connection, filepath: Path, company_id: str) -> tuple[int, int]:
    accepted = skipped = 0
    loaded_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for line_num, row in enumerate(reader, start=2):   # line 1 = header
            valid, reason = validate_row(row)
            if not valid:
                log.warning("  SKIP  line %-4d  %s  (%s)", line_num, filepath.name, reason)
                skipped += 1
                continue
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO transactions
                        (transaction_id, account_id, amount, country, transaction_date, loaded_at,
                         counterparty_name, reference, ordering_customer_name,
                         beneficiary_name, originating_bank_bic,
                         transaction_type, counterparty_type,
                         counterparty_wallet_address, intermediary_countries, company_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["transaction_id"].strip(),
                        row["account_id"].strip(),
                        float(row["amount"]),
                        row["country"].strip(),
                        row["transaction_date"].strip(),
                        loaded_at,
                        (row.get("counterparty_name") or "").strip() or None,
                        (row.get("reference") or "").strip() or None,
                        (row.get("ordering_customer_name") or "").strip() or None,
                        (row.get("beneficiary_name") or "").strip() or None,
                        (row.get("originating_bank_bic") or "").strip() or None,
                        (row.get("transaction_type") or "").strip().upper() or None,
                        (row.get("counterparty_type") or "").strip().upper() or None,
                        # Task 3: wallet addresses are PII — encrypt before the row lands in the DB (NULL-safe).
                        pii_crypto.encrypt_pii((row.get("counterparty_wallet_address") or "").strip() or None),
                        (row.get("intermediary_countries") or "").strip().upper() or None,
                        company_id,
                    ),
                )
                # rowcount == 0 means transaction_id already existed → duplicate silently ignored
                accepted += conn.total_changes > 0 and 1 or 0
            except sqlite3.Error as exc:
                log.error("  DB ERROR  line %d  %s  → %s", line_num, filepath.name, exc)
                skipped += 1

    conn.commit()
    return accepted, skipped


# Orchestrator
def run_ingestion(company_id: str) -> None:
    """Ingests every CSV currently sitting in data/incoming, tagging every
    row accepted this run with company_id — one company_id per import run
    (per-row company tagging would need it as a CSV column instead, which
    isn't how any real bank's file drop works: the file transfer itself
    identifies who it's from).

    Relies on app.py's /run-pipeline having a single global "one pipeline
    run at a time" lock (see _pipeline_state), so generator.py's
    freshly-written file for THIS company_id is the only thing normally
    pending here — a crashed prior run leaving another company's file
    behind is the one scenario that would misattribute rows, and isn't
    guarded against beyond that lock.
    """
    INCOMING_DIR.mkdir(exist_ok=True)
    PROCESSED_DIR.mkdir(exist_ok=True)

    csv_files = sorted(INCOMING_DIR.glob("*.csv"))
    if not csv_files:
        log.info("No CSV files found in %s — nothing to do.", INCOMING_DIR)
        return

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent readers
        init_db(conn)

        for filepath in csv_files:
            log.info("Processing  %s for company_id=%s", filepath.name, company_id)
            status = "COMPLETED"
            try:
                accepted, skipped = load_file(conn, filepath, company_id)
                if skipped > 0 and accepted == 0:
                    status = "FAILED"
                elif skipped > 0:
                    status = "PARTIAL"
                log.info("  ✓  accepted=%d  skipped=%d  status=%s", accepted, skipped, status)
            except Exception as exc:
                log.exception("  Fatal error reading %s: %s", filepath.name, exc)
                accepted, skipped, status = 0, 0, "FAILED"

            # Audit record
            conn.execute(
                """
                INSERT INTO ingestion_log (file_name, ingested_at, rows_accepted, rows_skipped, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (filepath.name, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                 accepted, skipped, status),
            )
            conn.commit()

            # Archive the file regardless of outcome (prevents re-processing loops)
            dest = PROCESSED_DIR / filepath.name
            if dest.exists():                        # guard against name collision
                dest = PROCESSED_DIR / f"{filepath.stem}_{datetime.utcnow():%H%M%S}.csv"
            shutil.move(str(filepath), dest)
            log.info("  Archived → %s", dest)

    log.info("Ingestion run complete.")


# Entry point
if __name__ == "__main__":
    import sys
    import auth_security
    # Load .env for direct terminal runs so the PII key matches the web app's (see generator.py).
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    cli_company_id = sys.argv[1] if len(sys.argv) > 1 else auth_security.LEGACY_COMPANY_ID
    run_ingestion(cli_company_id)