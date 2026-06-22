import csv
import logging
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
DB_PATH        = Path("data/database/aml_monitoring.db")
INCOMING_DIR   = Path("data/incoming")
PROCESSED_DIR  = Path("data/processed")
REQUIRED_FIELDS = {"transaction_id", "account_id", "amount", "country", "transaction_date"}

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler("logs/aml_loader.log"), logging.StreamHandler()],
)
log = logging.getLogger(__name__)


# ── Database bootstrap ────────────────────────────────────────────────────────
def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id   TEXT PRIMARY KEY,   -- enforces idempotency at DB level
            account_id       TEXT    NOT NULL,
            amount           REAL    NOT NULL,
            country          TEXT    NOT NULL,
            transaction_date TEXT    NOT NULL,
            loaded_at        TEXT    NOT NULL     -- audit: when this row was ingested
        )
    """)
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


# ── Row validation ────────────────────────────────────────────────────────────
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


# ── Single-file loader ────────────────────────────────────────────────────────
def load_file(conn: sqlite3.Connection, filepath: Path) -> tuple[int, int]:
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
                        (transaction_id, account_id, amount, country, transaction_date, loaded_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["transaction_id"].strip(),
                        row["account_id"].strip(),
                        float(row["amount"]),
                        row["country"].strip(),
                        row["transaction_date"].strip(),
                        loaded_at,
                    ),
                )
                # rowcount == 0 means transaction_id already existed → duplicate silently ignored
                accepted += conn.total_changes > 0 and 1 or 0
            except sqlite3.Error as exc:
                log.error("  DB ERROR  line %d  %s  → %s", line_num, filepath.name, exc)
                skipped += 1

    conn.commit()
    return accepted, skipped


# ── Orchestrator ──────────────────────────────────────────────────────────────
def run_ingestion() -> None:
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
            log.info("Processing  %s", filepath.name)
            status = "COMPLETED"
            try:
                accepted, skipped = load_file(conn, filepath)
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


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_ingestion()