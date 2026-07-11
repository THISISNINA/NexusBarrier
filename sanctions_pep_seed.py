"""
sanctions_pep_seed.py
Creates and seeds the separate screening.db database with:
  - sanctions_list   : 50+ fictional sanctioned individuals and entities
  - pep_list         : 30+ fictional politically exposed persons
  - internal_watchlist: 15+ fictional internally flagged customers

This file is INTENTIONALLY separate from aml_monitoring.db.
In real life, sanctions and PEP lists are maintained by external regulators
(OFAC, UN, EU, CBUAE) and updated independently of the bank's own systems.

Run this BEFORE running generator.py / aml_loader.py / aml_engine.py:
    python sanctions_pep_seed.py [company_id]

sanctions_list and pep_list are global regulator data. internal_watchlist
is each bank's own list (tenant-scoped by company_id), so its demo entries
are seeded per company — pass the workspace's company_id or the entries
land under the legacy demo company and SCN_INTERNAL_WATCHLIST never fires
for real tenants.

Safe to re-run — checks COUNT(*) before inserting (idempotent).

NOTE: All names, countries, and entities are completely fictional.
      No real persons, companies, or countries are referenced.
"""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from auth_security import LEGACY_COMPANY_ID

SCREENING_DB_PATH = Path("data/database/screening.db")


def get_conn() -> sqlite3.Connection:
    SCREENING_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SCREENING_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sanctions_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            list_source TEXT NOT NULL,      -- e.g. 'OFAC_DEMO', 'UN_DEMO', 'EU_DEMO', 'CBUAE_DEMO'
            entity_type TEXT NOT NULL,      -- 'INDIVIDUAL' or 'ENTITY'
            country TEXT,                   -- fictional country name
            added_date TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS pep_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            pep_category TEXT NOT NULL,     -- 'HEAD_OF_STATE','MINISTER','JUDGE','SOE_DIRECTOR'
            country TEXT,
            start_date TEXT,
            end_date TEXT,                  -- NULL = currently active PEP
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS internal_watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            account_id TEXT,                -- may be NULL if added by name only
            watch_reason TEXT NOT NULL,     -- 'PRIOR_SAR', 'EDD_REQUIRED', 'INTEL_SHARE'
            added_by TEXT NOT NULL,         -- analyst ID who added them
            added_date TEXT NOT NULL,
            review_date TEXT,               -- when to reassess
            is_active INTEGER NOT NULL DEFAULT 1,
            notes TEXT
        );
    """)
    # Tenant scoping for internal_watchlist — same additive migration
    # aml_engine._get_screening_conn applies, repeated here because this
    # script may run against a brand-new screening.db first.
    try:
        conn.execute(
            "ALTER TABLE internal_watchlist ADD COLUMN company_id TEXT NOT NULL "
            f"DEFAULT '{LEGACY_COMPANY_ID}'"
        )
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()


def _normalize(name: str) -> str:
    import re
    return re.sub(r"[^A-Z0-9 ]", "", name.upper()).strip()


# Sanctions list seed data
SANCTIONS_ENTRIES = [
    ("Omar Al Zaabi",            "OFAC_DEMO",  "INDIVIDUAL", "Republic of Valdoria"),
    ("Jassim Al Thani",          "OFAC_DEMO",  "INDIVIDUAL", "Republic of Valdoria"),
    ("Hamdan Al Shamsi",         "OFAC_DEMO",  "INDIVIDUAL", "Federal State of Krenovia"),
    ("Yusuf Adeyemi",            "OFAC_DEMO",  "INDIVIDUAL", "Republic of Valdoria"),
    ("Ivan Petrov",              "OFAC_DEMO",  "INDIVIDUAL", "Federal State of Krenovia"),
    ("Rashid Volkov",            "OFAC_DEMO",  "INDIVIDUAL", "Federal State of Krenovia"),
    ("Tamir Okafor",             "OFAC_DEMO",  "INDIVIDUAL", "Estoria Republic"),
    ("Nikolai Drenov",           "OFAC_DEMO",  "INDIVIDUAL", "Federal State of Krenovia"),
    ("Borislav Markov",          "OFAC_DEMO",  "INDIVIDUAL", "Morvenia Confederation"),
    ("Karim Zafar",              "OFAC_DEMO",  "INDIVIDUAL", "Republic of Valdoria"),
    ("Hassan Benali",            "UN_DEMO",    "INDIVIDUAL", "Taloria Emirate"),
    ("Amara Koné",               "UN_DEMO",    "INDIVIDUAL", "Estoria Republic"),
    ("Leila Ahmadi",             "UN_DEMO",    "INDIVIDUAL", "Republic of Valdoria"),
    ("Fatou Diallo",             "UN_DEMO",    "INDIVIDUAL", "Taloria Emirate"),
    ("Musa Conteh",              "UN_DEMO",    "INDIVIDUAL", "Estoria Republic"),
    ("Alibek Dzhaksybekov",      "UN_DEMO",    "INDIVIDUAL", "Morvenia Confederation"),
    ("Serghei Lungu",            "UN_DEMO",    "INDIVIDUAL", "Federal State of Krenovia"),
    ("Dragos Vasilescu",         "UN_DEMO",    "INDIVIDUAL", "Morvenia Confederation"),
    ("Tomas Breznik",            "UN_DEMO",    "INDIVIDUAL", "Taloria Emirate"),
    ("Vuk Stankovic",            "UN_DEMO",    "INDIVIDUAL", "Federal State of Krenovia"),
    ("Pierre Dubois",            "EU_DEMO",    "INDIVIDUAL", "Republic of Valdoria"),
    ("Elena Sorokina",           "EU_DEMO",    "INDIVIDUAL", "Federal State of Krenovia"),
    ("Olga Novikova",            "EU_DEMO",    "INDIVIDUAL", "Morvenia Confederation"),
    ("Miroslav Blazic",          "EU_DEMO",    "INDIVIDUAL", "Federal State of Krenovia"),
    ("Anastasia Voronova",       "EU_DEMO",    "INDIVIDUAL", "Republic of Valdoria"),
    ("Sultan Al Nuaimi",         "CBUAE_DEMO", "INDIVIDUAL", "Taloria Emirate"),
    ("Saeed Al Blooshi",         "CBUAE_DEMO", "INDIVIDUAL", "Republic of Valdoria"),
    ("Tariq Al Qasimi",          "CBUAE_DEMO", "INDIVIDUAL", "Taloria Emirate"),
    ("Hessa Al Suwaidi",         "CBUAE_DEMO", "INDIVIDUAL", "Republic of Valdoria"),
    ("Moza Al Mazrouei",         "CBUAE_DEMO", "INDIVIDUAL", "Taloria Emirate"),
    ("Nexum Trade Solutions FZE",       "OFAC_DEMO",  "ENTITY", "Republic of Valdoria"),
    ("Brightwall Holdings Ltd",         "OFAC_DEMO",  "ENTITY", "Federal State of Krenovia"),
    ("Irongate Capital Partners",       "OFAC_DEMO",  "ENTITY", "Republic of Valdoria"),
    ("Valdoria Export Consortium",      "OFAC_DEMO",  "ENTITY", "Republic of Valdoria"),
    ("Krenovia Resource Group LLC",     "OFAC_DEMO",  "ENTITY", "Federal State of Krenovia"),
    ("Estoria Maritime Holdings",       "UN_DEMO",    "ENTITY", "Estoria Republic"),
    ("Taloria Petroleum Ventures Ltd",  "UN_DEMO",    "ENTITY", "Taloria Emirate"),
    ("Morvenia Steel Industries Co",    "UN_DEMO",    "ENTITY", "Morvenia Confederation"),
    ("Northgate Arms Supplies FZE",     "UN_DEMO",    "ENTITY", "Republic of Valdoria"),
    ("Southern Cross Trading Co",       "UN_DEMO",    "ENTITY", "Estoria Republic"),
    ("Krenovia Finance Bridge SA",      "EU_DEMO",    "ENTITY", "Federal State of Krenovia"),
    ("Valdorian Infrastructure Corp",   "EU_DEMO",    "ENTITY", "Republic of Valdoria"),
    ("Morvenia Transport Network LLC",  "EU_DEMO",    "ENTITY", "Morvenia Confederation"),
    ("Baltic Shadow Investments Ltd",   "EU_DEMO",    "ENTITY", "Federal State of Krenovia"),
    ("Eastern Arc Commodities FZE",     "EU_DEMO",    "ENTITY", "Taloria Emirate"),
    ("Goldline Bullion Exchange LLC",   "CBUAE_DEMO", "ENTITY", "Republic of Valdoria"),
    ("Crescent Shell Trading FZE",      "CBUAE_DEMO", "ENTITY", "Taloria Emirate"),
    ("Horizon Dark Pool Finance Ltd",   "CBUAE_DEMO", "ENTITY", "Federal State of Krenovia"),
    ("Sandgate Currency Brokers Co",    "CBUAE_DEMO", "ENTITY", "Morvenia Confederation"),
    ("Miragelink Property Holdings",    "CBUAE_DEMO", "ENTITY", "Estoria Republic"),
    ("Falconcrest Trade Finance FZE",   "CBUAE_DEMO", "ENTITY", "Republic of Valdoria"),
]


# PEP list seed data
PEP_ENTRIES = [
    ("Mohammed Al Rashidi",    "HEAD_OF_STATE", "Republic of Valdoria",       "2018-03-01", None),
    ("Chidi Okafor",           "HEAD_OF_STATE", "Estoria Republic",           "2020-07-15", None),
    ("Park Jiyeon",            "HEAD_OF_STATE", "Morvenia Confederation",     "2019-11-01", None),
    ("Deepak Sharma",          "HEAD_OF_STATE", "Taloria Emirate",            "2010-01-01", "2021-06-30"),
    ("Nguyen Van Thanh",       "HEAD_OF_STATE", "Federal State of Krenovia", "2008-05-01", "2019-12-31"),
    ("Aisha Al Hamdan",        "MINISTER",      "Republic of Valdoria",       "2021-04-01", None),
    ("Reem Al Muhairi",        "MINISTER",      "Taloria Emirate",            "2022-01-15", None),
    ("Noura Al Ketbi",         "MINISTER",      "Republic of Valdoria",       "2020-09-01", None),
    ("Sunita Patel",           "MINISTER",      "Estoria Republic",           "2021-06-01", None),
    ("Li Xiaoming",            "MINISTER",      "Morvenia Confederation",     "2019-03-15", None),
    ("Carlos Mendes",          "MINISTER",      "Taloria Emirate",            "2022-08-01", None),
    ("Latifa Al Marri",        "MINISTER",      "Republic of Valdoria",       "2020-02-01", None),
    ("Rajesh Iyer",            "MINISTER",      "Federal State of Krenovia", "2012-07-01", "2020-03-31"),
    ("Anna Kowalski",          "MINISTER",      "Morvenia Confederation",     "2014-01-01", "2022-12-31"),
    ("Sofia Alves",            "MINISTER",      "Estoria Republic",           "2016-04-01", "2021-09-30"),
    ("Thomas Bergmann",        "MINISTER",      "Federal State of Krenovia", "2011-03-01", "2019-06-30"),
    ("Mariam Al Falasi",       "JUDGE",         "Republic of Valdoria",       "2017-09-01", None),
    ("Claire Fontaine",        "JUDGE",         "Taloria Emirate",            "2019-02-15", None),
    ("Sarah Whitfield",        "JUDGE",         "Estoria Republic",           "2020-07-01", None),
    ("Hana Mori",              "JUDGE",         "Morvenia Confederation",     "2013-05-01", "2023-01-31"),
    ("Wei Liang",              "JUDGE",         "Federal State of Krenovia", "2010-11-01", "2021-10-31"),
    ("Priya Nair",             "SOE_DIRECTOR",  "Taloria Emirate",            "2020-06-01", None),
    ("Arjun Mehta",            "SOE_DIRECTOR",  "Republic of Valdoria",       "2021-01-15", None),
    ("David Marsh",            "SOE_DIRECTOR",  "Estoria Republic",           "2019-08-01", None),
    ("Chen Jiaming",           "SOE_DIRECTOR",  "Morvenia Confederation",     "2022-03-01", None),
    ("Khalid Al Mansoori",     "SOE_DIRECTOR",  "Republic of Valdoria",       "2018-10-01", None),
    ("Ravi Krishnamurthy",     "SOE_DIRECTOR",  "Federal State of Krenovia", "2009-04-01", "2020-12-31"),
    ("Zara Hussain",           "SOE_DIRECTOR",  "Taloria Emirate",            "2015-07-01", "2022-06-30"),
    ("James Holloway",         "SOE_DIRECTOR",  "Estoria Republic",           "2012-01-01", "2019-03-31"),
    ("Anita Verma",            "SOE_DIRECTOR",  "Morvenia Confederation",     "2014-09-01", "2023-05-31"),
]


# Internal watchlist seed data
WATCHLIST_ENTRIES = [
    ("Fatima Bint Rashid",  None,       "PRIOR_SAR",    "MLRO_01",   "Prior SAR filed 2024-03 — structuring pattern confirmed."),
    ("Khalid Al Mansoori",  None,       "PRIOR_SAR",    "MLRO_01",   "Prior SAR filed 2023-11 — PEP high-value transactions."),
    ("Omar Al Zaabi",       None,       "PRIOR_SAR",    "MLRO_02",   "Prior SAR filed 2024-01 — sanctions name match flagged."),
    ("Arjun Mehta",         None,       "PRIOR_SAR",    "ANALYST_03","Prior SAR filed 2024-06 — rapid layering pattern."),
    ("Hana Mori",           None,       "PRIOR_SAR",    "MLRO_01",   "Prior SAR filed 2023-08 — cross-border anomaly."),
    ("Priya Nair",          None,       "EDD_REQUIRED", "ANALYST_01","SOE Director — all transactions require EDD review."),
    ("David Marsh",         None,       "EDD_REQUIRED", "ANALYST_02","High-risk jurisdiction activity — EDD mandatory."),
    ("Chen Jiaming",        None,       "EDD_REQUIRED", "MLRO_02",   "Dormant reactivation followed by large wire transfers."),
    ("Noura Al Ketbi",      None,       "EDD_REQUIRED", "ANALYST_01","Minister — elevated monitoring per internal policy."),
    ("Wei Liang",           None,       "EDD_REQUIRED", "MLRO_01",   "Former judge — connections to Krenovia flagged entities."),
    ("Ravi Krishnamurthy",  None,       "INTEL_SHARE",  "ANALYST_03","Typology intel: possible smurfing network link flagged by correspondent bank."),
    ("Sofia Alves",         None,       "INTEL_SHARE",  "ANALYST_02","Typology intel: beneficiary of flagged wire from Valdoria."),
    ("Thomas Bergmann",     None,       "INTEL_SHARE",  "MLRO_02",   "Typology intel: name appeared in Krenovia cross-border investigation."),
    ("Anita Verma",         None,       "INTEL_SHARE",  "ANALYST_01","Typology intel: linked to Morvenia Steel Industries (sanctioned entity)."),
    ("Carlos Mendes",       None,       "INTEL_SHARE",  "MLRO_01",   "Typology intel: frequent transfers to Taloria Emirate flagged accounts."),
]


def seed_sanctions(conn: sqlite3.Connection) -> int:
    count = conn.execute("SELECT COUNT(*) FROM sanctions_list").fetchone()[0]
    if count > 0:
        print(f"  sanctions_list already has {count} entries — skipping seed.")
        return 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rows = [
        (full_name, _normalize(full_name), source, entity_type, country, now)
        for full_name, source, entity_type, country in SANCTIONS_ENTRIES
    ]
    conn.executemany("""
        INSERT INTO sanctions_list
        (full_name, normalized_name, list_source, entity_type, country, added_date, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
    """, rows)
    conn.commit()
    print(f"  Seeded {len(rows)} entries into sanctions_list.")
    return len(rows)


def seed_pep(conn: sqlite3.Connection) -> int:
    count = conn.execute("SELECT COUNT(*) FROM pep_list").fetchone()[0]
    if count > 0:
        print(f"  pep_list already has {count} entries — skipping seed.")
        return 0
    rows = [
        (full_name, _normalize(full_name), category, country, start_date, end_date,
         1 if end_date is None else 0)
        for full_name, category, country, start_date, end_date in PEP_ENTRIES
    ]
    conn.executemany("""
        INSERT INTO pep_list
        (full_name, normalized_name, pep_category, country, start_date, end_date, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    print(f"  Seeded {len(rows)} entries into pep_list.")
    return len(rows)


def seed_internal_watchlist(conn: sqlite3.Connection, company_id: str) -> int:
    count = conn.execute(
        "SELECT COUNT(*) FROM internal_watchlist WHERE company_id = ?", (company_id,)
    ).fetchone()[0]
    if count > 0:
        print(f"  internal_watchlist already has {count} entries for {company_id} — skipping seed.")
        return 0
    now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    review_year = datetime.now(timezone.utc).year + 1
    review_date = f"{review_year}-01-01"
    rows = [
        (full_name, _normalize(full_name), account_id, reason, added_by,
         now_date, review_date, 1, notes)
        for full_name, account_id, reason, added_by, notes in WATCHLIST_ENTRIES
    ]
    conn.executemany("""
        INSERT INTO internal_watchlist
        (full_name, normalized_name, account_id, watch_reason, added_by,
         added_date, review_date, is_active, notes, company_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [row + (company_id,) for row in rows])
    conn.commit()
    print(f"  Seeded {len(rows)} entries into internal_watchlist for {company_id}.")
    return len(rows)


def print_summary(conn: sqlite3.Connection) -> None:
    print("\n── Screening DB Summary ─────────────────────────────")
    print(f"  sanctions_list   : {conn.execute('SELECT COUNT(*) FROM sanctions_list').fetchone()[0]} entries")
    by_source = conn.execute(
        "SELECT list_source, COUNT(*) FROM sanctions_list GROUP BY list_source ORDER BY list_source"
    ).fetchall()
    for source, cnt in by_source:
        print(f"    [{source}] {cnt}")
    print(f"  pep_list         : {conn.execute('SELECT COUNT(*) FROM pep_list').fetchone()[0]} entries")
    active_pep = conn.execute("SELECT COUNT(*) FROM pep_list WHERE is_active = 1").fetchone()[0]
    print(f"    Active PEPs: {active_pep}")
    print(f"  internal_watchlist: {conn.execute('SELECT COUNT(*) FROM internal_watchlist').fetchone()[0]} entries")
    by_reason = conn.execute(
        "SELECT watch_reason, COUNT(*) FROM internal_watchlist GROUP BY watch_reason ORDER BY watch_reason"
    ).fetchall()
    for reason, cnt in by_reason:
        print(f"    [{reason}] {cnt}")
    print("─────────────────────────────────────────────────────\n")


def main(company_id: str = LEGACY_COMPANY_ID) -> None:
    print(f"\nSeeding screening.db at: {SCREENING_DB_PATH.resolve()}")
    conn = get_conn()
    create_tables(conn)
    seed_sanctions(conn)
    seed_pep(conn)
    seed_internal_watchlist(conn, company_id)
    print_summary(conn)
    conn.close()
    print("Done. Run generator.py next.\n")


if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else LEGACY_COMPANY_ID)