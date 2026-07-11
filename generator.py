"""
generator.py — Synthetic Data Generator
----------------------------------------
Owns THREE things, per the spec's execution order (item 3 must land before
everything else that depends on customer identity):

  1. customer_profiles seed data — names, account_category (RETAIL /
     CORPORATE / CORRESPONDENT), UBO names, SWIFT BIC, and initial CRR
     (risk_rating / risk_rating_date / risk_rating_reason). (Items 3, 9)
  2. transactions CSV — unchanged core fields plus counterparty_name,
     reference, and (CORRESPONDENT-only) ordering_customer_name /
     beneficiary_name / originating_bank_bic. (Item 12)
  3. Deliberate screening-list overlap concentrated on the four screening
     PERSONA accounts (exact sanctions/PEP/watchlist names from
     sanctions_pep_seed.py) so the name-match scenarios fire exactly once
     each. All BACKGROUND retail/UBO names are filtered through the
     engine's own matcher (_screen_clean) to be screening-silent — the
     practice queue stays at ~one alert per persona.

aml_engine.py no longer seeds customer_profiles from transaction account
IDs after the fact (seed_profiles_from_existing_data is now a no-op stub
kept only for backwards compatibility) — this file is the single source
of truth for who a customer is, run BEFORE aml_loader.py / aml_engine.py.
"""
import csv
import random
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

HIGH_RISK = [
    "KP", "IR", "MM", "DZ", "AO", "BO", "BG", "CM", "CI", "CD", "HT", "KE",
    "KW", "LA", "LB", "MC", "NA", "NP", "PG", "SS", "SY", "VE", "VN", "VG", "YE",
]
NORMAL = ["US", "GB", "DE", "FR", "JP", "CA", "AU", "SG", "AE"]
THRESHOLD = 10_000

DB_PATH = Path("data/database/aml_monitoring.db")
SCREENING_DB_PATH = Path("data/database/screening.db")

N_ACCOUNTS = 220  # spec requires "at least 200"

# Random background transactions on top of the persona set. Kept at 0 for a
# minimal practice dataset: the persona accounts alone (~29 transactions)
# cover all 12 detection scenarios at roughly one alert each. Raise this
# (e.g. to 5_000) for a noisy, realistic-volume demo — background amounts
# and countries are benign-only either way (see make_transaction), so extra
# volume fills the dashboards without flooding the alert queue.
N_BACKGROUND_TX = 0

_RETAIL_NAMES = [
    "Khalid Al Mansoori", "Fatima Bint Rashid", "Omar Al Zaabi", "Aisha Al Hamdan",
    "Mohammed Al Rashidi", "Noura Al Ketbi", "Sultan Al Nuaimi", "Mariam Al Falasi",
    "Priya Nair", "Arjun Mehta", "Zara Hussain", "Ravi Krishnamurthy", "Sunita Patel",
    "Deepak Sharma", "Anita Verma", "Rajesh Iyer", "James Holloway", "Claire Fontaine",
    "David Marsh", "Sarah Whitfield", "Thomas Bergmann", "Anna Kowalski", "Pierre Dubois",
    "Elena Sorokina", "Wei Liang", "Hana Mori", "Chen Jiaming", "Li Xiaoming",
    "Park Jiyeon", "Nguyen Van Thanh", "Fatou Diallo", "Amara Koné", "Yusuf Adeyemi",
    "Chidi Okafor", "Leila Ahmadi", "Nadia Benlahcen", "Hassan Benali", "Samira Ouali",
    "Carlos Mendes", "Sofia Alves", "Ivan Petrov", "Olga Novikova", "Tariq Al Qasimi",
    "Reem Al Muhairi", "Hamdan Al Shamsi", "Moza Al Mazrouei", "Jassim Al Thani",
    "Latifa Al Marri", "Saeed Al Blooshi", "Hessa Al Suwaidi",
]

_CORPORATE_NAMES = [
    ("Nexus Freight LLC", ["James Holloway", "Wei Liang"]),
    ("Goldstream Trading FZE", ["Arjun Mehta", "Claire Fontaine"]),
    ("Horizon Real Estate Co", ["Khalid Al Mansoori"]),
    ("Apex Commodities DMCC", ["Chen Jiaming", "David Marsh"]),
    ("Crescent Logistics Ltd", ["Fatima Bint Rashid", "Rajesh Iyer"]),
    ("Bluewave Marine FZE", ["Sultan Al Nuaimi", "Thomas Bergmann"]),
    ("Pinnacle Investments LLC", ["Priya Nair", "Omar Al Zaabi"]),
    ("Meridian Holdings Group", ["Anna Kowalski", "Park Jiyeon"]),
    ("Starbridge Capital FZE", ["Wei Liang", "Hamdan Al Shamsi"]),
    ("Clearpath Trading Co", ["Tariq Al Qasimi", "Sofia Alves"]),
    ("Ironwood Construction LLC", ["Hassan Benali", "Ivan Petrov"]),
    ("Seagate Provisions DMCC", ["Ravi Krishnamurthy", "Hana Mori"]),
    ("Falconridge Properties LLC", ["Mohammed Al Rashidi"]),
    ("Brightline Finance FZE", ["Leila Ahmadi", "Carlos Mendes"]),
    ("Sandstorm Ventures Ltd", ["Jassim Al Thani", "Nguyen Van Thanh"]),
]

_CORRESPONDENT_NAMES = [
    ("Valdoria National Bank", "VALDAABB"),
    ("Krenovia Trade Finance Bank", "KRNVAEXX"),
    ("Estoria Commercial Bank", "ESTBDEFF"),
    ("Morvenia Central Bank", "MRVNAEBB"),
    ("Taloria Merchant Bank", "TLRNBEBB"),
]

_COUNTERPARTY_COMPANIES = [
    "Stellar Freight Co", "Oasis Trading FZE", "Delta Builders LLC", "Vantage Retail Group",
    "Northwind Logistics", "Coral Bay Imports", "Skyline Furnishings LLC", "Marina Foods Co",
]
_MERCHANTS = ["Carrefour", "Lulu Hypermarket", "Amazon.ae", "Noon.com", "Talabat", "ADNOC", "Spinneys"]
_EMPLOYERS = ["Emirates Group", "DP World", "Etisalat", "ADNOC Distribution", "Majid Al Futtaim"]

_CLEAN_WIRE_POOL: list | None = None

# ── Expanded KYC identity fields (inputs to kyc_risk scoring) ─────────────
# Deterministic by account index, like the jurisdiction_flag cadence below —
# a demo reset must reproduce byte-identical profiles.
#
# Retail nationality mix skews AE/expat to mirror a UAE retail book; the
# occasional grey-list nationality (indexes that also carry the
# jurisdiction_flag) lines up with their "high-risk jurisdiction at
# onboarding" risk_rating_reason so the KYC score agrees with the CRR story.
_RETAIL_NATIONALITY_POOL = [
    "AE", "IN", "AE", "PK", "GB", "AE", "PH", "EG", "AE", "JO",
    "FR", "CN", "AE", "NG", "RU", "AE", "BR", "KR", "AE", "MA",
]
_HIGH_RISK_NATIONALITY_POOL = ["IR", "SY", "MM", "YE"]

# Corporate country of incorporation — mostly onshore UAE, with the
# jurisdiction-flagged cadence (i % 9 == 0) incorporated offshore instead,
# matching their onboarding risk reason.
_OFFSHORE_INCORPORATION_POOL = ["KY", "PA", "VG", "MT"]

# Fictional correspondent banks — country of the BIC's home market.
_CORRESPONDENT_COUNTRY = {
    "VALDAABB": "AE",
    "KRNVAEXX": "AE",
    "ESTBDEFF": "DE",
    "MRVNAEBB": "AE",
    "TLRNBEBB": "BE",
}


def _synthetic_dob(idx: int) -> str:
    """Deterministic adult date of birth from the account index alone —
    no randomness, so demo resets reproduce it."""
    year = 1958 + (idx * 7) % 42
    month = (idx % 12) + 1
    day = (idx * 5) % 28 + 1
    return f"{year:04d}-{month:02d}-{day:02d}"


# Plausible branch codes for the account-number scheme below.
_BRANCH_CODES = ["0331", "0412", "0525", "0608", "0719"]


def _account_number(idx: int) -> str:
    """Deterministic core-banking style account number
    (branch-customer serial-account type suffix, e.g. 0412-107919-01)
    from the account index alone — same reset-reproducibility contract
    as _synthetic_dob. Serials are unique per idx (7919 is prime and
    coprime with 900000, so idx→serial is injective over this range)."""
    branch = _BRANCH_CODES[idx % len(_BRANCH_CODES)]
    serial = 100000 + (idx * 7919) % 900000
    suffix = "02" if idx % 13 == 0 else "01"
    return f"{branch}-{serial:06d}-{suffix}"


def _normalize(name: str) -> str:
    import re
    return re.sub(r"[^A-Z0-9 ]", "", name.upper()).strip()


def make_transaction(tx_date, account_id=None):
    # Background transactions are deliberately BENIGN-only: everyday amounts
    # capped below the 8,500 structuring band, NORMAL countries only, no
    # high-value outliers. Suspicious patterns come exclusively from the
    # persona accounts, so raising N_BACKGROUND_TX adds dashboard volume
    # without adding alerts.
    amount = min(round(random.lognormvariate(6.5, 1.2), 2), 8_000)
    country = random.choice(NORMAL)

    return {
        "transaction_id": str(uuid.uuid4()),
        "account_id": account_id or _account_number(random.randint(700, 999)),
        "amount": amount,
        "country": country,
        "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _tx_type_for(amount: float) -> str:
    r = random.random()
    if amount < 3_000 and r < 0.3:
        return "CASH_DEPOSIT"
    if r < 0.15:
        return "SALARY"
    if r < 0.35:
        return "RETAIL"
    if r < 0.5:
        return "CRYPTO"
    return "WIRE_TRANSFER"


def _wallet_address() -> str:
    chars = "0123456789abcdef"
    return "0x" + "".join(random.choice(chars) for _ in range(4)) + "..." + "".join(random.choice(chars) for _ in range(4))


def enrich_with_counterparty_fields(tx: dict, account_category: str) -> dict:
    """Item 12: populates counterparty_name / reference, and for
    CORRESPONDENT accounts the wire-message fields (ordering_customer_name,
    beneficiary_name, originating_bank_bic) that Category 3 screening reads
    independently of the account holder's own name.

    Also populates transaction_type / counterparty_type /
    counterparty_wallet_address / intermediary_countries — the channel and
    routing metadata the engine's cash-exclusive scenarios and the
    routing-path jurisdiction check rely on. If a caller (a persona
    generator that needs a GUARANTEED channel, e.g. forcing CASH_DEPOSIT
    for the structuring/smurfing/cash-agg personas) already set
    transaction_type/reference/intermediary_countries on tx, those values
    are respected rather than overwritten — only fields still unset get a
    randomly chosen fill-in."""
    amount = tx["amount"]
    tx_type = tx.get("transaction_type") or _tx_type_for(amount)
    tx["transaction_type"] = tx_type
    tx.setdefault("intermediary_countries", None)
    tx["ordering_customer_name"] = None
    tx["beneficiary_name"] = None
    tx["originating_bank_bic"] = None
    tx["counterparty_wallet_address"] = None

    if tx_type == "CASH_DEPOSIT":
        tx["counterparty_name"] = None
        tx["counterparty_type"] = None
        tx["reference"] = tx.get("reference") or random.choice(["CASH DEP", "ATM DEPOSIT"])
    elif tx_type == "SALARY":
        tx["counterparty_name"] = tx.get("counterparty_name") or random.choice(_EMPLOYERS)
        tx["counterparty_type"] = "EMPLOYER"
        tx["reference"] = tx.get("reference") or f"SALARY {tx['transaction_date'][:7]}"
    elif tx_type == "RETAIL":
        tx["counterparty_name"] = tx.get("counterparty_name") or random.choice(_MERCHANTS)
        tx["counterparty_type"] = "MERCHANT"
        tx["reference"] = tx.get("reference") or "POS PURCHASE"
    elif tx_type == "CRYPTO":
        tx["counterparty_name"] = tx.get("counterparty_name") or _wallet_address()
        tx["counterparty_wallet_address"] = tx["counterparty_name"]
        tx["counterparty_type"] = "VASP"
        tx["reference"] = tx.get("reference") or "CRYPTO EXCHANGE"
    else:
        if account_category == "CORRESPONDENT":
            # Screening-clean pool only — the engine screens these two wire
            # fields per transaction, so a list name here would raise a
            # sanction alert per wire once background volume is enabled.
            global _CLEAN_WIRE_POOL
            if _CLEAN_WIRE_POOL is None:
                _CLEAN_WIRE_POOL = _screen_clean(_RETAIL_NAMES + [c[0] for c in _CORPORATE_NAMES])
            ordering_pool = _CLEAN_WIRE_POOL
            tx["ordering_customer_name"] = random.choice(ordering_pool)
            tx["beneficiary_name"] = random.choice(ordering_pool)
            tx["originating_bank_bic"] = random.choice([c[1] for c in _CORRESPONDENT_NAMES])
            tx["counterparty_name"] = tx["beneficiary_name"]
            tx["counterparty_type"] = "BANK"
            tx["reference"] = tx.get("reference") or f"WIRE-{random.randint(100000, 999999)}"
        else:
            tx["counterparty_name"] = tx.get("counterparty_name") or random.choice(_COUNTERPARTY_COMPANIES + _RETAIL_NAMES)
            tx["counterparty_type"] = "CORPORATE"
            tx["reference"] = tx.get("reference") or random.choice([
                f"INV-{tx['transaction_date'][:4]}-{random.randint(1000, 9999)}",
                "CONTRACT PAYMENT",
            ])
    return tx


# Persona dates must land inside each scenario's rolling detection window,
# which the engine anchors to as_of = the day the pipeline runs. Everything
# here is therefore relative to now, never a fixed calendar date — fixed
# dates silently age out of every window and the scenarios stop firing.

# Every persona below is tuned to fire EXACTLY its own scenario and nothing
# else — amounts stay out of the 8,500–9,999 structuring band unless the
# band IS the scenario, legs are spaced >72h apart unless rapid layering IS
# the scenario, countries stay NORMAL (and single) unless the scenario needs
# otherwise, and per-account 6-month sums stay under the AED 55,000 cash
# ceiling unless cash aggregation IS the scenario. That keeps the practice
# queue at roughly one alert per persona instead of a wall of cross-fires.

def persona_structuring_account(account_id, n_transactions=3):
    # SCN_STRUCTURING_CASH: 3+ band transactions in the 30-day window.
    # Days 16-26 ago: inside the 30-day structuring window but OUTSIDE the
    # 14-day smurfing window, so this account never joins a smurf cluster;
    # 4-day spacing keeps any 3 legs out of the 72-hour layering window.
    # transaction_type is forced to CASH_DEPOSIT — the scenario is
    # cash-exclusive (see aml_engine.CASH_TYPE_SQL_PREDICATE), so leaving
    # this to the random _tx_type_for() fallback could silently type these
    # as WIRE_TRANSFER/CRYPTO and make the persona stop firing its own scenario.
    now = datetime.now()
    out = []
    for i in range(n_transactions):
        tx_date = now - timedelta(days=17 + i * 4 + random.uniform(0, 1), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(9_200, 9_950), 2), "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
            "transaction_type": "CASH_DEPOSIT",
        })
    return out


def persona_rapid_layering_account(account_id, n_legs=3):
    # SCN_RAPID_LAYERING: AED 20,000+ across 3+ legs within 72 hours.
    # 10,500 floor keeps legs above the structuring band (no smurf/struct
    # cross-fire); ~36k total stays under the 55k cash-agg ceiling and the
    # 40k same-day CTR threshold.
    base = datetime.now() - timedelta(days=random.uniform(4, 7))
    out = []
    for i in range(n_legs):
        tx_date = base + timedelta(hours=random.uniform(0, 60))
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(10_500, 13_500), 2), "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def persona_cross_border_account(account_id, n_countries=4):
    # SCN_CROSS_BORDER_ANOMALY: 4+ distinct countries within 30 days.
    # NORMAL countries only (no high-risk cross-fire), amounts below the
    # band, ~7-day spacing so no 3 legs land in a 72-hour window.
    now = datetime.now()
    countries = random.sample(NORMAL, k=n_countries)
    out = []
    for i, country in enumerate(countries):
        tx_date = now - timedelta(days=2 + i * 7 + random.uniform(0, 2), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(3_000, 8_000), 2), "country": country,
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def persona_smurfing_cluster(account_ids):
    # SCN_MULTI_ACCOUNT_STRUCTURING: 3+ accounts in band within 14 days —
    # one band transaction per account (a single tx can never also trip
    # the 3-transaction single-account structuring rule). Forced
    # CASH_DEPOSIT for the same reason as persona_structuring_account —
    # this scenario is cash-exclusive.
    base = datetime.now() - timedelta(days=11)
    out = []
    for account_id in account_ids:
        tx_date = base + timedelta(days=random.uniform(0, 8), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(8_700, 9_900), 2), "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
            "transaction_type": "CASH_DEPOSIT",
        })
    return out


def persona_dormant_reactivation_account(account_id):
    # SCN_DORMANT_REACTIVATION: last activity 180+ days before as_of, then
    # a reactivating transaction above AED 15,000. NORMAL country and <40k
    # so it can't also fire high-risk-jurisdiction or a CTR.
    now = datetime.now()
    early = now - timedelta(days=random.randint(300, 360), hours=random.randint(0, 23))
    reactivation = now - timedelta(days=random.randint(2, 12), hours=random.randint(0, 23))
    return [
        {"transaction_id": str(uuid.uuid4()), "account_id": account_id,
         "amount": round(random.uniform(500, 3_000), 2), "country": random.choice(NORMAL),
         "transaction_date": early.strftime("%Y-%m-%d %H:%M:%S")},
        {"transaction_id": str(uuid.uuid4()), "account_id": account_id,
         "amount": round(random.uniform(18_000, 30_000), 2), "country": random.choice(NORMAL),
         "transaction_date": reactivation.strftime("%Y-%m-%d %H:%M:%S")},
    ]


def persona_cash_agg_account(account_id, n_transactions=8):
    # SCN_CASH_AGG_6M: cumulative CASH-channel amount over a rolling
    # 6-month window above the account's effective threshold. 8 tx of
    # 7,000-7,800 spaced ~18 days apart lands ~AED 59,000 — above the
    # threshold while: staying below the 8,500 structuring band floor,
    # never putting 3 legs inside 72 hours (rapid layering), keeping to
    # one country (cross-border), and keeping the last-30-days volume in
    # line with the account's own baseline (behaviour change).
    #
    # Forced CASH_DEPOSIT — the scenario is cash-exclusive, so leaving
    # this to the random type fallback risks these legs getting typed as
    # WIRE_TRANSFER/CRYPTO and silently dropping out of the aggregate. See
    # PERSONA_EXPECTED_VOLUME_OVERRIDES for why this persona's account
    # also needs a below-default expected_monthly_volume: at the standard
    # AED 50,000 EMV, the new expected-volume-aware threshold (EMV * 6mo *
    # 0.5 = 150,000) would swallow this persona's ~59k total and it would
    # stop demonstrating the flat AED 55,000 floor entirely.
    now = datetime.now()
    out = []
    for i in range(n_transactions):
        tx_date = now - timedelta(days=4 + i * 18 + random.uniform(0, 3), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(7_000, 7_800), 2), "country": "AE",
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
            "transaction_type": "CASH_DEPOSIT",
        })
    return out


def persona_virtual_asset_routing_account(account_id):
    # Regression coverage for the exact real-world gap reported on this
    # persona's namesake account: mostly non-cash activity (contract-
    # payment wires, a crypto-exchange outflow) plus one small ATM cash
    # deposit, where the crypto leg's intermediary_countries routing path
    # touches Myanmar (MM) even though its declared endpoint (SG) is a
    # NORMAL-list country. Confirms two fixes together:
    #   1. SCN_CASH_AGG_6M no longer aggregates the wire/crypto legs — only
    #      the ~500 AED cash deposit counts as cash, nowhere near any
    #      threshold. Before the channel fix, the full ~75k mixed total
    #      would have cleared the flat AED 55,000 floor and fired a
    #      high-severity "cash aggregation" alert whose evidence was
    #      almost entirely non-cash.
    #   2. SCN_HIGH_RISK_JURISDICTION now fires off the MM ROUTING HOP
    #      alone, even though the crypto transfer's own declared endpoint
    #      is benign.
    # All legs land within the last 30 days (nothing further back), so
    # there is no baseline-period transaction at all — keeps this account
    # out of SCN_BEHAVIOUR_CHANGE's baseline join entirely rather than
    # tripping it as a side effect of the wire/crypto volume.
    now = datetime.now()
    out = [{
        "transaction_id": str(uuid.uuid4()), "account_id": account_id,
        "amount": round(random.uniform(300, 800), 2), "country": "AE",
        "transaction_date": (now - timedelta(days=25, hours=random.uniform(0, 20))).strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_type": "CASH_DEPOSIT",
    }]
    for d in (20, 14, 8):
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(18_000, 22_000), 2), "country": "GB",
            "transaction_date": (now - timedelta(days=d, hours=random.uniform(0, 20))).strftime("%Y-%m-%d %H:%M:%S"),
            "transaction_type": "WIRE_TRANSFER", "reference": "CONTRACT PAYMENT",
        })
    out.append({
        "transaction_id": str(uuid.uuid4()), "account_id": account_id,
        "amount": round(random.uniform(12_000, 15_000), 2), "country": "SG",
        "transaction_date": (now - timedelta(days=3, hours=random.uniform(0, 20))).strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_type": "CRYPTO", "intermediary_countries": "AE|MM|SG",
    })
    return out


def persona_high_risk_jurisdiction_account(account_id):
    # SCN_HIGH_RISK_JURISDICTION: single transaction above AED 10,000
    # involving a jurisdiction in aml_engine.HIGH_RISK_JURISDICTIONS
    # (which is narrower than this file's HIGH_RISK pool — "IR" is in both).
    tx_date = datetime.now() - timedelta(days=random.uniform(1, 10), hours=random.uniform(0, 20))
    return [{
        "transaction_id": str(uuid.uuid4()), "account_id": account_id,
        "amount": round(random.uniform(24_000, 28_000), 2), "country": "IR",
        "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
    }]


def persona_pep_exposure_account(account_id):
    # SCN_PEP_EXPOSURE single-transaction path: the account's customer_name
    # (see PERSONA_ACCOUNTS below) is an ACTIVE pep_list entry, so the
    # engine's _sync_pep_flags_from_screening_db sets is_pep=1, and one
    # transaction above the AED 50,000 PEP single-tx threshold fires it.
    # Expected companions on this account: SCN_PEP_MATCH (the name IS the
    # list entry), SCN_CASH_AGG_6M (PEPs get the tighter 0.7x threshold,
    # which any 50k+ tx necessarily clears), and a same-day CTR filing —
    # a PEP moving this much trips several rules at once, by design.
    tx_date = datetime.now() - timedelta(days=random.uniform(1, 10), hours=random.uniform(0, 20))
    return [{
        "transaction_id": str(uuid.uuid4()), "account_id": account_id,
        "amount": round(random.uniform(55_000, 60_000), 2), "country": "AE",
        "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
    }]


def persona_behaviour_change_account(account_id):
    # SCN_BEHAVIOUR_CHANGE: current 30-day volume 3x+ the account's own
    # 90-day baseline. One modest baseline transaction, then a recent burst
    # of three — 8-day spacing (no layering cluster), amounts capped below
    # the 8,500 band, ~27k six-month total (under the cash-agg ceiling).
    now = datetime.now()
    out = [{
        "transaction_id": str(uuid.uuid4()), "account_id": account_id,
        "amount": round(random.uniform(2_000, 3_000), 2), "country": random.choice(NORMAL),
        "transaction_date": (now - timedelta(days=random.uniform(55, 70))).strftime("%Y-%m-%d %H:%M:%S"),
    }]
    for i in range(3):
        tx_date = now - timedelta(days=3 + i * 8 + random.uniform(0, 2), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(7_600, 8_400), 2), "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


# 14 persona accounts guaranteeing coverage of ALL 12 detection scenarios
# with a deliberately small footprint (~29 transactions, roughly one alert
# per persona) so the practice queue stays readable.
# The PERSONA_* handles are internal keys only (they route the transaction
# builders and EMV overrides below) — what actually reaches the database,
# CSV, and UI is the realistic account number from PERSONA_ACCOUNT_IDS and
# the customer_name here. Pattern-based personas carry screening-clean
# names that must NOT appear in sanctions_pep_seed.py (or fuzzy/phonetic-
# match one — see _screen_clean), otherwise they'd raise a duplicate
# name-match alert on top of their own scenario. The four screening
# personas carry an EXACT screening-list name from sanctions_pep_seed.py
# so the name-match scenarios always hit — they need NO transactions at
# all (the engine anchors a name-match alert to as_of when the account
# has no activity):
#   - "Rashid Volkov"      → sanctions_list (OFAC_DEMO), not in _RETAIL_NAMES
#   - "Aisha Al Hamdan"    → pep_list ACTIVE minister (drives PEP_EXPOSURE via is_pep)
#   - "Park Jiyeon"        → pep_list ACTIVE head of state
#   - "Fatima Bint Rashid" → internal_watchlist (PRIOR_SAR)
PERSONA_ACCOUNTS = [
    ("PERSONA_STRUCT_01",    "Nasser Al Awadhi"),    # SCN_STRUCTURING_CASH
    ("PERSONA_LAYER_01",     "Bilal Qureshi"),       # SCN_RAPID_LAYERING
    ("PERSONA_XBORDER_01",   "Dominic Reyes"),       # SCN_CROSS_BORDER_ANOMALY
    ("PERSONA_SMURF_01",     "Salem Al Dhaheri"),    # SCN_MULTI_ACCOUNT_STRUCTURING
    ("PERSONA_SMURF_02",     "Farida Iskandar"),     # SCN_MULTI_ACCOUNT_STRUCTURING
    ("PERSONA_SMURF_03",     "Kavya Menon"),         # SCN_MULTI_ACCOUNT_STRUCTURING
    ("PERSONA_DORMANT_01",   "Stefan Villiers"),     # SCN_DORMANT_REACTIVATION
    ("PERSONA_BEHAVE_01",    "Huda Al Sayegh"),      # SCN_BEHAVIOUR_CHANGE
    ("PERSONA_CASHAGG_01",   "Marcus Oduya"),        # SCN_CASH_AGG_6M
    ("PERSONA_HIGHRISK_01",  "Lin Mei Fen"),         # SCN_HIGH_RISK_JURISDICTION
    ("PERSONA_PEPEXPO_01",   "Aisha Al Hamdan"),     # SCN_PEP_EXPOSURE (+ PEP_MATCH + CASH_AGG)
    ("PERSONA_SANCTION_01",  "Rashid Volkov"),       # SCN_SANCTION_MATCH
    ("PERSONA_PEPMATCH_01",  "Park Jiyeon"),         # SCN_PEP_MATCH
    ("PERSONA_WATCHLIST_01", "Fatima Bint Rashid"),  # SCN_INTERNAL_WATCHLIST
    ("PERSONA_VAROUTE_01",   "Georgina Mercer"),     # Regression: cash-channel + routing-path jurisdiction fixes
]

# Realistic account numbers for the persona accounts — same _account_number
# scheme as the background book, offset to index 500+ so their serials can
# never collide with the 220 background accounts (or the random 700–999
# range make_transaction uses as its no-profile fallback).
PERSONA_ACCOUNT_IDS = {
    handle: _account_number(500 + i)
    for i, (handle, _name) in enumerate(PERSONA_ACCOUNTS)
}

# Per-persona expected_monthly_volume overrides — every persona otherwise
# gets the flat default (50,000.00) set in build_customer_profiles below.
# PERSONA_CASHAGG_01 needs a modest declared EMV so its ~59k cash total
# still clears the flat AED 55,000 floor under the new expected-volume-
# aware SCN_CASH_AGG_6M threshold (see aml_engine.CASH_AGG_EXPECTED_VOLUME_RATIO) —
# at the 50,000 default, the EMV-derived floor (50,000 * 6mo * 0.5 =
# 150,000) would swallow this persona's total and it would silently stop
# firing its own scenario.
PERSONA_EXPECTED_VOLUME_OVERRIDES = {
    "PERSONA_CASHAGG_01": 8_000.00,
}


def build_persona_transactions():
    acct = PERSONA_ACCOUNT_IDS
    out = []
    out += persona_structuring_account(acct["PERSONA_STRUCT_01"])
    out += persona_rapid_layering_account(acct["PERSONA_LAYER_01"])
    out += persona_cross_border_account(acct["PERSONA_XBORDER_01"])
    out += persona_smurfing_cluster([acct[f"PERSONA_SMURF_{i:02d}"] for i in range(1, 4)])
    out += persona_dormant_reactivation_account(acct["PERSONA_DORMANT_01"])
    out += persona_behaviour_change_account(acct["PERSONA_BEHAVE_01"])
    out += persona_cash_agg_account(acct["PERSONA_CASHAGG_01"])
    out += persona_high_risk_jurisdiction_account(acct["PERSONA_HIGHRISK_01"])
    out += persona_pep_exposure_account(acct["PERSONA_PEPEXPO_01"])
    out += persona_virtual_asset_routing_account(acct["PERSONA_VAROUTE_01"])
    # PERSONA_SANCTION_01 / PERSONA_PEPMATCH_01 / PERSONA_WATCHLIST_01:
    # intentionally no transactions — their scenarios fire on the profile
    # name alone.
    return out


def _load_screening_names() -> tuple[list[str], list[str], list[str]]:
    if not SCREENING_DB_PATH.exists():
        return [], [], []
    try:
        conn = sqlite3.connect(SCREENING_DB_PATH)
        sanc = [r[0] for r in conn.execute(
            "SELECT full_name FROM sanctions_list WHERE is_active = 1"
        ).fetchall()]
        pep = [r[0] for r in conn.execute(
            "SELECT full_name FROM pep_list WHERE is_active = 1"
        ).fetchall()]
        watch = [r[0] for r in conn.execute(
            "SELECT full_name FROM internal_watchlist WHERE is_active = 1"
        ).fetchall()]
        conn.close()
        return sanc, pep, watch
    except sqlite3.Error:
        return [], [], []


def _screen_clean(names: list[str]) -> list[str]:
    """Drops every name the engine's own screening matcher (exact + fuzzy +
    phonetic — see aml_engine._resolve_match) would hit against the active
    sanctions/PEP/watchlist entries. The background customer population must
    be SILENT: deliberate screening hits belong exclusively to the persona
    accounts, otherwise every list-named profile adds a duplicate alert and
    the practice queue balloons into the hundreds."""
    import aml_engine
    global _SCREEN_CANDIDATES
    if _SCREEN_CANDIDATES is None:
        sanc, pep, watch = _load_screening_names()
        _SCREEN_CANDIDATES = {aml_engine._normalize_name(n): n for n in sanc + pep + watch}
    if not _SCREEN_CANDIDATES:
        return list(names)
    return [n for n in names if aml_engine._resolve_match(n, _SCREEN_CANDIDATES) is None]


_SCREEN_CANDIDATES: dict | None = None


def _crr_for(name: str, sanctioned_names: set, pep_names: set, jurisdiction_flag: bool) -> tuple[str, str]:
    norm = _normalize(name)
    if norm in sanctioned_names:
        return "HIGH", "Name matches an external sanctions list entry"
    if norm in pep_names:
        return "HIGH", "Politically Exposed Person (PEP) — elevated monitoring required"
    if jurisdiction_flag:
        return "HIGH", "Linked to a FATF/CBUAE high-risk jurisdiction at onboarding"
    r = random.random()
    if r < 0.55:
        return "LOW", "Standard profile, no adverse indicators at onboarding"
    return "MEDIUM", "Default risk rating — no specific triggers at onboarding"


def build_customer_profiles() -> list[dict]:
    sanc_names, pep_names, _watch_names = _load_screening_names()
    sanctioned_norm = {_normalize(n) for n in sanc_names}
    pep_norm = {_normalize(n) for n in pep_names}

    # Background accounts draw ONLY screening-clean names — the deliberate
    # sanctions/PEP/watchlist overlap lives on the four screening persona
    # accounts (see PERSONA_ACCOUNTS), exactly one hit per list, instead of
    # being smeared across the whole customer base.
    clean_retail = _screen_clean(_RETAIL_NAMES) or list(_RETAIL_NAMES)

    profiles = []
    now_date = datetime.now().strftime("%Y-%m-%d")

    n_retail = int(N_ACCOUNTS * 0.60)
    n_corporate = int(N_ACCOUNTS * 0.30)
    n_correspondent = N_ACCOUNTS - n_retail - n_corporate

    idx = 0
    for i in range(n_retail):
        idx += 1
        account_id = _account_number(idx)
        name = clean_retail[i % len(clean_retail)]
        jurisdiction_flag = (i % 11 == 0)
        risk_rating, risk_reason = _crr_for(name, sanctioned_norm, pep_norm, jurisdiction_flag)
        # Jurisdiction-flagged accounts get a grey-list nationality so the
        # KYC score agrees with their onboarding risk_rating_reason; most
        # customers reside in AE, every 7th lives in their home country.
        if jurisdiction_flag:
            nationality = _HIGH_RISK_NATIONALITY_POOL[i % len(_HIGH_RISK_NATIONALITY_POOL)]
        else:
            nationality = _RETAIL_NATIONALITY_POOL[i % len(_RETAIL_NATIONALITY_POOL)]
        residence = nationality if i % 7 == 0 else "AE"
        profiles.append({
            "account_id": account_id, "customer_name": name, "customer_type": "INDIVIDUAL",
            "account_category": "RETAIL", "risk_rating": risk_rating, "risk_rating_date": now_date,
            "risk_rating_reason": risk_reason, "is_pep": 1 if _normalize(name) in pep_norm else 0,
            "expected_monthly_volume": 50000.00, "ubo_names": None, "swift_bic": None,
            "nationality": nationality, "country_of_residence": residence,
            "date_of_birth": _synthetic_dob(idx),
        })

    for i in range(n_corporate):
        idx += 1
        account_id = _account_number(idx)
        corp_name, ubos = _CORPORATE_NAMES[i % len(_CORPORATE_NAMES)]
        # UBO names get the same screening-clean treatment as retail names —
        # a listed beneficial owner on a background account would raise its
        # own UBO screening alert per profile. Companies whose UBOs are all
        # list names get a clean stand-in owner instead.
        ubos = _screen_clean(ubos) or [clean_retail[i % len(clean_retail)]]
        jurisdiction_flag = (i % 9 == 0)
        risk_rating, risk_reason = _crr_for(corp_name, sanctioned_norm, pep_norm, jurisdiction_flag)
        # Non-individuals: nationality doubles as country of incorporation,
        # date_of_birth stays NULL (templates render the '—' fallback).
        incorporation = (
            _OFFSHORE_INCORPORATION_POOL[i % len(_OFFSHORE_INCORPORATION_POOL)]
            if jurisdiction_flag else "AE"
        )
        profiles.append({
            "account_id": account_id, "customer_name": corp_name, "customer_type": "CORPORATE",
            "account_category": "CORPORATE", "risk_rating": risk_rating, "risk_rating_date": now_date,
            "risk_rating_reason": risk_reason, "is_pep": 0, "expected_monthly_volume": 150000.00,
            "ubo_names": "|".join(ubos), "swift_bic": None,
            "nationality": incorporation, "country_of_residence": incorporation,
            "date_of_birth": None,
        })

    for i in range(n_correspondent):
        idx += 1
        account_id = _account_number(idx)
        bank_name, bic = _CORRESPONDENT_NAMES[i % len(_CORRESPONDENT_NAMES)]
        bank_country = _CORRESPONDENT_COUNTRY.get(bic, "AE")
        profiles.append({
            "account_id": account_id, "customer_name": bank_name, "customer_type": "CORPORATE",
            "account_category": "CORRESPONDENT", "risk_rating": "MEDIUM", "risk_rating_date": now_date,
            "risk_rating_reason": "Correspondent banking relationship — standard enhanced monitoring",
            "is_pep": 0, "expected_monthly_volume": 500000.00, "ubo_names": None, "swift_bic": bic,
            "nationality": bank_country, "country_of_residence": bank_country,
            "date_of_birth": None,
        })

    for p_idx, (persona_id, persona_name) in enumerate(PERSONA_ACCOUNTS):
        profiles.append({
            "account_id": PERSONA_ACCOUNT_IDS[persona_id], "customer_name": persona_name,
            "customer_type": "INDIVIDUAL", "account_category": "RETAIL", "risk_rating": "MEDIUM",
            "risk_rating_date": now_date,
            "risk_rating_reason": "Default risk rating — no specific triggers at onboarding",
            "is_pep": 0,
            "expected_monthly_volume": PERSONA_EXPECTED_VOLUME_OVERRIDES.get(persona_id, 50000.00),
            "ubo_names": None, "swift_bic": None,
            "nationality": "AE", "country_of_residence": "AE",
            "date_of_birth": _synthetic_dob(p_idx),
        })

    return profiles


def write_customer_profiles(profiles: list[dict], company_id: str) -> None:
    import aml_engine
    import pii_crypto
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(aml_engine.SCHEMA_DDL)
    aml_engine._apply_additive_migrations(conn)
    for p in profiles:
        # Task 3: encrypt sensitive PII (customer_name, nationality,
        # date_of_birth) before it ever touches the database file. Everything
        # else on the profile stays cleartext — it's operational, not PII.
        # encrypt_pii is NULL-safe (CORPORATE/CORRESPONDENT dob is None) and
        # idempotent, so the ON CONFLICT re-write can't double-wrap.
        enc_name = pii_crypto.encrypt_pii(p["customer_name"])
        enc_nationality = pii_crypto.encrypt_pii(p["nationality"])
        enc_dob = pii_crypto.encrypt_pii(p["date_of_birth"])
        conn.execute("""
            INSERT INTO customer_profiles
                (account_id, customer_name, customer_type, account_category, risk_rating,
                 risk_rating_date, risk_rating_reason, is_pep, expected_monthly_volume,
                 ubo_names, swift_bic, nationality, country_of_residence, date_of_birth,
                 company_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(company_id, account_id) DO UPDATE SET
                customer_name=excluded.customer_name, customer_type=excluded.customer_type,
                account_category=excluded.account_category, risk_rating=excluded.risk_rating,
                risk_rating_date=excluded.risk_rating_date, risk_rating_reason=excluded.risk_rating_reason,
                expected_monthly_volume=excluded.expected_monthly_volume,
                ubo_names=excluded.ubo_names, swift_bic=excluded.swift_bic,
                nationality=excluded.nationality,
                country_of_residence=excluded.country_of_residence,
                date_of_birth=excluded.date_of_birth
        """, (p["account_id"], enc_name, p["customer_type"], p["account_category"],
              p["risk_rating"], p["risk_rating_date"], p["risk_rating_reason"], p["is_pep"],
              p["expected_monthly_volume"], p["ubo_names"], p["swift_bic"],
              enc_nationality, p["country_of_residence"], enc_dob, company_id))
    conn.commit()
    conn.close()
    print(f"Seeded/updated {len(profiles)} customer profiles for company_id={company_id} "
          f"({sum(1 for p in profiles if p['account_category']=='RETAIL')} RETAIL, "
          f"{sum(1 for p in profiles if p['account_category']=='CORPORATE')} CORPORATE, "
          f"{sum(1 for p in profiles if p['account_category']=='CORRESPONDENT')} CORRESPONDENT).")


def main(company_id: str):
    profiles = build_customer_profiles()
    write_customer_profiles(profiles, company_id)

    account_by_category = {p["account_id"]: p["account_category"] for p in profiles}
    # Background traffic must never land on a persona account — each persona
    # is tuned to fire EXACTLY its own scenario, and stray transactions
    # could cross-fire others.
    persona_account_ids = set(PERSONA_ACCOUNT_IDS.values())
    real_account_ids = [p["account_id"] for p in profiles if p["account_id"] not in persona_account_ids]

    # Trailing 12 months ending today — the engine anchors every rolling
    # detection window to as_of = run day, so data must reach the present.
    start = datetime.now() - timedelta(days=365)
    rows = []
    for _ in range(N_BACKGROUND_TX):
        account_id = random.choice(real_account_ids)
        tx = make_transaction(start + timedelta(minutes=random.randint(0, 525_600)), account_id=account_id)
        category = account_by_category.get(account_id, "RETAIL")
        rows.append(enrich_with_counterparty_fields(tx, category))

    persona_rows = build_persona_transactions()
    for tx in persona_rows:
        rows.append(enrich_with_counterparty_fields(tx, "RETAIL"))

    incoming_dir = Path("data/incoming")
    incoming_dir.mkdir(parents=True, exist_ok=True)
    # One file per company_id — /run-pipeline may be triggered by different
    # companies close together, and aml_loader.py ingests every *.csv it
    # finds in data/incoming in one pass, tagging ALL of them with whatever
    # single company_id it's invoked with (see run_ingestion). Distinct
    # per-company filenames keep concurrent generate+ingest cycles from
    # racing over the same file or misattributing rows.
    file_path = incoming_dir / f"aml_transactions_{company_id}.csv"

    fieldnames = ["transaction_id", "account_id", "amount", "country", "transaction_date",
                  "counterparty_name", "reference", "ordering_customer_name",
                  "beneficiary_name", "originating_bank_bic",
                  "transaction_type", "counterparty_type",
                  "counterparty_wallet_address", "intermediary_countries"]
    with open(file_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} transactions for company_id={company_id} directly into → {file_path}")


if __name__ == "__main__":
    import sys
    import auth_security
    # Direct terminal runs load .env themselves (app-triggered subprocess runs
    # inherit os.environ from the parent). Ensures the SAME NEXUSBARRIER_PII_KEY
    # is used here as the web app, so what this script encrypts stays readable.
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    cli_company_id = sys.argv[1] if len(sys.argv) > 1 else auth_security.LEGACY_COMPANY_ID
    main(cli_company_id)