import csv, random, uuid
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

# High-Risk Jurisdictions subject to a Call for Action & Jurisdictions under Increased Monitoring (as of Feb 2026)
HIGH_RISK = [
    "KP", # Democratic People's Republic of Korea
    "IR", # Iran
    "MM", # Myanmar
    "DZ", # Algeria
    "AO", # Angola
    "BO", # Bolivia
    "BG", # Bulgaria
    "CM", # Cameroon
    "CI", # Côte d'Ivoire
    "CD", # Democratic Republic of Congo
    "HT", # Haiti
    "KE", # Kenya
    "KW", # Kuwait
    "LA", # Lao People's Democratic Republic
    "LB", # Lebanon
    "MC", # Monaco
    "NA", # Namibia
    "NP", # Nepal
    "PG", # Papua New Guinea
    "SS", # South Sudan
    "SY", # Syria
    "VE", # Venezuela
    "VN", # Vietnam
    "VG", # Virgin Islands (UK)
    "YE"  # Yemen
]

# Standard reference countries for benchmarking clean/normal traffic
NORMAL    = ["US", "GB", "DE", "FR", "JP", "CA", "AU", "SG", "AE"]
THRESHOLD = 10_000

def make_transaction(tx_date, account_id=None):
    r = random.random()

    if r < 0.70:                                         # Normal (~70%)
        amount  = round(random.lognormvariate(6.5, 1.2), 2)   # log-normal: realistic spend curve
        country = random.choices(NORMAL, k=1)[0]
        amount  = min(amount, 8_000)                     # cap below threshold

    elif r < 0.90:                                       # Borderline (~20%)
        amount  = round(random.uniform(8_500, 9_999), 2) # structuring zone
        country = random.choices(NORMAL + HIGH_RISK,
                                 weights=[0.6]*len(NORMAL) + [0.4]*len(HIGH_RISK), k=1)[0]

    else:                                                # Suspicious (~10%)
        pattern = random.random()
        if pattern < 0.50:                               # Structuring: just-below threshold
            amount = round(random.uniform(9_800, 9_999), 2)
        elif pattern < 0.80:                             # High-risk jurisdiction + large
            amount = round(random.uniform(15_000, 200_000), 2)
        else:                                            # Anomalous spike
            amount = round(random.uniform(50_000, 500_000), 2)
        country = random.choices(HIGH_RISK, k=1)[0]

    return {
        "transaction_id":   str(uuid.uuid4()),
        "account_id":       account_id or f"ACC{random.randint(1000, 9999)}",
        "amount":           amount,
        "country":          country,
        "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Persona injection ───────────────────────────────────────────────────────
# The random-account-per-transaction model above gives every account a
# near-uniform, sparse, randomly-scattered history (most accounts end up
# with only 1-2 transactions across the whole year), which means scenarios
# that depend on the SAME account doing multiple things close together in
# time (SCN_STRUCTURING_CASH, SCN_RAPID_LAYERING, SCN_CROSS_BORDER_ANOMALY)
# or several DIFFERENT accounts coordinating within a tight window
# (SCN_MULTI_ACCOUNT_STRUCTURING) almost never fire on randomly-generated
# data, regardless of whether the detection logic is correct — there's
# simply no clustered signal in the data to detect. This section explicitly
# injects a small number of named "persona" accounts with realistic
# clustered patterns, on top of (not replacing) the existing random
# population, so every scenario has genuine signal to find. Each persona's
# pattern is built to be the kind of activity a real analyst would expect
# to see flagged — not artificially extreme, just genuinely clustered.
PERSONA_WINDOW_START = datetime(2025, 6, 1)   # mid-year, so 90-day baselines and
                                               # 6-month windows both have room on either side


def persona_structuring_account(account_id: str, n_transactions: int = 4) -> list[dict]:
    """Classic single-account structuring: several just-below-threshold
    cash transactions clustered within STRUCTURING_WINDOW_DAYS (30 days)."""
    base = PERSONA_WINDOW_START + timedelta(days=random.randint(0, 60))
    out = []
    for i in range(n_transactions):
        tx_date = base + timedelta(days=random.uniform(0, 25), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()),
            "account_id": account_id,
            "amount": round(random.uniform(9_200, 9_950), 2),
            "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def persona_rapid_layering_account(account_id: str, n_legs: int = 4) -> list[dict]:
    """Rapid same-account fund concentration: several transactions within
    a tight 72-hour-or-less window totalling a meaningful sum."""
    base = PERSONA_WINDOW_START + timedelta(days=random.randint(70, 130))
    out = []
    for i in range(n_legs):
        tx_date = base + timedelta(hours=random.uniform(0, 60))
        out.append({
            "transaction_id": str(uuid.uuid4()),
            "account_id": account_id,
            "amount": round(random.uniform(6_000, 14_000), 2),
            "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def persona_cross_border_account(account_id: str, n_countries: int = 5) -> list[dict]:
    """Same account transacting across many distinct countries within a
    short window — trade-based-laundering / fund-dispersal signature."""
    base = PERSONA_WINDOW_START + timedelta(days=random.randint(140, 190))
    countries = random.sample(NORMAL + HIGH_RISK, k=n_countries)
    out = []
    for i, country in enumerate(countries):
        tx_date = base + timedelta(days=random.uniform(0, 25))
        out.append({
            "transaction_id": str(uuid.uuid4()),
            "account_id": account_id,
            "amount": round(random.uniform(3_000, 9_000), 2),
            "country": country,
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def persona_smurfing_cluster(account_ids: list[str]) -> list[dict]:
    """Multiple DISTINCT accounts all transacting in the structuring band
    within a tight shared window — the multi-account smurfing pattern.
    Distinct from persona_structuring_account, which clusters multiple
    transactions on ONE account; this clusters one transaction each across
    SEVERAL accounts."""
    base = PERSONA_WINDOW_START + timedelta(days=random.randint(200, 240))
    out = []
    for account_id in account_ids:
        tx_date = base + timedelta(days=random.uniform(0, 10), hours=random.uniform(0, 20))
        out.append({
            "transaction_id": str(uuid.uuid4()),
            "account_id": account_id,
            "amount": round(random.uniform(8_700, 9_900), 2),
            "country": random.choice(NORMAL),
            "transaction_date": tx_date.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def persona_dormant_reactivation_account(account_id: str) -> list[dict]:
    """A transaction early in the year, total silence, then a large
    reactivation transaction near year-end — the dormant-account pattern.
    Needs to be hand-placed because random scattering essentially never
    produces a clean 180+ day silence gap followed by exactly one
    reactivation (any random tx landing in the gap breaks the pattern)."""
    early = datetime(2025, 1, random.randint(2, 20), random.randint(0, 23), random.randint(0, 59))
    reactivation = datetime(2025, 11, random.randint(1, 25), random.randint(0, 23), random.randint(0, 59))
    return [
        {
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(500, 3_000), 2), "country": random.choice(NORMAL),
            "transaction_date": early.strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "transaction_id": str(uuid.uuid4()), "account_id": account_id,
            "amount": round(random.uniform(18_000, 60_000), 2), "country": random.choice(NORMAL + HIGH_RISK),
            "transaction_date": reactivation.strftime("%Y-%m-%d %H:%M:%S"),
        },
    ]


def build_persona_transactions() -> list[dict]:
    """Assembles all persona-injected transactions. account_id values use a
    PERSONA_ prefix so they're trivially distinguishable from the random
    population (random IDs are ACC1000-ACC9999, never PERSONA_*) — useful
    for demos ("here's our known-suspicious test account") without needing
    a separate lookup table."""
    out: list[dict] = []
    out += persona_structuring_account("PERSONA_STRUCT_01")
    out += persona_structuring_account("PERSONA_STRUCT_02", n_transactions=5)
    out += persona_rapid_layering_account("PERSONA_LAYER_01")
    out += persona_rapid_layering_account("PERSONA_LAYER_02", n_legs=3)
    out += persona_cross_border_account("PERSONA_XBORDER_01")
    out += persona_smurfing_cluster([f"PERSONA_SMURF_{i:02d}" for i in range(1, 5)])
    out += persona_dormant_reactivation_account("PERSONA_DORMANT_01")
    out += persona_dormant_reactivation_account("PERSONA_DORMANT_02")
    return out


start = datetime(2025, 1, 1) # Set to a full year leading up to 2026
rows  = [make_transaction(start + timedelta(minutes=random.randint(0, 525_600)))
         for _ in range(5_000)]
rows += build_persona_transactions()

incoming_dir = Path("data/incoming")
incoming_dir.mkdir(parents=True, exist_ok=True) 

# This ensures the CSV goes to NexusBarrier/data/incoming/aml_transactions.csv
file_path = incoming_dir / "aml_transactions.csv"

with open(file_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} transactions directly into → {file_path}")