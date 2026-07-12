"""kyc_risk.py — pure, deterministic static (KYC-attribute) initial risk rating (no DB/behaviour), scoring customer_type/PEP/EDD/jurisdiction on a 1–15 scale per the UAE RBA (Cabinet Decision 10/2019, FATF R.1/12/13); weights and jurisdiction lists are institutional calibration (permitted to exceed the FATF floor), not statutory, and PEP floors the tier at HIGH."""

MAX_RISK_SCORE = 15
BASELINE_SCORE = 1  # every customer starts at 1 — the scale is 1..15, not 0..15

# Jurisdiction risk sets (ISO-3166 alpha-2): FATF call-for-action black list — highest weight.
FATF_CALL_FOR_ACTION = {"KP", "IR", "MM"}

# FATF increased-monitoring grey list plus CBUAE-flagged corridors (see aml_engine.HIGH_RISK_JURISDICTIONS) — moderate weight.
FATF_INCREASED_MONITORING = {
    "SY", "CU", "YE", "LY", "AF", "HT", "PK", "PH",
    "SS", "LB", "CD", "VE", "DZ", "AO", "BO", "BG", "CM", "CI", "KE",
    "LA", "NA", "NP", "VN",
}

# Offshore/secrecy centres — institutional (not FATF) list; keeps FATF-delisted jurisdictions, a permitted exceed-the-floor choice.
OFFSHORE_SECRECY_CENTRES = {"KY", "PA", "MT", "VG", "MC", "LI", "SC", "BS"}

# Factor weights (points on the 1–15 scale)
WEIGHT_COMPLEX_ENTITY = 3        # CORPORATE customer_type — layered ownership
WEIGHT_CORRESPONDENT = 2         # CORRESPONDENT account_category (Art. 28)
WEIGHT_PEP = 5                   # heaviest single factor (Art. 15 / FATF R.12)
WEIGHT_EDD_REQUIRED = 3          # an EDD flag already on file
WEIGHT_JURISDICTION_BLACK = 4    # FATF call-for-action exposure
WEIGHT_JURISDICTION_GREY = 2     # FATF increased-monitoring exposure
WEIGHT_JURISDICTION_OFFSHORE = 2 # offshore/secrecy-centre exposure

# Tier thresholds
TIER_HIGH_MIN = 10
TIER_MEDIUM_MIN = 5


def _tier_from_score(score: int) -> str:
    if score >= TIER_HIGH_MIN:
        return "HIGH"
    if score >= TIER_MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


def calculate_initial_risk_rating(customer_dict: dict) -> dict:
    """Deterministic initial (onboarding) risk rating for one customer.

    Reads only static KYC attributes from `customer_dict` — tolerant of
    missing keys so legacy/partial profiles score on whatever is on file:

        customer_type         'INDIVIDUAL' / 'CORPORATE'
        account_category      'RETAIL' / 'CORPORATE' / 'CORRESPONDENT'
        is_pep                truthy int (SQLite 0/1)
        edd_required          truthy int (SQLite 0/1)
        nationality           ISO-3166 alpha-2 or None
        country_of_residence  ISO-3166 alpha-2 or None

    Returns:
        {
          "score":     int, 1..MAX_RISK_SCORE (capped),
          "max_score": MAX_RISK_SCORE,
          "tier":      "LOW" | "MEDIUM" | "HIGH",
          "factors":   comma-separated human-readable trigger string,
          "factor_list": the same triggers as a list,
        }
    """
    score = BASELINE_SCORE
    factors: list[str] = []

    # Customer type — corporates score higher: layered ownership obscures who controls the funds.
    customer_type = (customer_dict.get("customer_type") or "").upper()
    if customer_type == "CORPORATE":
        score += WEIGHT_COMPLEX_ENTITY
        factors.append(f"Complex Entity Structure (+{WEIGHT_COMPLEX_ENTITY})")

    # Correspondent banking — its own mandatory due-diligence regime (Art. 28), stacked on the corporate weight.
    account_category = (customer_dict.get("account_category") or "").upper()
    if account_category == "CORRESPONDENT":
        score += WEIGHT_CORRESPONDENT
        factors.append(f"Correspondent Banking Relationship (+{WEIGHT_CORRESPONDENT})")

    # PEP — heaviest single factor, and see the tier floor below.
    is_pep = bool(customer_dict.get("is_pep"))
    if is_pep:
        score += WEIGHT_PEP
        factors.append(f"Politically Exposed Person Status (+{WEIGHT_PEP})")

    # An EDD flag already on file is itself a risk signal — someone judged this customer to need enhanced measures.
    if customer_dict.get("edd_required"):
        score += WEIGHT_EDD_REQUIRED
        factors.append(f"Enhanced Due Diligence Required (+{WEIGHT_EDD_REQUIRED})")

    # Jurisdiction — nationality and residence both checked; each tier counts once, but multiple tiers can trip.
    countries = {
        (customer_dict.get("nationality") or "").upper(),
        (customer_dict.get("country_of_residence") or "").upper(),
    }
    countries.discard("")

    black_hits = sorted(countries & FATF_CALL_FOR_ACTION)
    if black_hits:
        score += WEIGHT_JURISDICTION_BLACK
        factors.append(
            f"FATF Call-for-Action Jurisdiction: {', '.join(black_hits)} (+{WEIGHT_JURISDICTION_BLACK})"
        )

    grey_hits = sorted(countries & FATF_INCREASED_MONITORING)
    if grey_hits:
        score += WEIGHT_JURISDICTION_GREY
        factors.append(
            f"FATF Increased-Monitoring Jurisdiction: {', '.join(grey_hits)} (+{WEIGHT_JURISDICTION_GREY})"
        )

    offshore_hits = sorted(countries & OFFSHORE_SECRECY_CENTRES)
    if offshore_hits:
        score += WEIGHT_JURISDICTION_OFFSHORE
        factors.append(
            f"Offshore Financial Centre Nexus: {', '.join(offshore_hits)} (+{WEIGHT_JURISDICTION_OFFSHORE})"
        )

    score = min(score, MAX_RISK_SCORE)
    tier = _tier_from_score(score)

    # PEP tier floor — Art. 15 / FATF R.12 mandate EDD for PEPs; float only the tier (score stays honest), disclosed as its own trigger.
    if is_pep and tier != "HIGH":
        tier = "HIGH"
        factors.append("PEP Status Floors Tier at HIGH (mandatory EDD)")

    return {
        "score": score,
        "max_score": MAX_RISK_SCORE,
        "tier": tier,
        "factors": ", ".join(factors) if factors else "No elevated risk factors identified at onboarding",
        "factor_list": factors,
    }
