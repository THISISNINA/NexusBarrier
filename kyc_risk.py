"""
kyc_risk.py — Initial Customer Risk Rating (static KYC-attribute scoring)
--------------------------------------------------------------------------
Deterministic onboarding-time risk rating computed from WHO the customer is
on file (customer_type, PEP flag, EDD flag, nationality / country of
residence) — no transaction behaviour at all. This is deliberately a
different layer from aml_risk.py, which scores transaction *behaviour*
(velocity, structuring proximity, jurisdiction exposure of actual flows):

    kyc_risk.py  → "how risky is this customer on paper?"   (static, pure)
    aml_risk.py  → "how risky is what this account is doing?" (behavioural)

Regulatory basis (UAE):
  - Federal Decree-Law No. (20) of 2018 on AML/CFT (as amended) and
    Cabinet Decision No. (10) of 2019 establish the Risk-Based Approach:
    institutions must identify and assess customer risk and apply
    commensurate due diligence (FATF Recommendation 1).
  - Art. 15, Cabinet Decision No. (10) of 2019 / FATF R.12: foreign PEPs
    require Enhanced Due Diligence and senior-management approval — this
    is why is_pep floors the tier at HIGH below (the profile schema does
    not distinguish foreign from domestic PEPs, so the conservative
    treatment is applied to all).
  - Art. 28, Cabinet Decision No. (10) of 2019 / FATF R.13: cross-border
    correspondent relationships carry their own mandatory due-diligence
    obligations — hence the CORRESPONDENT account-category weight.

As with aml_risk.py: the individual point weights and jurisdiction sets
below are institutional CALIBRATION implementing the RBA principle, not
statutory figures. FATF/CBUAE mandate that higher risk gets more
scrutiny; they do not prescribe "+5 for PEP". A real deployment should
have compliance sign off on the numbers. Exceeding the FATF floor (e.g.
keeping a delisted jurisdiction on the internal elevated-risk list) is
explicitly permitted — the lists below do exactly that.

Pure module: no database access, no writes, no randomness. Same input
dict always produces the same output dict.
"""

MAX_RISK_SCORE = 15
BASELINE_SCORE = 1  # every customer starts at 1 — the scale is 1..15, not 0..15

# ── Jurisdiction risk sets (ISO-3166 alpha-2, matching transactions.country
# and aml_engine.HIGH_RISK_JURISDICTIONS conventions) ──────────────────────
#
# FATF "call for action" black list — highest weight.
FATF_CALL_FOR_ACTION = {"KP", "IR", "MM"}

# FATF "increased monitoring" grey list (snapshot) plus CBUAE-flagged
# corridors already treated as high-risk by the transaction-monitoring
# layer (see aml_engine.HIGH_RISK_JURISDICTIONS) — moderate weight.
FATF_INCREASED_MONITORING = {
    "SY", "CU", "YE", "LY", "AF", "HT", "PK", "PH",
    "SS", "LB", "CD", "VE", "DZ", "AO", "BO", "BG", "CM", "CI", "KE",
    "LA", "NA", "NP", "VN",
}

# Offshore / secrecy financial centres — institutional risk-appetite list,
# NOT a FATF list. Deliberately retains jurisdictions FATF has since
# delisted (Malta 2022, Cayman Islands and Panama 2023) because opaque
# ownership structures routed through them remain a live ML typology;
# keeping them here is a permitted exceed-the-floor calibration choice.
OFFSHORE_SECRECY_CENTRES = {"KY", "PA", "MT", "VG", "MC", "LI", "SC", "BS"}

# ── Factor weights (points on the 1–15 scale) ─────────────────────────────
WEIGHT_COMPLEX_ENTITY = 3        # CORPORATE customer_type — layered ownership
WEIGHT_CORRESPONDENT = 2         # CORRESPONDENT account_category (Art. 28)
WEIGHT_PEP = 5                   # heaviest single factor (Art. 15 / FATF R.12)
WEIGHT_EDD_REQUIRED = 3          # an EDD flag already on file
WEIGHT_JURISDICTION_BLACK = 4    # FATF call-for-action exposure
WEIGHT_JURISDICTION_GREY = 2     # FATF increased-monitoring exposure
WEIGHT_JURISDICTION_OFFSHORE = 2 # offshore/secrecy-centre exposure

# ── Tier thresholds ────────────────────────────────────────────────────────
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

    # Customer type — corporates score higher than individuals: layered
    # ownership (UBOs, nominee arrangements) obscures who really controls
    # the funds.
    customer_type = (customer_dict.get("customer_type") or "").upper()
    if customer_type == "CORPORATE":
        score += WEIGHT_COMPLEX_ENTITY
        factors.append(f"Complex Entity Structure (+{WEIGHT_COMPLEX_ENTITY})")

    # Correspondent banking relationship — its own mandatory due-diligence
    # regime (Art. 28, Cabinet Decision 10/2019), stacked on top of the
    # corporate weight since correspondents are corporates too.
    account_category = (customer_dict.get("account_category") or "").upper()
    if account_category == "CORRESPONDENT":
        score += WEIGHT_CORRESPONDENT
        factors.append(f"Correspondent Banking Relationship (+{WEIGHT_CORRESPONDENT})")

    # PEP — heaviest single factor, and see the tier floor below.
    is_pep = bool(customer_dict.get("is_pep"))
    if is_pep:
        score += WEIGHT_PEP
        factors.append(f"Politically Exposed Person Status (+{WEIGHT_PEP})")

    # An EDD flag already on file is itself a risk signal — someone has
    # already judged this customer to need enhanced measures.
    if customer_dict.get("edd_required"):
        score += WEIGHT_EDD_REQUIRED
        factors.append(f"Enhanced Due Diligence Required (+{WEIGHT_EDD_REQUIRED})")

    # Jurisdiction — nationality and country of residence are both checked;
    # each tier counts at most once no matter how many fields hit it, and a
    # customer can trip multiple tiers (e.g. black-list nationality resident
    # in an offshore centre).
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

    # PEP tier floor — Art. 15, Cabinet Decision No. (10) of 2019 / FATF
    # R.12 mandate EDD for (foreign) PEPs regardless of how the rest of the
    # profile scores; the schema doesn't record foreign vs. domestic, so
    # all PEPs get the conservative treatment. The numeric score is left
    # honest — only the tier is floored, and the floor is disclosed as its
    # own trigger so investigators see it wasn't the arithmetic.
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
