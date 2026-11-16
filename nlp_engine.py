"""
NLP Engine for AI-Based Spam & Phishing Detection System
Handles language identification (English, Hindi, Spanish, French),
text cleaning, tokenization, semantic threat analysis, urgency extraction,
and explainability indicators.
"""

import re
import string

# Multilingual Urgency Keywords
URGENCY_KEYWORDS = {
    "en": ["immediately", "urgent", "urgently", "action required", "within 24 hours",
           "within 2 hours", "expires today", "final notice", "last chance", "act now",
           "limited time", "hurry", "asap", "deadline", "instant", "instantly", "time sensitive"],
    "hi": ["turant", "fauran", "abhi", "jaldi", "aaj hi", "24 ghante me", "antim chetavni",
           "शीघ्र", "तुरंत", "अभी", "अंतिम चेतावनी", "जल्दी करें"],
    "es": ["urgente", "inmediatamente", "último aviso", "acción requerida", "en 24 horas",
           "expira hoy", "plazo límite", "actúe ahora", "aviso urgente"],
    "fr": ["urgent", "immédiatement", "action requise", "dernier rappel", "dans 24 heures",
           "expire aujourd'hui", "délai dépassé", "avertissement"]
}

# Threat & Legal Intimidation Keywords
THREAT_KEYWORDS = {
    "en": ["arrest warrant", "lawsuit", "legal action", "police", "jail", "court summons",
           "permanently suspended", "account terminated", "frozen", "deactivated",
           "violation", "penalty", "locked", "restriction", "investigation"],
    "hi": ["court", "police", "jail", "saza", "khata band", "block", "parivahan",
           "पुलिस", "गिरफ्तारी", "खाता ब्लॉक", "कानूनी कार्रवाई", "समन"],
    "es": ["orden de arresto", "demanda", "bloqueo inmediato", "cuenta suspendida",
           "policía", "sanción", "penalización", "acción legal", "bloqueada"],
    "fr": ["mandat d'arrêt", "poursuites judiciaires", "police", "compte bloqué",
           "suspension immédiate", "pénalité", "fermeture définitive", "résiliation"]
}

# Fake Reward & Lottery Claims
REWARD_KEYWORDS = {
    "en": ["won", "winner", "congratulations", "lottery", "jackpot", "cash prize",
           "free gift card", "selected as winner", "unclaimed funds", "million dollars",
           "crypto wealth", "100% free", "instant payout", "deposit bonus", "free spins"],
    "hi": ["inaam", "jeeta", "badhai ho", "lottery", "lucky draw", "free cash", "kbc",
           "बधाई हो", "इनाम", "लॉटरी", "मुफ्त", "कैशबैक", "विजेता"],
    "es": ["ganador", "felicidades", "lotería", "premio", "cheque regalo",
           "seleccionado", "dinero gratis", "sorteo"],
    "fr": ["gagné", "gagnant", "félicitations", "loterie", "gros lot", "tirage au sort",
           "virement immédiat", "remboursement"]
}

# Credential & Banking Harvest Keywords
CREDENTIAL_KEYWORDS = {
    "en": ["password", "pin", "cvv", "credit card", "debit card", "ssn", "social security",
           "bank account", "routing number", "seed phrase", "secret key", "verify identity",
           "login credentials", "2-step verification", "atm pin", "passcode"],
    "hi": ["password", "atm pin", "cvv", "aadhar", "pan card", "net banking", "otp",
           "पासवर्ड", "आधार कार्ड", "पैन कार्ड", "ओटीपी", "बैंक खाता"],
    "es": ["contraseña", "clave de acceso", "tarjeta de crédito", "pin", "número de cuenta",
           "datos bancarios", "código secreto", "dni"],
    "fr": ["mot de passe", "carte bancaire", "code secret", "coordonnées bancaires",
           "numéro de compte", "identifiants", "sécurité sociale"]
}


def detect_language(text):
    """
    Detect language based on Unicode script ranges and characteristic lexical tokens.
    Supports: English (en), Hindi (hi), Spanish (es), French (fr).
    Returns (lang_code, lang_name, is_supported).
    """
    if not text or not text.strip():
        return "en", "English", True

    text_lower = text.lower()

    # 1. Check Devanagari script for Hindi
    devanagari_count = len(re.findall(r"[\u0900-\u097F]", text))
    if devanagari_count >= 3:
        return "hi", "Hindi (Devanagari)", True

    # 2. Check Hindi / Hinglish phonetics
    hinglish_markers = ["aapka", "karein", "khata", "badhai", "rupaye", "jeeta", "inaam",
                        "turant", "paisa", "grahak", "sandigdh", "namaste", "shubhkamnayein"]
    hinglish_matches = sum(1 for m in hinglish_markers if m in text_lower)
    if hinglish_matches >= 2:
        return "hi", "Hindi (Hinglish)", True

    # 3. Check French markers and diacritics
    french_diacritics = ["é", "è", "ê", "à", "ç", "ù", "ô", "î", "œ"]
    french_markers = ["votre", "compte", "veuillez", "cliquez", "facture", "bonjour",
                      "sélectionné", "remboursement", "banque", "connexion", "espace client"]
    fr_score = sum(text_lower.count(d) for d in french_diacritics) + sum(2 for m in french_markers if m in text_lower)
    if fr_score >= 3:
        return "fr", "French (Français)", True

    # 4. Check Spanish markers and diacritics
    spanish_diacritics = ["á", "í", "ó", "ú", "ñ", "¿", "¡"]
    spanish_markers = ["cuenta", "estimado", "contraseña", "banco", "haga clic", "tarjeta",
                       "ganado", "solicite", "ingrese", "seguridad", "banca online"]
    es_score = sum(text_lower.count(d) for d in spanish_diacritics) + sum(2 for m in spanish_markers if m in text_lower)
    if es_score >= 3:
        return "es", "Spanish (Español)", True

    # 5. Check if text is standard Latin / English
    ascii_chars = sum(1 for c in text if c in string.ascii_letters or c.isspace() or c in string.digits)
    total_chars = max(len(text), 1)
    if (ascii_chars / total_chars) > 0.7:
        return "en", "English", True

    # If foreign script (e.g. Cyrillic, Arabic, Chinese)
    return "unknown", "Unsupported Language", False


def clean_text_for_ml(text):
    """Clean and normalize raw text for ML TF-IDF vectorization."""
    if not text:
        return ""
    
    text = text.lower()
    # Normalize URLs to a uniform token
    text = re.sub(r"https?://\S+|www\.\S+", " __url__ ", text)
    # Normalize email addresses
    text = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", " __email__ ", text)
    # Normalize currency figures
    text = re.sub(r"[\$€£₹]\s*\d+(?:[,\.]\d+)?", " __currency__ ", text)
    # Normalize general digits
    text = re.sub(r"\b\d+\b", " __number__ ", text)
    # Strip excess punctuation but keep spaces
    text = re.sub(r"[^\w\s_]", " ", text)
    # Collapse multiple whitespaces
    text = re.sub(r"\s+", " ", text).strip()
    return text


def analyze_linguistic_threats(text, lang_code="en"):
    """
    Extract suspicious semantic keywords, urgency, threats,
    fake rewards, and credential requests.
    """
    if not text:
        return {
            "urgency_triggers": [],
            "threat_triggers": [],
            "reward_triggers": [],
            "credential_triggers": [],
            "manipulation_flags": [],
            "nlp_risk_points": 0,
            "manipulation_score": 0
        }

    text_lower = text.lower()

    # Aggregate triggers across detected language and English (since attackers frequently mix languages)
    active_langs = list(set([lang_code, "en"]))

    found_urgency = []
    found_threats = []
    found_rewards = []
    found_credentials = []
    manipulation_flags = []

    for l in active_langs:
        for kw in URGENCY_KEYWORDS.get(l, []):
            if kw.lower() in text_lower and kw not in found_urgency:
                found_urgency.append(kw)

        for kw in THREAT_KEYWORDS.get(l, []):
            if kw.lower() in text_lower and kw not in found_threats:
                found_threats.append(kw)

        for kw in REWARD_KEYWORDS.get(l, []):
            if kw.lower() in text_lower and kw not in found_rewards:
                found_rewards.append(kw)

        for kw in CREDENTIAL_KEYWORDS.get(l, []):
            if kw.lower() in text_lower and kw not in found_credentials:
                found_credentials.append(kw)

    # Behavioral Manipulation Patterns
    # 1. Excessive ALL CAPS (shouting / panic induction)
    words = text.split()
    caps_words = [w for w in words if len(w) >= 3 and w.isupper() and w.isalpha()]
    if len(caps_words) >= 3:
        manipulation_flags.append(f"Excessive capitalized words ({len(caps_words)} words) to induce panic or excitement")

    # 2. Excessive exclamation marks
    exclamation_count = text.count("!")
    if exclamation_count >= 3:
        manipulation_flags.append(f"Excessive exclamation points ({exclamation_count} detected) creating psychological pressure")

    # 3. Currency / Lottery lures
    currency_count = len(re.findall(r"[\$€£₹]\s*\d+", text))
    if currency_count >= 2:
        manipulation_flags.append(f"Multiple financial incentives/currency values detected ({currency_count} occurrences)")

    # Compute NLP heuristic risk contribution
    nlp_risk = 0
    if found_urgency:
        nlp_risk += min(len(found_urgency) * 15, 30)
    if found_threats:
        nlp_risk += min(len(found_threats) * 20, 40)
    if found_rewards:
        nlp_risk += min(len(found_rewards) * 15, 30)
    if found_credentials:
        nlp_risk += min(len(found_credentials) * 25, 50)
    if manipulation_flags:
        nlp_risk += len(manipulation_flags) * 10

    nlp_risk = min(max(nlp_risk, 0), 100)

    return {
        "urgency_triggers": found_urgency,
        "threat_triggers": found_threats,
        "reward_triggers": found_rewards,
        "credential_triggers": found_credentials,
        "manipulation_flags": manipulation_flags,
        "nlp_risk_points": nlp_risk,
        "manipulation_score": nlp_risk
    }
