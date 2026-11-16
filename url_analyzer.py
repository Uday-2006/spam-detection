"""
Suspicious URL Detection Engine
Performs safe, in-depth structural, lexical, and behavioral heuristic analysis
on URLs extracted from messages without ever initiating network connections.
"""

import re
from urllib.parse import urlparse

# Recognized URL Shortener Services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "goo.gl", "rotf.lol", "v.gd", "clck.ru", "shorturl.at"
}

# High-Risk / Commonly Abused Top Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".buzz", ".loan", ".biz",
    ".gq", ".cf", ".ml", ".tk", ".cc", ".to", ".info", ".online", ".site",
    ".website", ".live", ".space", ".surf", ".rest", ".fit"
}

# High-Value Brands Targeted in Phishing Campaigns
TARGETED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "chase", "wellsfargo",
    "bankofamerica", "netflix", "facebook", "instagram", "whatsapp", "binance",
    "coinbase", "dropbox", "sbi", "hdfc", "santander", "bbva", "steam", "linkedin",
    "citibank", "metamask", "dhl", "fedex", "usps", "adobe"
]

# Sensitive Path / Query Keywords
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "update", "banking",
    "account", "password", "authenticate", "signin", "kyc", "cancel-wire",
    "seed-phrase", "restore", "claim", "free", "bonus", "gift", "billing", "wallet"
]

IP_PATTERN = re.compile(
    r"^(?:http[s]?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$",
    re.IGNORECASE
)

URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))",
    re.IGNORECASE
)

MARKDOWN_LINK_REGEX = re.compile(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", re.IGNORECASE)


def extract_urls(text):
    """Extract all distinct URLs and markdown links from input text."""
    if not text:
        return []

    found_urls = []
    # Check for markdown links [Display](URL)
    for match in MARKDOWN_LINK_REGEX.finditer(text):
        display_text = match.group(1).strip()
        actual_url = match.group(2).strip()
        found_urls.append({"display": display_text, "url": actual_url, "is_markdown": True})

    # Standard regex extraction
    for match in URL_REGEX.finditer(text):
        raw_url = match.group(0).strip()
        # Clean trailing punctuation
        raw_url = re.sub(r"[,\.;:!?'\"\)]+$", "", raw_url)
        # Avoid duplicating markdown target
        if not any(item["url"] == raw_url for item in found_urls):
            found_urls.append({"display": raw_url, "url": raw_url, "is_markdown": False})

    return found_urls


def is_ip_address(netloc):
    """Check if the network location (hostname) is an IPv4 address."""
    clean_host = netloc.split(":")[0]
    parts = clean_host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


def detect_typosquatting(domain):
    """Detect brand lookalikes, leetspeak tricks, or spoofed hyphenations."""
    domain_lower = domain.lower()
    
    # Common leetspeak substitutions
    normalized = (domain_lower
                  .replace("0", "o")
                  .replace("1", "l")
                  .replace("3", "e")
                  .replace("5", "s")
                  .replace("@", "a")
                  .replace("v", "u"))

    detected = []
    for brand in TARGETED_BRANDS:
        # Check if brand is present inside a spoofed domain (e.g., paypa1-update.com or paypal.security-alert.xyz)
        if brand in normalized:
            # If the actual legitimate root domain is exactly brand.com / brand.org / etc, that's legitimate
            is_legit_root = (domain_lower == f"{brand}.com" or
                             domain_lower.endswith(f".{brand}.com") or
                             domain_lower == f"{brand}.org" or
                             domain_lower.endswith(f".{brand}.org"))
            if not is_legit_root:
                detected.append(brand)
    return list(set(detected))


def analyze_single_url(url_obj):
    """Perform comprehensive structural analysis on a single URL."""
    raw_url = url_obj["url"]
    display_text = url_obj.get("display", raw_url)
    
    # Prepend scheme if missing for proper parsing
    parse_target = raw_url
    has_scheme = bool(re.match(r"^https?://", parse_target, re.IGNORECASE))
    if not has_scheme:
        parse_target = "http://" + parse_target

    try:
        parsed = urlparse(parse_target)
    except Exception:
        return {
            "url": raw_url,
            "domain": "Malformed",
            "risk_score": 75,
            "flags": ["Malformed or invalid URL syntax"],
            "is_shortener": False,
            "is_ip": False,
            "has_https": False,
            "verdict": "Suspicious"
        }

    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    flags = []
    risk_score = 0

    # 1. Protocol Check
    has_https = parsed.scheme.lower() == "https"
    if not has_https:
        flags.append("Insecure HTTP protocol (no SSL/TLS encryption)")
        risk_score += 15

    # 2. IP Address as Hostname
    ip_mode = is_ip_address(netloc)
    if ip_mode:
        flags.append(f"Host uses raw numeric IP address ({netloc}) instead of domain name")
        risk_score += 45

    # 3. URL Shortener Detection
    is_short = any(netloc == short or netloc.endswith("." + short) for short in URL_SHORTENERS)
    if is_short:
        flags.append(f"Known URL shortener service ({netloc}) hides true destination")
        risk_score += 25

    # 4. Suspicious TLD Detection
    suspicious_tld_found = None
    for tld in SUSPICIOUS_TLDS:
        if netloc.endswith(tld):
            suspicious_tld_found = tld
            break
    if suspicious_tld_found:
        flags.append(f"High-risk top level domain ({suspicious_tld_found}) frequently used in phishing")
        risk_score += 25

    # 5. Lookalike / Brand Spoofing / Typosquatting
    spoofed_brands = detect_typosquatting(netloc)
    if spoofed_brands:
        flags.append(f"Brand impersonation / lookalike domain detected targeting: {', '.join(spoofed_brands)}")
        risk_score += 50

    # 6. Deceptive '@' Symbol in URL
    if "@" in raw_url:
        flags.append("Deceptive '@' symbol in URL (HTTP basic authentication trick)")
        risk_score += 40

    # 7. Excessive Subdomains (Deep Subdomain Layering)
    subdomain_parts = [p for p in netloc.split(".") if p]
    if len(subdomain_parts) >= 4 and not ip_mode:
        flags.append(f"Excessive subdomain depth ({len(subdomain_parts)} parts) masking destination")
        risk_score += 20

    # 8. Suspicious Path / Query Keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query]
    if found_keywords:
        flags.append(f"Sensitive keywords in URL path/query: {', '.join(found_keywords[:4])}")
        risk_score += min(len(found_keywords) * 10, 30)

    # 9. Excessive URL Length
    if len(raw_url) > 75:
        flags.append(f"Unusually long URL structure ({len(raw_url)} characters)")
        risk_score += 10

    # 10. Mismatched Display Text vs Actual URL
    if url_obj.get("is_markdown", False) and display_text != raw_url:
        # Check if display text pretends to be a different domain
        if re.search(r"https?://|[a-z0-9\-]+\.[a-z]{2,}", display_text, re.IGNORECASE):
            clean_display = display_text.lower().replace("https://", "").replace("http://", "").split("/")[0]
            if clean_display not in netloc and netloc not in clean_display:
                flags.append(f"Anchor deception: displayed link '{display_text}' leads to '{netloc}'")
                risk_score += 45

    risk_score = min(max(risk_score, 0), 100)
    verdict = "High Risk" if risk_score >= 60 else ("Medium Risk" if risk_score >= 30 else "Low Risk")

    return {
        "url": raw_url,
        "display": display_text,
        "domain": netloc,
        "path": path,
        "has_https": has_https,
        "is_ip": ip_mode,
        "is_shortener": is_short,
        "risk_score": risk_score,
        "verdict": verdict,
        "flags": flags
    }


def analyze_message_urls(text):
    """Extract and analyze all URLs found inside a message."""
    extracted = extract_urls(text)
    details = [analyze_single_url(u) for u in extracted]

    if not details:
        return {
            "url_count": 0,
            "has_urls": False,
            "max_url_risk": 0,
            "average_url_risk": 0,
            "url_risk_level": "None",
            "url_threat_flags": [],
            "urls": []
        }

    max_risk = max(d["risk_score"] for d in details)
    avg_risk = int(sum(d["risk_score"] for d in details) / len(details))
    all_flags = []
    for d in details:
        for f in d["flags"]:
            if f not in all_flags:
                all_flags.append(f)

    risk_level = "High Risk" if max_risk >= 60 else ("Medium Risk" if max_risk >= 30 else "Low Risk")

    return {
        "url_count": len(details),
        "has_urls": True,
        "max_url_risk": max_risk,
        "average_url_risk": avg_risk,
        "url_risk_level": risk_level,
        "url_threat_flags": all_flags,
        "urls": details
    }
