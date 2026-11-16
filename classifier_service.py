"""
Classifier Service: Integrates ML Model, NLP Engine, and Suspicious URL Analyzer
Computes composite risk score (0-100), categorization (Safe, Spam, Phishing),
and transparent explainability reports.
"""

import os
import re
import joblib
import numpy as np

from nlp_engine import detect_language, clean_text_for_ml, analyze_linguistic_threats
from url_analyzer import analyze_message_urls


class SpamPhishingDetector:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(base_dir, "models", "spam_model.pkl")
        self.vectorizer_path = os.path.join(base_dir, "models", "tfidf_vectorizer.pkl")
        self.model = None
        self.vectorizer = None
        self.load_model()

    def load_model(self):
        """Load the pre-trained ML model and TF-IDF vectorizer into memory."""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                print("[Detector] Pre-trained ML model and vectorizer loaded successfully.")
            else:
                print("[Detector] Warning: Model files not found. Run train_model.py first.")
        except Exception as e:
            print(f"[Detector] Error loading model: {e}")

    def analyze_sender(self, sender_email, subject, message):
        """Analyze sender domain, lookalikes, and mismatched branding."""
        if not sender_email or "@" not in sender_email:
            return {
                "sender_valid": False,
                "sender_flags": ["Missing or invalid sender email format"],
                "sender_risk": 10
            }

        sender_email = sender_email.strip().lower()
        domain = sender_email.split("@")[-1]
        flags = []
        risk = 0

        # Check for suspicious sender TLD
        from url_analyzer import SUSPICIOUS_TLDS, TARGETED_BRANDS, detect_typosquatting
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(f"Sender uses high-risk suspicious TLD: {tld}")
                risk += 25
                break

        # Check for typosquatting / spoofed brand in sender domain
        spoofed = detect_typosquatting(domain)
        if spoofed:
            flags.append(f"Sender domain impersonates brand: {', '.join(spoofed)}")
            risk += 40

        # Brand mismatch: check if body mentions official brand but sender is third-party
        text_lower = (subject + " " + message).lower()
        for brand in ["paypal", "apple", "chase", "microsoft", "google", "amazon", "netflix", "sbi", "hdfc"]:
            if brand in text_lower:
                if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com") or
                        domain == f"{brand}.co.in" or domain.endswith(f".{brand}.co.in")):
                    flags.append(f"Brand mismatch: Message mentions {brand.capitalize()}, but sender domain is '{domain}'")
                    risk += 25
                    break

        return {
            "sender_valid": True,
            "domain": domain,
            "sender_flags": flags,
            "sender_risk": min(risk, 50)
        }

    def predict(self, message, subject="", sender=""):
        """
        Executes end-to-end detection pipeline:
        1. Language identification
        2. NLP Threat & Urgency extraction
        3. URL structural & behavioral analysis
        4. Sender domain reputation check
        5. Machine learning classification
        6. Composite Risk Scoring & Explainability
        """
        combined_text = f"{subject} {message}".strip()
        if not combined_text:
            return {
                "status": "error",
                "error": "Empty message content provided."
            }

        # 1. Detect Language
        lang_code, lang_name, is_supported = detect_language(combined_text)

        # 2. Extract NLP & Semantic Threats
        nlp_res = analyze_linguistic_threats(combined_text, lang_code=lang_code)

        # 3. Analyze Suspicious URLs
        url_res = analyze_message_urls(combined_text)

        # 4. Analyze Sender Email
        sender_res = self.analyze_sender(sender, subject, message)

        # 5. Machine Learning Inference
        ml_prediction = "Safe"
        ml_probabilities = {"Safe": 0.33, "Spam": 0.33, "Phishing": 0.33}
        top_ml_category = "Safe"
        ml_confidence = 0.50

        if self.model and self.vectorizer:
            cleaned = clean_text_for_ml(combined_text)
            features = self.vectorizer.transform([cleaned])
            classes = list(self.model.classes_)
            probas = self.model.predict_proba(features)[0]

            ml_probabilities = {cls_name: round(float(prob), 4) for cls_name, prob in zip(classes, probas)}
            top_ml_category = classes[np.argmax(probas)]
            ml_confidence = round(float(np.max(probas)), 4)
            ml_prediction = top_ml_category

        # 6. Composite Risk Score Calculation (0 - 100)
        # Factors: ML probabilities, URL threats, NLP triggers, Sender flags
        phish_prob = ml_probabilities.get("Phishing", 0.0)
        spam_prob = ml_probabilities.get("Spam", 0.0)
        safe_prob = ml_probabilities.get("Safe", 0.0)

        # Base risk from ML model
        base_ml_risk = (phish_prob * 85) + (spam_prob * 45) + (safe_prob * 10)

        # Additional risk additions
        url_risk_contrib = url_res["max_url_risk"] * 0.40
        nlp_risk_contrib = nlp_res["nlp_risk_points"] * 0.35
        sender_risk_contrib = sender_res["sender_risk"] * 0.35

        composite_score = int(round(
            (base_ml_risk * 0.45) +
            url_risk_contrib +
            nlp_risk_contrib +
            sender_risk_contrib
        ))

        # Phishing override triggers (critical cybersecurity defenses)
        is_hard_phish = False
        if any("Brand impersonation" in f or "Anchor deception" in f or "numeric IP" in f for f in url_res["url_threat_flags"]):
            is_hard_phish = True
            composite_score = max(composite_score, 78)

        if len(nlp_res["credential_triggers"]) >= 1 and (len(nlp_res["threat_triggers"]) >= 1 or len(nlp_res["urgency_triggers"]) >= 1):
            composite_score = max(composite_score, 72)

        # Clamping
        composite_score = max(0, min(composite_score, 100))

        # Final Category Determination
        if composite_score >= 61 or is_hard_phish:
            final_category = "Phishing"
            risk_level = "High Risk"
            risk_color = "#ff3366"  # Crimson Red
        elif composite_score >= 31:
            final_category = "Spam"
            risk_level = "Medium Risk"
            risk_color = "#ffb703"  # Amber Orange
        else:
            final_category = "Safe"
            risk_level = "Low Risk"
            risk_color = "#00f5d4"  # Neon Cyan / Emerald

        # 7. Generate Explainability Report
        explanations = []

        if final_category == "Phishing":
            explanations.append(f"Model identified high-confidence phishing indicators (Phishing confidence: {phish_prob * 100:.1f}%).")
        elif final_category == "Spam":
            explanations.append(f"Message exhibits characteristics of unsolicited commercial spam or promotional content (Confidence: {spam_prob * 100:.1f}%).")
        else:
            explanations.append(f"Message conforms to legitimate correspondence patterns (Legitimacy confidence: {safe_prob * 100:.1f}%).")

        # Linguistic Triggers
        if nlp_res["urgency_triggers"]:
            explanations.append(f"Urgency tactics detected: {', '.join(nlp_res['urgency_triggers'][:4])} (used to rush the victim).")
        if nlp_res["threat_triggers"]:
            explanations.append(f"Intimidating / threatening language detected: {', '.join(nlp_res['threat_triggers'][:4])}.")
        if nlp_res["reward_triggers"]:
            explanations.append(f"Suspicious reward / prize claims: {', '.join(nlp_res['reward_triggers'][:4])}.")
        if nlp_res["credential_triggers"]:
            explanations.append(f"Explicit requests for sensitive credentials: {', '.join(nlp_res['credential_triggers'][:4])}.")
        for m_flag in nlp_res["manipulation_flags"]:
            explanations.append(m_flag)

        # URL Triggers
        for u_flag in url_res["url_threat_flags"]:
            explanations.append(f"URL Security Warning: {u_flag}")

        # Sender Triggers
        for s_flag in sender_res["sender_flags"]:
            explanations.append(f"Sender Warning: {s_flag}")

        if not is_supported:
            explanations.append("Language Note: Language not officially supported (English, Hindi, Spanish, French supported). Generic structural heuristics applied.")

        if not explanations:
            explanations.append("No abnormal security risks or malicious markers were identified.")

        return {
            "status": "success",
            "category": final_category,
            "risk_score": composite_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "language": {
                "code": lang_code,
                "name": lang_name,
                "supported": is_supported
            },
            "ml_analysis": {
                "predicted_label": ml_prediction,
                "confidence": ml_confidence,
                "probabilities": ml_probabilities
            },
            "nlp_analysis": nlp_res,
            "url_analysis": url_res,
            "sender_analysis": sender_res,
            "explanations": explanations
        }


# Singleton instance
detector = SpamPhishingDetector()
