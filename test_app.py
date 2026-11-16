"""
Comprehensive Test Suite for AI-Based Spam & Phishing Detection System
Validates end-to-end functionality across all routes, ML inference, and database.
"""

import sys
import json
from app import app
import database

def run_tests():
    print("=" * 65)
    print("RUNNING COMPREHENSIVE SYSTEM TESTS FOR PHISHSHIELD AI")
    print("=" * 65)

    client = app.test_client()
    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f" [PASS] {name}")
        else:
            print(f" [FAIL] {name} - {details}")

    # Test 1: Public Landing Page
    res = client.get("/")
    assert_test("Public Landing Page (GET /)", res.status_code == 200)

    # Test 2: Login Page
    res = client.get("/login")
    assert_test("Login Page (GET /login)", res.status_code == 200)

    # Test 3: User Authentication (Login as admin)
    res = client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
    assert_test("User Sign-in with default Admin", res.status_code == 200 and (b"Dashboard" in res.data or b"Sentinel" in res.data))

    # Test 4: Dashboard Page
    res = client.get("/dashboard")
    assert_test("Authenticated Dashboard Access", res.status_code == 200)

    # Test 5: Detect Page
    res = client.get("/detect")
    assert_test("Detection Center Page (GET /detect)", res.status_code == 200)

    # Test 6: API Detect - Phishing Message
    phish_payload = {
        "sender": "security@chase-fraud.net",
        "subject": "URGENT: Suspicious wire transfer detected on your account!",
        "message": "A transfer of $3,450.00 was initiated. Click immediately to cancel debit card: http://192.168.1.105/chase-wire. Failure to verify within 24 hours will result in permanent suspension."
    }
    res = client.post("/api/detect", json=phish_payload)
    data = res.get_json()
    assert_test(
        "API Detect (Phishing Test)",
        res.status_code == 200 and data.get("category") == "Phishing" and data.get("risk_score", 0) >= 70,
        f"Category: {data.get('category')}, Score: {data.get('risk_score')}"
    )
    det_id = data.get("detection_id")

    # Test 7: API Detect - Safe Message
    safe_payload = {
        "sender": "team@github.com",
        "subject": "Security alert: New sign-in from Chrome on Windows",
        "message": "Hi, We noticed a new sign-in to your GitHub account from Chrome on Windows. If this was you, you can safely ignore this email. If not, please review your recent activity."
    }
    res = client.post("/api/detect", json=safe_payload)
    safe_data = res.get_json()
    assert_test(
        "API Detect (Safe Test)",
        res.status_code == 200 and safe_data.get("category") == "Safe" and safe_data.get("risk_score", 100) <= 30,
        f"Category: {safe_data.get('category')}, Score: {safe_data.get('risk_score')}"
    )

    # Test 8: API Detect - Spam Message
    spam_payload = {
        "sender": "promo@megadeals.xyz",
        "subject": "CONGRATULATIONS! You have WON a $1,000 Walmart Gift Card!",
        "message": "You have been randomly selected as our lucky winner! Claim your $1000 gift card immediately! Click here to claim your free reward before midnight today!"
    }
    res = client.post("/api/detect", json=spam_payload)
    spam_data = res.get_json()
    assert_test(
        "API Detect (Spam Test)",
        res.status_code == 200 and spam_data.get("category") == "Spam" and 30 <= spam_data.get("risk_score", 0) <= 65,
        f"Category: {spam_data.get('category')}, Score: {spam_data.get('risk_score')}"
    )

    # Test 9: Standalone URL Scanner API
    url_payload = {"url": "http://paypa1-security-update.com/login"}
    res = client.post("/api/scan-url", json=url_payload)
    url_data = res.get_json()
    assert_test(
        "API Standalone URL Scanner",
        res.status_code == 200 and url_data.get("result", {}).get("risk_score", 0) >= 60,
        f"Result: {url_data.get('result', {}).get('verdict')}"
    )

    # Test 10: User Feedback Submission
    if det_id:
        fb_payload = {
            "detection_id": det_id,
            "feedback_type": "correct",
            "suggested_category": "Phishing",
            "comments": "Accurate phishing categorization."
        }
        res = client.post("/api/feedback", json=fb_payload)
        fb_data = res.get_json()
        assert_test(
            "API User Feedback Submission",
            res.status_code == 200 and fb_data.get("status") == "success"
        )

    # Test 11: History API
    res = client.get("/api/history")
    hist_data = res.get_json()
    assert_test(
        "API History Retrieval",
        res.status_code == 200 and len(hist_data.get("data", [])) > 0,
        f"Records found: {len(hist_data.get('data', []))}"
    )

    # Test 12: CSV History Export
    res = client.get("/api/export-history")
    assert_test(
        "CSV History Export Endpoint",
        res.status_code == 200 and "text/csv" in res.content_type and b"Category,Risk Score" in res.data
    )

    # Test 13: Dashboard Stats API
    res = client.get("/api/stats")
    stats_data = res.get_json()
    assert_test(
        "API Dashboard Stats & Model Metrics",
        res.status_code == 200 and "stats" in stats_data and "model_metrics" in stats_data
    )

    # Test 14: About Project Page
    res = client.get("/about")
    assert_test("About Project & Viva Notes Page (GET /about)", res.status_code == 200)

    print("=" * 65)
    print(f"TEST RESULTS: {passed}/{total} TESTS PASSED ({passed/total * 100:.1f}%)")
    print("=" * 65)

    if passed == total:
        print("ALL TESTS PASSED WITH ZERO ERRORS!")
        return 0
    else:
        print("SOME TESTS FAILED.")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
