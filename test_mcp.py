"""
Unit test for MCP Server functions
"""

import json
from mcp_server import detect_message, scan_url, get_threat_stats, get_recent_history

def test_mcp():
    print("Testing MCP detect_message...")
    res_raw = detect_message(
        message="URGENT: Your PayPal account has been suspended! Verify credentials at http://paypa1-security.xyz/login",
        subject="Action Required",
        sender="security@paypa1-security.xyz"
    )
    res = json.loads(res_raw)
    assert res["category"] == "Phishing", f"Expected Phishing, got {res['category']}"
    assert res["risk_score"] >= 70, f"Expected risk >= 70, got {res['risk_score']}"
    print(f" [PASS] detect_message: {res['category']} (Risk: {res['risk_score']})")

    print("Testing MCP scan_url...")
    url_res_raw = scan_url("http://192.168.1.100/chase-login")
    url_res = json.loads(url_res_raw)
    assert url_res["result"]["risk_score"] >= 40
    print(f" [PASS] scan_url: {url_res['result']['verdict']} (Risk: {url_res['result']['risk_score']})")

    print("Testing MCP get_threat_stats...")
    stats_raw = get_threat_stats()
    stats = json.loads(stats_raw)
    assert "stats" in stats and "model_metrics" in stats
    print(f" [PASS] get_threat_stats: Total analyzed {stats['stats']['total_analyzed']}")

    print("Testing MCP get_recent_history...")
    hist_raw = get_recent_history(limit=5)
    hist = json.loads(hist_raw)
    assert hist["status"] == "success"
    print(f" [PASS] get_recent_history: {hist['count']} items returned")

    print("\nALL MCP TOOLS VERIFIED SUCCESSFULLY!")

if __name__ == "__main__":
    test_mcp()
