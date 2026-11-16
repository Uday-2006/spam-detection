"""
Model Context Protocol (MCP) Server for PhishShield AI
Exposes AI-based spam and phishing detection tools, URL forensics,
and threat intelligence query capabilities to MCP clients.

Compatible with Antigravity, Claude Desktop, Cursor, and any standard MCP client.
"""

import os
import json
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from mcp.server.mcpserver import MCPServer

import database
from classifier_service import detector
from url_analyzer import analyze_single_url

# Initialize SQLite database
database.init_db()

# Initialize MCPServer instance
mcp = MCPServer(
    name="phishshield-ai",
    version="2.4.0",
    description="AI-Based Spam, Phishing, and URL Threat Detection System"
)


@mcp.tool()
def detect_message(message: str, subject: str = "", sender: str = "") -> str:
    """
    Analyze an email or text message for spam and phishing threats using NLP, Machine Learning, and URL analysis.

    Args:
        message: The body text or email content to analyze.
        subject: Optional email subject line.
        sender: Optional sender email address (e.g. support@paypal-verify.xyz).

    Returns:
        JSON string containing category (Safe, Spam, Phishing), risk score (0-100),
        language detected, ML confidence, NLP threat triggers, and explainability report.
    """
    if not message.strip() and not subject.strip():
        return json.dumps({"status": "error", "error": "Empty message or subject provided."})

    result = detector.predict(message=message, subject=subject, sender=sender)
    if result.get("status") == "error":
        return json.dumps(result)

    # Log to SQLite database
    det_id = database.save_detection(
        user_id=1,  # Default system/MCP user
        sender=sender,
        subject=subject,
        message=message,
        result=result
    )
    result["detection_id"] = det_id
    return json.dumps(result, indent=2)


@mcp.tool()
def scan_url(url: str) -> str:
    """
    Perform passive structural forensic analysis on a suspicious URL.
    Checks for numeric IP hostnames, typosquatting (brand lookalikes),
    URL shorteners, high-risk TLDs (.xyz, .top, .buzz), and insecure HTTP.
    Does NOT connect to or open the remote URL.

    Args:
        url: The web address or link to analyze.

    Returns:
        JSON string containing risk score (0-100), verdict, domain, and detected threat flags.
    """
    if not url.strip():
        return json.dumps({"status": "error", "error": "Empty URL provided."})

    res = analyze_single_url({"url": url.strip(), "display": url.strip(), "is_markdown": False})
    return json.dumps({"status": "success", "result": res}, indent=2)


@mcp.tool()
def get_threat_stats() -> str:
    """
    Retrieve real-time threat intelligence analytics, message counts by category,
    and machine learning model evaluation metrics.

    Returns:
        JSON string with total analyzed messages, category breakdown (Safe, Spam, Phishing),
        risk severity distribution, and ML model accuracy/F1 metrics.
    """
    stats = database.get_dashboard_stats()

    metrics_path = os.path.join(BASE_DIR, "models", "model_metrics.json")
    model_metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                model_metrics = json.load(f)
        except Exception:
            pass

    return json.dumps({"stats": stats, "model_metrics": model_metrics}, indent=2)


@mcp.tool()
def get_recent_history(limit: int = 10, category: str = "All") -> str:
    """
    Query the detection history audit log from the SQLite database.

    Args:
        limit: Maximum number of detection records to return (default 10).
        category: Filter by category ('All', 'Safe', 'Spam', 'Phishing').

    Returns:
        JSON list of historical detection events.
    """
    rows = database.get_history(category=category, limit=limit)
    records = []
    for r in rows:
        records.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "sender": r["sender"],
            "subject": r["subject"],
            "category": r["detected_category"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "language": r["language"],
            "url_count": r["url_count"]
        })
    return json.dumps({"status": "success", "count": len(records), "data": records}, indent=2)


@mcp.tool()
def submit_feedback(detection_id: int, feedback_type: str, suggested_category: str = "", comments: str = "") -> str:
    """
    Submit human analyst verification feedback for a detection event.
    Logs feedback for human supervisor review without automatically retraining the model.

    Args:
        detection_id: ID of the detection record.
        feedback_type: 'correct', 'false_positive', or 'false_negative'.
        suggested_category: Corrected category if incorrect ('Safe', 'Spam', 'Phishing').
        comments: Optional reasoning notes.

    Returns:
        JSON confirmation string.
    """
    fb_id = database.save_feedback(
        detection_id=detection_id,
        user_id=1,
        feedback_type=feedback_type,
        suggested_category=suggested_category,
        comments=comments
    )
    return json.dumps({
        "status": "success",
        "feedback_id": fb_id,
        "message": "Feedback recorded in human audit queue."
    }, indent=2)


if __name__ == "__main__":
    # Run the MCP server over standard input/output (stdio)
    mcp.run(transport="stdio")
