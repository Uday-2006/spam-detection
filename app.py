"""
Flask Web Application: AI-Based Spam & Phishing Detection System
Provides complete web UI, authentication, REST APIs, and analytics.
"""

import os
import json
import io
import csv
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response, send_file
)
from werkzeug.security import check_password_hash

import database
from classifier_service import detector
from url_analyzer import analyze_single_url

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cyberdefense_secret_key_2026_secure")
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure Database is initialized on boot
database.init_db()


# --- Authentication Helper & Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Open access by default as requested: "first create this later on we will work on login page"
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user_context():
    """Inject logged-in user state and app metadata into all templates."""
    return {
        "current_user": {
            "id": session.get("user_id", 1),
            "username": session.get("username", "Analyst Security Profile"),
            "role": session.get("role", "Level 4 SecOps"),
            "is_authenticated": True
        },
        "app_name": "PhishShield AI",
        "app_title": "PhishShield AI - Threat Sentinel"
    }


# ==========================================
# PUBLIC & AUTHENTICATION ROUTES
# ==========================================

@app.route("/")
def index():
    """Directly loads the SOC Threat Intelligence Dashboard."""
    return dashboard()


@app.route("/login", methods=["GET", "POST"])
def login():
    """User Sign-in with secure password verification."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = database.get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}! Signed in successfully.", "success")
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        else:
            flash("Invalid username or password. Please try again.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """User Registration with password validation."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "warning")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "warning")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "warning")
            return render_template("register.html")

        user_id, error = database.create_user(username, email, password, role="user")
        if error:
            flash(error, "danger")
            return render_template("register.html")

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    """Clear session and log user out."""
    session.clear()
    flash("You have been securely signed out.", "info")
    return redirect(url_for("login"))


# ==========================================
# APPLICATION DASHBOARD & INTERFACE ROUTES
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():
    """Main Analytics & Threat Intelligence Dashboard."""
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    stats = database.get_dashboard_stats(user_id=user_id, is_admin=is_admin)

    # Load Model Metrics for display
    metrics_path = os.path.join(os.path.dirname(__file__), "models", "model_metrics.json")
    model_metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                model_metrics = json.load(f)
        except Exception:
            pass

    # Recent activity
    recent_detections = database.get_history(user_id=None if is_admin else user_id, limit=6)

    return render_template(
        "dashboard.html",
        stats=stats,
        model_metrics=model_metrics,
        recent_detections=recent_detections,
        is_admin=is_admin
    )


@app.route("/detect")
@login_required
def detect():
    """Detection Center page with interactive inputs and explainability meters."""
    return render_template("detect.html")


@app.route("/url-scanner")
@login_required
def url_scanner():
    """Standalone Suspicious URL Scanner."""
    return render_template("url_scanner.html")


@app.route("/history")
@login_required
def history():
    """Detection history audit log with search, filter, and export."""
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    return render_template("history.html", is_admin=is_admin)


@app.route("/feedback")
@login_required
def feedback():
    """User feedback and model evaluation audit page."""
    feedback_list = database.get_all_feedback()
    is_admin = session.get("role") == "admin"
    return render_template("feedback.html", feedback_list=feedback_list, is_admin=is_admin)


@app.route("/about")
def about():
    """Detailed technical documentation, viva notes, and architecture."""
    metrics_path = os.path.join(os.path.dirname(__file__), "models", "model_metrics.json")
    model_metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                model_metrics = json.load(f)
        except Exception:
            pass
    return render_template("about.html", model_metrics=model_metrics)


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route("/api/detect", methods=["POST"])
@login_required
def api_detect():
    """
    Main detection API endpoint.
    Accepts: { sender, subject, message }
    Returns: Complete JSON analysis + risk score + explainability
    """
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    subject = data.get("subject", "").strip()
    sender = data.get("sender", "").strip()

    if not message and not subject:
        return jsonify({"status": "error", "error": "Please enter a subject or message to analyze."}), 400

    # Run full detection pipeline
    result = detector.predict(message=message, subject=subject, sender=sender)

    if result.get("status") == "error":
        return jsonify(result), 400

    # Save to SQLite database
    user_id = session.get("user_id")
    det_id = database.save_detection(
        user_id=user_id,
        sender=sender,
        subject=subject,
        message=message,
        result=result
    )

    result["detection_id"] = det_id
    return jsonify(result)


@app.route("/api/scan-url", methods=["POST"])
@login_required
def api_scan_url():
    """Standalone URL scanner endpoint."""
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"status": "error", "error": "Please provide a valid URL to scan."}), 400

    analysis = analyze_single_url({"url": target_url, "display": target_url, "is_markdown": False})
    return jsonify({"status": "success", "result": analysis})


@app.route("/api/feedback", methods=["POST"])
@login_required
def api_submit_feedback():
    """Record user feedback on detection accuracy."""
    data = request.get_json() or {}
    det_id = data.get("detection_id")
    feedback_type = data.get("feedback_type", "correct")
    suggested = data.get("suggested_category", "")
    comments = data.get("comments", "").strip()

    if not det_id:
        return jsonify({"status": "error", "error": "Missing detection_id."}), 400

    user_id = session.get("user_id")
    fb_id = database.save_feedback(
        detection_id=det_id,
        user_id=user_id,
        feedback_type=feedback_type,
        suggested_category=suggested,
        comments=comments
    )

    return jsonify({"status": "success", "feedback_id": fb_id, "message": "Feedback submitted successfully! Thank you."})


@app.route("/api/stats", methods=["GET"])
@login_required
def api_stats():
    """Provide dashboard numbers, category counts, and daily timelines."""
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    stats = database.get_dashboard_stats(user_id=user_id, is_admin=is_admin)

    metrics_path = os.path.join(os.path.dirname(__file__), "models", "model_metrics.json")
    model_metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                model_metrics = json.load(f)
        except Exception:
            pass

    return jsonify({"stats": stats, "model_metrics": model_metrics})


@app.route("/api/history", methods=["GET"])
@login_required
def api_history():
    """Return filtered and searchable detection history."""
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    category = request.args.get("category", "All")
    risk_level = request.args.get("risk_level", "All")
    search = request.args.get("search", "").strip()

    rows = database.get_history(
        user_id=None if is_admin else user_id,
        category=category,
        risk_level=risk_level,
        search=search,
        limit=200
    )

    history_list = []
    for r in rows:
        history_list.append({
            "id": r["id"],
            "user_name": r["user_name"] or "Anonymous",
            "sender": r["sender"] or "N/A",
            "subject": r["subject"] or "No Subject",
            "message_content": r["message_content"],
            "category": r["detected_category"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "language": r["language"],
            "url_count": r["url_count"],
            "analysis_summary": json.loads(r["analysis_summary"]) if r["analysis_summary"] else {},
            "created_at": r["created_at"]
        })

    return jsonify({"status": "success", "data": history_list})


@app.route("/api/history/<int:det_id>", methods=["DELETE"])
@login_required
def api_delete_history(det_id):
    """Delete a detection record."""
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    success = database.delete_detection(det_id, user_id=user_id, is_admin=is_admin)
    return jsonify({"status": "success" if success else "error"})


@app.route("/api/export-history", methods=["GET"])
@login_required
def export_history_csv():
    """Generate and stream a CSV file containing detection history."""
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    rows = database.get_history(user_id=None if is_admin else user_id, limit=1000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Date", "Sender", "Subject", "Category", "Risk Score", "Risk Level", "Language", "Message Content"])

    for r in rows:
        writer.writerow([
            r["id"],
            r["created_at"],
            r["sender"] or "",
            r["subject"] or "",
            r["detected_category"],
            r["risk_score"],
            r["risk_level"],
            r["language"] or "",
            r["message_content"].replace("\n", " ")
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=detection_history.csv"}
    )


@app.route("/api/sample-messages", methods=["GET"])
def api_sample_messages():
    """Return pre-configured sample messages for quick 1-click testing."""
    samples = {
        "phishing_bank": {
            "title": "Bank Account Suspension (Phishing)",
            "sender": "security@chase-online-fraud-division.net",
            "subject": "URGENT: Suspicious wire transfer detected on your account!",
            "message": "A transfer of $3,450.00 to an offshore account was initiated. If you did NOT authorize this transfer, click immediately to cancel and secure your debit card: http://192.168.1.105/chase-cancel-wire. Failure to verify within 24 hours will result in permanent account locking.",
            "lang": "en"
        },
        "phishing_brand": {
            "title": "PayPal Credential Harvesting (Phishing)",
            "sender": "support@paypa1-security-update.com",
            "subject": "URGENT: Your PayPal Account Has Been Suspended!",
            "message": "Dear customer, We detected unauthorized login attempts from IP 185.220.101.4. You must verify your password and identity within 2 hours or your account balance will be permanently frozen: http://paypa1-security-update.com/login",
            "lang": "en"
        },
        "spam_lottery": {
            "title": "Walmart Gift Card Lottery (Spam)",
            "sender": "promo@megadeals-superstore.xyz",
            "subject": "CONGRATULATIONS! You have WON a $1,000 Walmart Gift Card!",
            "message": "You have been randomly selected as our lucky winner! Claim your $1000 gift card immediately! Click here to claim your free reward before midnight today! Limited inventory!",
            "lang": "en"
        },
        "safe_work": {
            "title": "Work Sprint Agenda (Safe)",
            "sender": "team@github.com",
            "subject": "Security alert: New sign-in from Chrome on Windows",
            "message": "Hi, We noticed a new sign-in to your GitHub account from Chrome on Windows. If this was you, you can safely ignore this email. If not, please review your recent activity in your settings.",
            "lang": "en"
        },
        "hindi_phishing": {
            "title": "SBI KYC Block Alert (Hindi Phishing)",
            "sender": "security@sbi-yono-update.loan",
            "subject": "SBI YONO Alert: Aapka SBI Bank Khata Block ho chuka hai!",
            "message": "Priy Grahak, Aapka SBI YONO khata KYC update na hone ke karan block kar diya gaya hai. Apna Aadhar, PAN Card aur Net Banking Password turant update karein: http://sbi-kyc-verification-login.xyz/update",
            "lang": "hi"
        },
        "spanish_phishing": {
            "title": "Banco Santander Alerta (Spanish Phishing)",
            "sender": "seguridad@banco-santander-verificacion.xyz",
            "subject": "AVISO URGENTE: Bloqueo inmediato de tu cuenta bancaria",
            "message": "Estimado cliente de Santander, por motivos de seguridad hemos bloqueado su acceso web. Para restablecer su tarjeta y clave de acceso, confirme sus datos aquí: http://santander-seguridad-banca-online.top/login",
            "lang": "es"
        },
        "french_phishing": {
            "title": "Banque Postale Sécurité (French Phishing)",
            "sender": "alerte@banque-postale-securite.top",
            "subject": "URGENT : Suspension immédiate de votre accès bancaire",
            "message": "Cher client, une tentative de connexion inhabituelle a été détectée sur votre compte. Pour débloquer votre carte et confirmer votre code secret, cliquez sur : http://labanquepostale-connexion-espace.xyz/client",
            "lang": "fr"
        }
    }
    return jsonify(samples)


if __name__ == "__main__":
    # Run locally on port 5000
    print("=" * 60)
    print("Starting AI-Based Spam & Phishing Detection System")
    print("Local URL: http://127.0.0.1:5000")
    print("Default Admin: admin / admin123")
    print("Default User:  analyst / analyst123")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
