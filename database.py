"""
SQLite Database Layer for AI-Based Spam & Phishing Detection System
Manages secure authentication, detection history, and model feedback logging.
"""

import os
import json
import shutil
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DB_PATH = os.path.join(BASE_DIR, "database.db")

# In serverless environments like Vercel, only /tmp is writable
if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/database.db"
    if not os.path.exists(DB_PATH) and os.path.exists(REPO_DB_PATH):
        try:
            shutil.copy2(REPO_DB_PATH, DB_PATH)
        except Exception as e:
            print(f"[Database] Notice: Initializing new database in /tmp: {e}")
else:
    DB_PATH = REPO_DB_PATH


def get_db_connection():
    """Create and return a row-factory SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables and seed baseline users & sample records."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Detections Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sender TEXT,
            subject TEXT,
            message_content TEXT NOT NULL,
            detected_category TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            language TEXT,
            url_count INTEGER DEFAULT 0,
            analysis_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # 3. User Feedback Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER NOT NULL,
            user_id INTEGER,
            feedback_type TEXT NOT NULL,
            user_suggested_category TEXT,
            comments TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (detection_id) REFERENCES detections (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    conn.commit()

    # Seed Default Users if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_pass = generate_password_hash("admin123")
        analyst_pass = generate_password_hash("analyst123")

        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("admin", "admin@cyberdefense.local", admin_pass, "admin")
        )
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("analyst", "analyst@cyberdefense.local", analyst_pass, "user")
        )
        conn.commit()
        print("[Database] Seeded default users: 'admin' (admin123) and 'analyst' (analyst123).")

    # Seed Sample Detections if empty
    cursor.execute("SELECT COUNT(*) FROM detections")
    if cursor.fetchone()[0] == 0:
        seed_sample_detections(conn)

    conn.close()


def seed_sample_detections(conn):
    """Seed realistic initial detection events for immediate visual analytics."""
    cursor = conn.cursor()
    now = datetime.now()

    sample_items = [
        (
            1, "security@paypa1-update.com", "URGENT: Your PayPal Account Has Been Suspended!",
            "We detected unauthorized login attempts. You must verify your identity within 24 hours: http://paypa1-security-update.com/login",
            "Phishing", 98, "High Risk", "English", 1,
            json.dumps({"flags": ["Brand lookalike domain", "Insecure HTTP", "Urgency tactic"], "phishing_prob": 0.98}),
            (now - timedelta(days=6, hours=4)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        (
            1, "billing@digitalocean.com", "Your monthly droplet statement",
            "Your payment of $12.00 for Droplet-Compute-Node has been processed successfully. Download the receipt from your portal.",
            "Safe", 12, "Low Risk", "English", 0,
            json.dumps({"flags": [], "safe_prob": 0.94}),
            (now - timedelta(days=5, hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        (
            2, "promo@megadeals-superstore.xyz", "CONGRATULATIONS! You have WON a $1,000 Walmart Gift Card!",
            "You have been randomly selected as our lucky winner! Claim your $1000 gift card immediately! Limited inventory!",
            "Spam", 52, "Medium Risk", "English", 0,
            json.dumps({"flags": ["Promotional prize claim", "Suspicious TLD .xyz"], "spam_prob": 0.91}),
            (now - timedelta(days=4, hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        (
            2, "alert@chase-online-fraud-division.net", "Suspicious wire transfer detected on your account!",
            "A transfer of $3,450.00 was initiated. Click immediately to cancel and secure your debit card: http://192.168.1.105/chase-cancel-wire",
            "Phishing", 100, "High Risk", "English", 1,
            json.dumps({"flags": ["Raw IP address host", "Urgency tactic", "Financial intimidation"], "phishing_prob": 0.99}),
            (now - timedelta(days=3, hours=11)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        (
            1, "security@sbi-yono-update.loan", "SBI YONO Alert: Aapka SBI Bank Khata Block ho chuka hai!",
            "Priy Grahak, Aapka SBI YONO khata KYC update na hone ke karan block kar diya gaya hai. Net Banking Password turant update karein: http://sbi-kyc-verification-login.xyz/update",
            "Phishing", 95, "High Risk", "Hindi (Hinglish)", 1,
            json.dumps({"flags": ["Hindi KYC phish", "High-risk TLD .loan", "Credential harvesting"], "phishing_prob": 0.96}),
            (now - timedelta(days=2, hours=6)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        (
            2, "newsletter@morningbrew.com", "Today's top business tech stories",
            "Good morning! Today we cover semiconductor developments, tech earnings reports, and market updates. Grab your coffee and enjoy the read.",
            "Safe", 14, "Low Risk", "English", 0,
            json.dumps({"flags": [], "safe_prob": 0.95}),
            (now - timedelta(days=1, hours=3)).strftime("%Y-%m-%d %H:%M:%S")
        ),
        (
            1, "offers@instant-loans-express.top", "Instant Cash Loan Approved! No credit check required!",
            "Need cash right now? You are pre-approved for up to $25,000 with 0% interest! Instant payout into your account!",
            "Spam", 48, "Medium Risk", "English", 0,
            json.dumps({"flags": ["Instant cash loan", "High-risk TLD .top"], "spam_prob": 0.88}),
            (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S")
        )
    ]

    for item in sample_items:
        cursor.execute("""
            INSERT INTO detections (
                user_id, sender, subject, message_content, detected_category,
                risk_score, risk_level, language, url_count, analysis_summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, item)

    # Add sample feedback records
    cursor.execute("""
        INSERT INTO feedback (detection_id, user_id, feedback_type, user_suggested_category, comments, created_at)
        VALUES (1, 1, 'correct', 'Phishing', 'Accurately flagged spoofed domain and phishing urgency.', datetime('now', '-5 days'))
    """)
    cursor.execute("""
        INSERT INTO feedback (detection_id, user_id, feedback_type, user_suggested_category, comments, created_at)
        VALUES (2, 1, 'correct', 'Safe', 'Properly marked normal billing invoice as legitimate.', datetime('now', '-4 days'))
    """)

    conn.commit()
    print("[Database] Seeded sample detection records and feedback.")


# --- User Authentication Helpers ---
def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def create_user(username, email, password, role="user"):
    conn = get_db_connection()
    cursor = conn.cursor()
    pwd_hash = generate_password_hash(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, pwd_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id, None
    except sqlite3.IntegrityError as e:
        conn.close()
        return None, "Username or Email already registered."


# --- Detection Helpers ---
def save_detection(user_id, sender, subject, message, result):
    conn = get_db_connection()
    cursor = conn.cursor()

    analysis_json = json.dumps({
        "ml": result.get("ml_analysis"),
        "nlp": result.get("nlp_analysis"),
        "url": result.get("url_analysis"),
        "sender": result.get("sender_analysis"),
        "explanations": result.get("explanations", [])
    })

    cursor.execute("""
        INSERT INTO detections (
            user_id, sender, subject, message_content, detected_category,
            risk_score, risk_level, language, url_count, analysis_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        sender,
        subject,
        message,
        result["category"],
        result["risk_score"],
        result["risk_level"],
        result["language"]["name"],
        result["url_analysis"]["url_count"],
        analysis_json
    ))
    conn.commit()
    det_id = cursor.lastrowid
    conn.close()
    return det_id


def get_detection_by_id(det_id):
    conn = get_db_connection()
    det = conn.execute("""
        SELECT d.*, u.username as user_name
        FROM detections d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE d.id = ?
    """, (det_id,)).fetchone()
    conn.close()
    return det


def get_history(user_id=None, category=None, risk_level=None, search=None, limit=100):
    conn = get_db_connection()
    query = """
        SELECT d.*, u.username as user_name
        FROM detections d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE 1=1
    """
    params = []

    if user_id:
        query += " AND d.user_id = ?"
        params.append(user_id)

    if category and category != "All":
        query += " AND d.detected_category = ?"
        params.append(category)

    if risk_level and risk_level != "All":
        query += " AND d.risk_level = ?"
        params.append(risk_level)

    if search:
        query += " AND (d.subject LIKE ? OR d.message_content LIKE ? OR d.sender LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY d.created_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def delete_detection(det_id, user_id=None, is_admin=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    if is_admin or not user_id:
        cursor.execute("DELETE FROM detections WHERE id = ?", (det_id,))
    else:
        cursor.execute("DELETE FROM detections WHERE id = ? AND user_id = ?", (det_id, user_id))
    cursor.execute("DELETE FROM feedback WHERE detection_id = ?", (det_id,))
    conn.commit()
    conn.close()
    return True


# --- Feedback Helpers ---
def save_feedback(detection_id, user_id, feedback_type, suggested_category="", comments=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO feedback (detection_id, user_id, feedback_type, user_suggested_category, comments)
        VALUES (?, ?, ?, ?, ?)
    """, (detection_id, user_id, feedback_type, suggested_category, comments))
    conn.commit()
    fb_id = cursor.lastrowid
    conn.close()
    return fb_id


def get_all_feedback():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT f.*, d.detected_category, d.subject, d.risk_score, u.username
        FROM feedback f
        JOIN detections d ON f.detection_id = d.id
        LEFT JOIN users u ON f.user_id = u.id
        ORDER BY f.created_at DESC
    """).fetchall()
    conn.close()
    return rows


# --- Dashboard Analytics ---
def get_dashboard_stats(user_id=None, is_admin=False):
    conn = get_db_connection()

    filter_clause = ""
    params = []
    if not is_admin and user_id:
        filter_clause = " WHERE user_id = ?"
        params.append(user_id)

    # Total counts
    total = conn.execute(f"SELECT COUNT(*) FROM detections{filter_clause}", params).fetchone()[0]

    cat_query = f"SELECT detected_category, COUNT(*) FROM detections{filter_clause} GROUP BY detected_category"
    cat_rows = conn.execute(cat_query, params).fetchall()
    categories = {"Safe": 0, "Spam": 0, "Phishing": 0}
    for row in cat_rows:
        if row[0] in categories:
            categories[row[0]] = row[1]

    # Risk level counts
    risk_query = f"SELECT risk_level, COUNT(*) FROM detections{filter_clause} GROUP BY risk_level"
    risk_rows = conn.execute(risk_query, params).fetchall()
    risk_distribution = {"Low Risk": 0, "Medium Risk": 0, "High Risk": 0}
    for row in risk_rows:
        if row[0] in risk_distribution:
            risk_distribution[row[0]] = row[1]

    # Daily activity for the last 7 days
    daily_query = f"""
        SELECT strftime('%Y-%m-%d', created_at) as day, COUNT(*) as count
        FROM detections
        {filter_clause}
        GROUP BY day
        ORDER BY day DESC
        LIMIT 7
    """
    daily_rows = conn.execute(daily_query, params).fetchall()
    timeline = [{"day": r["day"], "count": r["count"]} for r in reversed(daily_rows)]

    # Feedback breakdown
    fb_correct = conn.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type = 'correct'").fetchone()[0]
    fb_false_pos = conn.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type = 'false_positive'").fetchone()[0]
    fb_false_neg = conn.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type = 'false_negative'").fetchone()[0]

    # Total registered users
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    conn.close()

    return {
        "total_analyzed": total,
        "categories": categories,
        "risk_distribution": risk_distribution,
        "timeline": timeline,
        "feedback": {
            "correct": fb_correct,
            "false_positive": fb_false_pos,
            "false_negative": fb_false_neg,
            "total": fb_correct + fb_false_pos + fb_false_neg
        },
        "total_users": total_users
    }
