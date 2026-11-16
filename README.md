# AI-Based Spam and Phishing Email/Message Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.9-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cybersecurity](https://img.shields.io/badge/Focus-Threat%20Intelligence-cyan.svg)](#)

A modern, full-stack cybersecurity web application designed to detect, classify, and explain spam and phishing messages using **Natural Language Processing (NLP)**, **Machine Learning**, and **Suspicious URL Analysis**.

---

## 1. Project Overview

Modern cyber attacks frequently bypass static blacklists and spam filters using linguistic urgency, lookalike typosquatted domains, transliterated foreign languages, and deceptive anchor links. This project delivers an enterprise-grade defense platform that combines:
1. **Multinomial Logistic Regression + TF-IDF Vectorization** (Unigrams & Bigrams)
2. **Semantic NLP Feature Analysis** (Urgency, Threat intimidation, Fake Rewards, Credential demands)
3. **Passive Zero-Click URL Forensics** (Raw numeric IPs, Typosquatting, URL shorteners, Insecure HTTP, Deep subdomains)
4. **Composite Risk Scoring Engine (0 to 100)** with clear explainability
5. **Multilingual Support** for English, Hindi (Devanagari & Hinglish), Spanish, and French
6. **Human-in-the-Loop Feedback Management** with anti-data poisoning safeguards

---

## 2. Technology Stack

- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Bootstrap 5, FontAwesome 6
- **Data Visualization:** Chart.js 4 (Doughnut, Bar, Line charts)
- **Backend Framework:** Python Flask
- **Machine Learning:** Scikit-Learn (TF-IDF Vectorizer + Multinomial Logistic Regression)
- **Natural Language Processing:** Regex tokenizers, custom multilingual semantic lexicon
- **URL Forensics:** `urllib.parse` structural parser & Typosquatting engine
- **Database:** SQLite 3 (ACID compliant, parameterized queries)
- **Security:** PBKDF2:SHA256 password hashing via Werkzeug, Zero-click link isolation
- **AI Agent Integration:** Model Context Protocol (MCP) Server via `mcp 2.x` (Stdio transport)

---

## 3. Model Context Protocol (MCP) Integration

The project includes an **MCP Server** ([mcp_server.py](file:///c:/Users/ayush/OneDrive/Desktop/spam%20detection/mcp_server.py)) that allows AI assistants (Antigravity, Claude Desktop, Cursor, etc.) to connect to the detection system and invoke tools natively.

### Available MCP Tools:
1. `detect_message`: Runs full NLP, ML classification, and URL heuristics on a message, saving the detection to SQLite and returning the verdict, risk score (0-100), and explainability report.
2. `scan_url`: Inspects links for numeric IPs, typosquatting (brand lookalikes), URL shorteners, and suspicious TLDs.
3. `get_threat_stats`: Returns threat statistics, category distributions, and ML model performance metrics.
4. `get_recent_history`: Queries recent detection events from the audit log.
5. `submit_feedback`: Records human verification feedback into the database.

### Connecting Through MCP:

Add the following to your MCP client configuration (e.g. `.agents/mcp_config.json`, `~/.gemini/config/mcp_config.json`, or Claude Desktop's `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "phishshield": {
      "command": "c:\\Users\\ayush\\OneDrive\\Desktop\\spam detection\\.venv\\Scripts\\python.exe",
      "args": [
        "c:\\Users\\ayush\\OneDrive\\Desktop\\spam detection\\mcp_server.py"
      ],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

---

## 4. Directory Structure

```
spam_phishing_detector/
│
├── app.py                      # Flask application routes, REST API, authentication
├── train_model.py              # ML training, evaluation, metrics export pipeline
├── classifier_service.py       # End-to-end detection service & composite scoring
├── nlp_engine.py               # Language detection & semantic threat extraction
├── url_analyzer.py             # Passive structural URL vulnerability scanner
├── database.py                 # SQLite database schema, helpers, and sample seeders
├── generate_dataset.py         # Curated multi-lingual dataset generator
├── requirements.txt            # Dependency manifest
├── database.db                 # SQLite database
│
├── models/
│   ├── spam_model.pkl          # Trained classifier model
│   ├── tfidf_vectorizer.pkl    # Fitted TF-IDF vectorizer
│   └── model_metrics.json      # Accuracy, F1, Precision, Confusion Matrix JSON
│
├── dataset/
│   └── spam_dataset.csv        # Balanced dataset (Safe, Spam, Phishing)
│
├── templates/
│   ├── base.html               # Master layout with cyber theme, sidebar, navbar
│   ├── index.html              # Landing page with pipeline overview & metrics
│   ├── login.html              # Authentication sign-in with 1-click demo chips
│   ├── register.html           # User registration with password strength meter
│   ├── dashboard.html          # Interactive analytics & model performance cards
│   ├── detect.html             # Main detection center with 1-click test scenarios
│   ├── url_scanner.html        # Standalone suspicious URL inspection engine
│   ├── history.html            # Searchable, filterable audit log with CSV export
│   ├── feedback.html           # Analyst feedback reviews & retraining audit
│   └── about.html              # Project specs, architecture flow, and viva Q&A
│
├── static/
│   ├── css/
│   │   └── style.css           # Cybersecurity navy/cyan/emerald theme & glassmorphism
│   └── js/
│       ├── main.js             # Theme switcher (dark/light), mobile navigation
│       └── dashboard.js        # Chart.js renderers
│
└── README.md                   # Comprehensive documentation
```

---

## 4. Key Features

### A. Authentication & Role-Based Access
- User registration and login with PBKDF2:SHA256 password hashing.
- Role management (`admin` and `user`).
- Pre-seeded demo credentials for instant evaluation:
  - **Admin:** `admin` / `admin123`
  - **Analyst:** `analyst` / `analyst123`

### B. Machine Learning Classification
- Classifies input messages into **Safe**, **Spam**, or **Phishing**.
- Outputs multi-class probabilities using calibrated logistic regression.
- Evaluated on test set:
  - **Overall Accuracy:** `93.94%`
  - **Macro F1-Score:** `94.10%`
  - **Phishing Precision:** `100.0%`
  - **Phishing Recall:** `100.0%`
  - **False Positive Rate:** `7.69%`

### C. Suspicious URL Detection Engine
- Analyzes hyperlinks extracted from messages without ever connecting to remote servers:
  - **Raw IP-address hostnames** (e.g. `http://192.168.1.105/chase`)
  - **URL shorteners** (`bit.ly`, `tinyurl.com`, `t.co`, etc.)
  - **Typosquatting & Brand Lookalikes** (`paypa1.com`, `micros0ft.com`, `apple-verify.xyz`)
  - **High-risk TLDs** (`.xyz`, `.top`, `.club`, `.work`, `.buzz`, `.loan`)
  - **Insecure HTTP vs HTTPS**
  - **Anchor Deception** (mismatched display link vs true href target)

### D. Composite Risk Scoring System (0 – 100)
- **0 – 30 (Low Risk - Neon Emerald):** Safe, routine transactional correspondence.
- **31 – 60 (Medium Risk - Amber Orange):** Commercial marketing, unsolicited spam, prize announcements.
- **61 – 100 (High Risk - Crimson Red):** Phishing attacks, credential traps, account suspension threats.
- Displays animated circular score gauge and detailed explainability breakdowns.

### E. Multilingual Support
- Detects and preprocesses messages in:
  - **English (EN)**
  - **Hindi (HI)** (Devanagari script & transliterated Hinglish)
  - **Spanish (ES)**
  - **French (FR)**
- Unsupported languages are clearly flagged while generic structural heuristics are safely applied.

### F. Human-in-the-Loop Feedback & Anti-Poisoning
- Allows analysts to mark predictions as **Correct**, report **False Positives**, or report **False Negatives**.
- **Adversarial Security Guardrail:** The system **never automatically retrains** on unverified submissions, preventing malicious data poisoning attacks.

### G. Detection History & Analytics
- Search and filter records by keyword, category, and risk score.
- Modal inspection of original message, headers, and threat rationale.
- One-click **Export to CSV**.
- Admin Dashboard featuring Chart.js visual analytics.

---

## 5. Installation & Setup Instructions

### Prerequisites
- Python 3.10 or higher (compatible with Python 3.10, 3.11, 3.12, 3.13, 3.15+)
- Git

### Step-by-Step Local Setup

1. **Clone or Navigate to the Project Directory:**
   ```bash
   cd "spam detection"
   ```

2. **Create a Python Virtual Environment:**
   ```bash
   python -m venv .venv
   ```

3. **Activate the Virtual Environment:**
   - **Windows (PowerShell):**
     ```powershell
     .venv\Scripts\Activate.ps1
     ```
   - **Windows (Command Prompt):**
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - **Linux / macOS:**
     ```bash
     source .venv/bin/activate
     ```

4. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Train the Machine Learning Model (Pre-trained models are already included, but can be retrained anytime):**
   ```bash
   python train_model.py
   ```

6. **Run the Flask Web Application:**
   ```bash
   python app.py
   ```

7. **Access the Web Interface:**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 6. Sample Messages for Testing & Demonstration

Use these built-in test messages (or click the quick sample buttons on the **Detect Message** page):

| Scenario | Sender | Subject | Sample Message Snippet | Expected Result |
|---|---|---|---|---|
| **Bank Impersonation** | `security@chase-fraud.net` | `URGENT: Wire Transfer` | `Suspicious wire transfer of $3,450 detected. Click immediately to cancel debit card: http://192.168.1.105/chase-wire` | **Phishing (High Risk: 98-100)** |
| **PayPal Lookalike** | `support@paypa1-update.com` | `Account Suspended` | `Unauthorized login attempts. Verify your credentials within 2 hours: http://paypa1-security-update.com/login` | **Phishing (High Risk: 95-100)** |
| **Walmart Lottery** | `promo@megadeals.xyz` | `YOU WON $1,000!` | `You have been selected as lucky winner! Claim your $1000 gift card immediately before midnight!` | **Spam (Medium Risk: 45-55)** |
| **Work Collaboration** | `team@github.com` | `New sign-in from Chrome` | `We noticed a new sign-in to your GitHub account from Windows. If this was you, you can safely ignore this email.` | **Safe (Low Risk: 10-20)** |
| **Hindi Phishing** | `security@sbi-yono.loan` | `SBI Khata Block Alert` | `Priy Grahak, Aapka SBI YONO khata KYC update na hone ke karan block kar diya gaya hai. Net Banking Password turant update karein: http://sbi-kyc.xyz/login` | **Phishing (High Risk: 90-100)** |
| **Spanish Phishing** | `seguridad@santander.xyz` | `AVISO URGENTE` | `Por motivos de seguridad hemos bloqueado su acceso web. Para restablecer su tarjeta, confirme sus datos aquí: http://santander-seguridad.top/login` | **Phishing (High Risk: 90-100)** |
| **French Phishing** | `alerte@banque-postale.top` | `URGENT : Suspension` | `Tentative inhabituelle sur votre compte. Pour débloquer votre carte et confirmer votre code secret, cliquez sur: http://labanquepostale.xyz/client` | **Phishing (High Risk: 90-100)** |

---

## 7. Model Evaluation Report

The evaluation report is automatically generated by `train_model.py` and saved to `models/model_metrics.json`:

```
=================================================================
MODEL EVALUATION RESULTS (Test Split: 25%)
=================================================================
Overall Accuracy:       93.94%
Macro F1-Score:         94.10%
Weighted Precision:     93.94%
Weighted Recall:        93.94%
False Positive Rate:    7.69%

Detailed Classification Report:
              precision    recall  f1-score   support
    Phishing       1.00      1.00      1.00        10
        Safe       0.92      0.92      0.92        13
        Spam       0.90      0.90      0.90        10

Confusion Matrix:
        Phishing   Safe   Spam
Phishing:     10      0      0
    Safe:      0     12      1
    Spam:      0      1      9
=================================================================
```

---

## 8. College Viva & Technical Questions Guide

### Q1: Why use Multinomial Logistic Regression instead of basic Naive Bayes?
> Logistic Regression with balanced class weights provides smooth, calibrated probability scores (`predict_proba`) across multiple classes without assuming complete feature independence. This allows precise thresholding for composite risk scoring.

### Q2: How does the system handle adversarial typosquatting?
> Attackers substitute characters (e.g. `1` for `l`, `0` for `o`). The URL analyzer normalizes these leetspeak variants and checks root domain targets against protected brands (PayPal, Apple, Google, Chase, SBI, etc.). If the brand token appears in an unauthorized domain, it flags a brand lookalike threat.

### Q3: Why is automated model retraining on feedback dangerous?
> In cybersecurity, unverified feedback introduces **Adversarial Data Poisoning**. Attackers could flood the system with feedback labeling phishing messages as "Safe", slowly blinding the model to phishing indicators. The system stages feedback for human analyst verification before retraining.

---

## 9. Vercel & Cloud Deployment Guide

PhishShield AI is pre-configured for instant deployment on **Vercel** serverless functions via `@vercel/python`.

### Step 1: Create a GitHub Repository
1. Open [GitHub: Create a New Repository](https://github.com/new).
2. Enter repository name: `phishshield-ai` (or `spam-phishing-detection`).
3. Set visibility to **Public** (or **Private**). Leave *"Initialize with README"* unchecked.
4. Click **Create repository**.

### Step 2: Push Local Code to GitHub
Open your terminal in this project directory and run:
```bash
# Add your GitHub remote (replace with your GitHub username)
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/phishshield-ai.git

# Push the main branch to GitHub
git push -u origin main
```

### Step 3: Deploy to Vercel (1-Click Deployment)
1. Go to your [Vercel Dashboard](https://vercel.com/new) and log in.
2. Click **Add New... > Project**.
3. Under **Import Git Repository**, find your `phishshield-ai` repo and click **Import**.
4. Vercel will automatically detect `vercel.json` and `requirements.txt`.
5. Click **Deploy**.
6. Within 60 seconds, your application will be live at `https://phishshield-ai.vercel.app`!

---

## 10. License

This project is developed for educational and academic demonstration purposes under the MIT License.
