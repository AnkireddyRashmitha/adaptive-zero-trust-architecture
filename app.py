from flask import Flask, request, jsonify, session, render_template, send_from_directory
from datetime import datetime
import sqlite3, hashlib, json, os

app = Flask(__name__)
app.secret_key = "zerotrust_secret_2024"

DB = "zerotrust.db"

# ──────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS trust_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        score REAL DEFAULT 100.0,
        failed_logins INTEGER DEFAULT 0,
        high_risk_actions INTEGER DEFAULT 0,
        denied_requests INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        sensitivity TEXT DEFAULT 'low',
        min_trust_score REAL DEFAULT 0.0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        resource_id INTEGER,
        status TEXT DEFAULT 'pending',
        requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(resource_id) REFERENCES resources(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        risk_level TEXT DEFAULT 'low',
        details TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute("SELECT COUNT(*) FROM resources")
    if c.fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO resources (name,description,sensitivity,min_trust_score) VALUES (?,?,?,?)",
            [
                ("Public Dashboard",  "General system dashboard",       "low",      0.0),
                ("Internal Reports",  "Internal company reports",       "medium",  60.0),
                ("HR Database",       "Human resources sensitive data", "high",    80.0),
                ("Financial Records", "Confidential financial data",    "critical",90.0),
                ("Source Code Repo",  "Application source code",        "high",    75.0),
                ("Admin Panel",       "System administration tools",    "critical",95.0),
            ]
        )
    conn.commit()
    conn.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def ensure_trust_row(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO trust_scores (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()

def calc_trust_score(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM trust_scores WHERE user_id=?", (user_id,))
    row = c.fetchone()
    c.execute("SELECT created_at FROM users WHERE id=?", (user_id,))
    u = c.fetchone()
    conn.close()

    if not row:
        return 100.0, {"failed_logins":0.0,"account_age":10.0,"high_risk_actions":0.0,"denied_requests":0.0}

    failed = row["failed_logins"]     * 10.0
    high   = row["high_risk_actions"] * 15.0
    denied = row["denied_requests"]   * 5.0
    age_bonus = 10.0
    if u:
        try:
            created = datetime.strptime(u["created_at"][:19], "%Y-%m-%d %H:%M:%S")
            age_bonus = min((datetime.now() - created).days * 0.5, 20.0)
        except:
            age_bonus = 10.0

    score = round(max(0.0, 100.0 - failed - high - denied + age_bonus), 1)
    return score, {
        "failed_logins":     -failed,
        "account_age":       +age_bonus,
        "high_risk_actions": -high,
        "denied_requests":   -denied,
    }

def log_activity(user_id, action, risk_level="low", details=None):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO activity_logs (user_id,action,risk_level,details,timestamp) VALUES (?,?,?,?,?)",
        (user_id, action, risk_level,
         json.dumps(details) if details else None,
         datetime.now().strftime("%d/%m/%Y, %H:%M:%S"))
    )
    conn.commit()
    conn.close()

# ──────────────────────────────────────────────
# SERVE FRONTEND
# ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ──────────────────────────────────────────────
# AUTH
# ──────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role     = data.get("role", "user")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if role not in ("user", "admin"):
        role = "user"
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email,password,role) VALUES (?,?,?)",
                  (email, hash_pw(password), role))
        conn.commit()
        uid = c.lastrowid
        ensure_trust_row(uid)
        log_activity(uid, "register", "low", {"email": email})
        return jsonify({"message": "Registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409
    finally:
        conn.close()

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone()
    if not user or user["password"] != hash_pw(password):
        if user:
            ensure_trust_row(user["id"])
            c.execute("UPDATE trust_scores SET failed_logins=failed_logins+1 WHERE user_id=?", (user["id"],))
            conn.commit()
            log_activity(user["id"], "failed_login", "medium", {"email": email})
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401
    conn.close()
    ensure_trust_row(user["id"])
    session["user_id"] = user["id"]
    session["email"]   = user["email"]
    session["role"]    = user["role"]
    log_activity(user["id"], "login", "low", {"email": email})
    return jsonify({"message": "Login successful",
                    "user": {"id": user["id"], "email": user["email"], "role": user["role"]}})

@app.route("/api/logout", methods=["POST"])
def logout():
    uid = session.get("user_id")
    if uid:
        log_activity(uid, "logout", "low")
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/api/me", methods=["GET"])
def me():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"id": session["user_id"], "email": session["email"], "role": session["role"]})

# ──────────────────────────────────────────────
# DASHBOARD
# ──────────────────────────────────────────────
@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    uid = session["user_id"]
    score, _ = calc_trust_score(uid)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM access_requests WHERE user_id=?", (uid,))
    my_req = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM access_requests WHERE user_id=? AND status='approved'", (uid,))
    approved = c.fetchone()["cnt"]
    conn.close()
    return jsonify({"trust_score": score, "my_requests": my_req, "approved_access": approved})

# ──────────────────────────────────────────────
# TRUST SCORE
# ──────────────────────────────────────────────
@app.route("/api/trust-score", methods=["GET"])
def trust_score():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    score, factors = calc_trust_score(session["user_id"])
    return jsonify({"score": score, "factors": factors})

# ──────────────────────────────────────────────
# RESOURCES
# ──────────────────────────────────────────────
@app.route("/api/resources", methods=["GET"])
def resources():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    score, _ = calc_trust_score(session["user_id"])
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM resources")
    rows = c.fetchall()
    conn.close()
    return jsonify([{**dict(r), "accessible": score >= r["min_trust_score"]} for r in rows])

# ──────────────────────────────────────────────
# ACCESS REQUESTS
# ──────────────────────────────────────────────
@app.route("/api/access-requests", methods=["GET"])
def get_access_requests():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    uid = session["user_id"]
    conn = get_db()
    c = conn.cursor()
    if session["role"] == "admin":
        c.execute("""SELECT ar.*, u.email, r.name as resource_name
                     FROM access_requests ar
                     JOIN users u ON ar.user_id=u.id
                     JOIN resources r ON ar.resource_id=r.id
                     ORDER BY ar.requested_at DESC""")
    else:
        c.execute("""SELECT ar.*, r.name as resource_name
                     FROM access_requests ar
                     JOIN resources r ON ar.resource_id=r.id
                     WHERE ar.user_id=? ORDER BY ar.requested_at DESC""", (uid,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/access-requests", methods=["POST"])
def create_request():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    uid = session["user_id"]
    resource_id = request.json.get("resource_id")
    score, _ = calc_trust_score(uid)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM resources WHERE id=?", (resource_id,))
    res = c.fetchone()
    if not res:
        conn.close()
        return jsonify({"error": "Resource not found"}), 404
    status = "approved" if score >= res["min_trust_score"] else "pending"
    risk   = "high" if res["sensitivity"] == "critical" else ("medium" if res["sensitivity"] == "high" else "low")
    if status == "pending":
        c.execute("UPDATE trust_scores SET denied_requests=denied_requests+1 WHERE user_id=?", (uid,))
        log_activity(uid, "access_denied", "high", {"resource": res["name"]})
    else:
        log_activity(uid, "access_granted", risk, {"resource": res["name"]})
    c.execute("INSERT INTO access_requests (user_id,resource_id,status) VALUES (?,?,?)",
              (uid, resource_id, status))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Request {status}", "status": status}), 201

@app.route("/api/access-requests/<int:req_id>", methods=["PATCH"])
def review_request(req_id):
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    status = request.json.get("status")
    if status not in ("approved", "rejected"):
        return jsonify({"error": "Invalid status"}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE access_requests SET status=?,reviewed_at=? WHERE id=?",
              (status, datetime.now().strftime("%d/%m/%Y, %H:%M:%S"), req_id))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Request {status}"})

# ──────────────────────────────────────────────
# ACTIVITY LOGS
# ──────────────────────────────────────────────
@app.route("/api/activity-logs", methods=["GET"])
def activity_logs():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    uid = session["user_id"]
    conn = get_db()
    c = conn.cursor()
    if session["role"] == "admin":
        c.execute("""SELECT al.*, u.email FROM activity_logs al
                     JOIN users u ON al.user_id=u.id
                     ORDER BY al.id DESC LIMIT 50""")
    else:
        c.execute("SELECT * FROM activity_logs WHERE user_id=? ORDER BY id DESC LIMIT 20", (uid,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ──────────────────────────────────────────────
# ADMIN
# ──────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    if "user_id" not in session or session["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,email,role,created_at FROM users")
    users = c.fetchall()
    conn.close()
    result = []
    for u in users:
        score, _ = calc_trust_score(u["id"])
        result.append({**dict(u), "trust_score": score})
    return jsonify(result)

# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)