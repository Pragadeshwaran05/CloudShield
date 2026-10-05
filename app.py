from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash
)

import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = "cloudshield-development-secret-key"

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cloudshield.db"
)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    connection = get_db()
    cursor = connection.cursor()

    # USERS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL
        )
    """)

    # SECURITY EVENTS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT,
            ip_address TEXT,
            username TEXT,
            resource TEXT,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT
        )
    """)

    # SECURITY ALERTS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            threat_type TEXT,
            severity TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'OPEN',
            detected_at TEXT NOT NULL,
            resolved_at TEXT,
            FOREIGN KEY(event_id)
                REFERENCES security_events(id)
        )
    """)

    # CREATE DEVELOPMENT ADMIN
    existing_admin = cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if existing_admin is None:

        password_hash = generate_password_hash("admin123")

        cursor.execute("""
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                role,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "admin",
            "admin@cloudshield.local",
            password_hash,
            "admin",
            datetime.now().isoformat()
        ))

    connection.commit()
    connection.close()


# =========================================================
# AUTHENTICATION CHECK
# =========================================================

def is_logged_in():
    return "user_id" in session


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return render_template("home.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if is_logged_in():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:

            flash(
                "Username and password are required.",
                "error"
            )

            return redirect(url_for("login"))

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not is_logged_in():
        return redirect(url_for("login"))

    connection = get_db()

    total_events = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM security_events
        """
    ).fetchone()["count"]

    critical_alerts = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM security_alerts
        WHERE severity = 'CRITICAL'
        AND status != 'RESOLVED'
        """
    ).fetchone()["count"]

    high_risk_events = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM security_events
        WHERE severity = 'HIGH'
        """
    ).fetchone()["count"]

    suspicious_events = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM security_events
        WHERE status = 'SUSPICIOUS'
        """
    ).fetchone()["count"]

    recent_events = connection.execute(
        """
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT 10
        """
    ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        total_events=total_events,
        critical_alerts=critical_alerts,
        high_risk_events=high_risk_events,
        suspicious_events=suspicious_events,
        recent_events=recent_events
    )


# =========================================================
# LIVE MONITORING
# =========================================================

@app.route("/live-monitoring")
def live_monitoring():

    if not is_logged_in():
        return redirect(url_for("login"))

        connection = get_db()

        events = connection.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

        connection.close()

        return render_template(
            "monitoring.html",
            events=events
        )


# =========================================================
# SECURITY ALERTS
# =========================================================

@app.route("/security-alerts")
def security_alerts():

    if not is_logged_in():
        return redirect(url_for("login"))

    connection = get_db()

    alerts = connection.execute(
        """
        SELECT *
        FROM security_alerts
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()

    connection.close()

    return render_template(
        "alerts.html",
        alerts=alerts
    )


# =========================================================
# CREATE SECURITY EVENT API
# =========================================================

@app.route("/api/events", methods=["POST"])
def create_event():

    if not is_logged_in():

        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    data = request.get_json(silent=True)

    if not data:

        return jsonify({
            "success": False,
            "message": "JSON body required"
        }), 400

    event_type = data.get("event_type")

    if not event_type:

        return jsonify({
            "success": False,
            "message": "event_type is required"
        }), 400

    severity = data.get("severity", "INFO")

    allowed_severities = [
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    if severity not in allowed_severities:

        return jsonify({
            "success": False,
            "message": "Invalid severity"
        }), 400

    status = data.get("status", "NORMAL")

    allowed_statuses = [
        "NORMAL",
        "SUSPICIOUS",
        "BLOCKED",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if status not in allowed_statuses:

        return jsonify({
            "success": False,
            "message": "Invalid status"
        }), 400

    connection = get_db()

    cursor = connection.execute(
        """
        INSERT INTO security_events
        (
            timestamp,
            event_type,
            source,
            ip_address,
            username,
            resource,
            severity,
            status,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().isoformat(),
            event_type,
            data.get("source", "unknown"),
            data.get("ip_address", "unknown"),
            data.get("username", ""),
            data.get("resource", ""),
            severity,
            status,
            data.get("message", "")
        )
    )

    event_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "message": "Security event recorded",
        "event_id": event_id
    }), 201


# =========================================================
# GET SECURITY EVENTS API
# =========================================================

@app.route("/api/events", methods=["GET"])
def get_events():

    if not is_logged_in():

        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    connection = get_db()

    events = connection.execute(
        """
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()

    connection.close()

    result = []

    for event in events:

        result.append({
            "id": event["id"],
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "source": event["source"],
            "ip_address": event["ip_address"],
            "username": event["username"],
            "resource": event["resource"],
            "severity": event["severity"],
            "status": event["status"],
            "message": event["message"]
        })

    return jsonify({
        "success": True,
        "events": result
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    return jsonify({
        "application": "CloudShield",
        "status": "online",
        "service": "Cyber Security Monitoring"
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>CloudShield could not find this page.</p>
    """, 404


@app.errorhandler(500)
def server_error(error):

    return """
    <h1>500 - Internal Server Error</h1>
    <p>CloudShield encountered an internal error.</p>
    """, 500


# =========================================================
# INITIALIZE DATABASE
# =========================================================

initialize_database()


# =========================================================
# START CLOUDSHIELD
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )   