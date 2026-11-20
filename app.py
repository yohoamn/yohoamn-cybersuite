import base64
import hashlib
import io
import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from PIL import ExifTags, Image
from werkzeug.security import check_password_hash, generate_password_hash

# ==========================================================
#  yohoamn! CyberSuite — HoneyTrap + StegoVault
#  Author: yohoamn! | Track: HCL Cyber Analyst Project
# ==========================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "yohoamn-cyber-secret-key-2026")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload cap

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cybersuite.db")

# --- Anti-Copy Integrity Signature ---
AUTHOR_NAME = "yohoamn!"
_ENCODED_OWNER = "eW9ob2FtbiE="  # Base64 check for yohoamn!
BUILD_FINGERPRINT = hashlib.sha256(f"{AUTHOR_NAME}-CYBERSUITE-HCL".encode()).hexdigest()[:16].upper()


def is_tampered():
    expected = base64.b64decode(_ENCODED_OWNER).decode("utf-8")
    return AUTHOR_NAME != expected


# --- Database Setup ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'Cyber Analyst',
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            target_endpoint TEXT NOT NULL,
            username_tried TEXT,
            payload_tried TEXT,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            user_agent TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            blocked_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS stego_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyst TEXT NOT NULL,
            action TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # Safe default analyst account (works cleanly under multi-worker cloud boot)
    cur.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (
            "yohoamn",
            generate_password_hash("cyber123"),
            "Lead Cyber Analyst",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )

    conn.commit()
    conn.close()


init_db()


# --- Global Template Variables ---
@app.context_processor
def inject_globals():
    return {
        "author": AUTHOR_NAME,
        "tampered": is_tampered(),
        "current_user": session.get("username"),
        "user_role": session.get("role", "Cyber Analyst"),
        "build_id": BUILD_FINGERPRINT,
    }


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access the CyberSuite SOC dashboard.", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


# --- Threat Detection Engine (HoneyTrap IDS) ---
SQLI_REGEX = re.compile(
    r"('|--|;|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bor\s+1\s*=\s*1\b|'or'|\"or\")",
    re.IGNORECASE,
)
XSS_REGEX = re.compile(
    r"(<script|</script|onerror\s*=|onload\s*=|javascript:|alert\s*\(|<img|<svg)",
    re.IGNORECASE,
)
CMDI_REGEX = re.compile(
    r"(&&|\|\||\bwhoami\b|\bcat\s+/|\brm\s+-rf\b|\bcmd\.exe\b|\bpowershell\b)",
    re.IGNORECASE,
)
PATH_REGEX = re.compile(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini)", re.IGNORECASE)


def classify_payload(username_in, password_in):
    combined = f"{username_in} {password_in}"
    if SQLI_REGEX.search(combined):
        return "SQL Injection (SQLi)", "CRITICAL"
    if XSS_REGEX.search(combined):
        return "Cross-Site Scripting (XSS)", "HIGH"
    if CMDI_REGEX.search(combined):
        return "OS Command Injection", "CRITICAL"
    if PATH_REGEX.search(combined):
        return "Path Traversal", "HIGH"
    return "Brute-Force / Unauthorized Login", "MEDIUM"


# --- StegoVault Core Engine (Fast Byte-Level LSB + EXIF) ---
STEGO_MARKER = b"<<<YOHOAMN_END>>>"


def encode_lsb(image_bytes, secret_text):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    raw = bytearray(img.tobytes())
    payload = secret_text.encode("utf-8") + STEGO_MARKER

    if len(payload) * 8 > len(raw):
        raise ValueError("Secret message is too large for this image. Use a larger image.")

    idx = 0
    for byte in payload:
        for shift in range(7, -1, -1):
            raw[idx] = (raw[idx] & ~1) | ((byte >> shift) & 1)
            idx += 1

    out_img = Image.frombytes("RGB", img.size, bytes(raw))
    buf = io.BytesIO()
    out_img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def decode_lsb(image_bytes):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    raw = img.tobytes()
    marker_len = len(STEGO_MARKER)
    extracted = bytearray()
    max_bytes = min(len(raw) // 8, 50000)

    for i in range(max_bytes):
        base = i * 8
        val = 0
        for b in range(8):
            val = (val << 1) | (raw[base + b] & 1)
        extracted.append(val)
        if len(extracted) >= marker_len and extracted[-marker_len:] == STEGO_MARKER:
            return bytes(extracted[:-marker_len]).decode("utf-8", errors="replace")
    return None


def extract_exif_data(image_bytes):
    img = Image.open(io.BytesIO(image_bytes))
    info = {
        "Format": img.format or "Unknown",
        "Dimensions": f"{img.size[0]} x {img.size[1]} px",
        "Color Mode": img.mode,
    }
    exif_found = 0
    try:
        exif = img.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                info[str(tag_name)] = str(value)[:120]
                exif_found += 1
            gps_ifd = exif.get_ifd(0x8825)
            if gps_ifd:
                info["GPS_WARNING"] = f"GPS Metadata Exposed ({len(gps_ifd)} tags found!)"
                exif_found += 1
    except Exception:
        pass
    if exif_found == 0:
        info["EXIF Status"] = "Clean — No hidden camera/GPS EXIF tags found in this image."
    return info


def strip_exif_data(image_bytes):
    img = Image.open(io.BytesIO(image_bytes))
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        img = img.convert("RGBA")
    else:
        img = img.convert("RGB")
    clean_img = Image.frombytes(img.mode, img.size, img.tobytes())
    buf = io.BytesIO()
    clean_img.save(buf, format="PNG")
    buf.seek(0)
    return buf


# ==========================================================
#  ROUTES: AUTHENTICATION & OVERVIEW
# ==========================================================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        action = request.form.get("action", "login")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("login"))

        client_ip = get_client_ip()
        ua = request.headers.get("User-Agent", "Unknown")[:120]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        cur = conn.cursor()

        if action == "register":
            try:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (
                        username,
                        generate_password_hash(password),
                        "Cyber Analyst",
                        now,
                    ),
                )
                conn.commit()
                flash("Analyst account created! You can now log in.", "success")
            except sqlite3.IntegrityError:
                flash("Username already exists. Choose another.", "danger")
            finally:
                conn.close()
            return redirect(url_for("login"))

        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            cur.execute(
                """
                INSERT INTO attack_logs
                (ip_address, target_endpoint, username_tried, payload_tried, attack_type, severity, user_agent, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ip,
                    "/login",
                    username[:100],
                    "*** (Authenticated)",
                    "SOC Login Success (/login)",
                    "SAFE",
                    ua,
                    now,
                ),
            )
            conn.commit()
            conn.close()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}. SOC systems online.", "success")
            return redirect(url_for("dashboard"))

        attack_type, severity = classify_payload(username, password)
        if attack_type == "Brute-Force / Unauthorized Login":
            attack_type = "Failed SOC Login (/login)"
        else:
            attack_type = f"{attack_type} (/login)"

        cur.execute(
            """
            INSERT INTO attack_logs
            (ip_address, target_endpoint, username_tried, payload_tried, attack_type, severity, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_ip,
                "/login",
                username[:100],
                password[:150],
                attack_type,
                severity,
                ua,
                now,
            ),
        )
        conn.commit()
        conn.close()

        flash("Invalid analyst credentials.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out securely.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()
    total_attacks = cur.execute(
        "SELECT COUNT(*) FROM attack_logs WHERE severity != 'SAFE'"
    ).fetchone()[0]
    critical_attacks = cur.execute(
        "SELECT COUNT(*) FROM attack_logs WHERE severity = 'CRITICAL'"
    ).fetchone()[0]
    blocked_count = cur.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    stego_count = cur.execute("SELECT COUNT(*) FROM stego_logs").fetchone()[0]
    recent_attacks = cur.execute(
        "SELECT * FROM attack_logs ORDER BY id DESC LIMIT 5"
    ).fetchall()
    recent_stego = cur.execute(
        "SELECT * FROM stego_logs ORDER BY id DESC LIMIT 5"
    ).fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        total_attacks=total_attacks,
        critical_attacks=critical_attacks,
        blocked_count=blocked_count,
        stego_count=stego_count,
        recent_attacks=recent_attacks,
        recent_stego=recent_stego,
    )


# ==========================================================
#  ROUTES: MODULE 1 — HONEYTRAP (HONEYPOT & LIVE IDS)
# ==========================================================
@app.route("/honeytrap")
@login_required
def honeytrap_soc():
    conn = get_db()
    cur = conn.cursor()
    logs = cur.execute("SELECT * FROM attack_logs ORDER BY id DESC LIMIT 50").fetchall()
    blocked = cur.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    breakdown = cur.execute(
        "SELECT attack_type, COUNT(*) as cnt FROM attack_logs GROUP BY attack_type ORDER BY cnt DESC"
    ).fetchall()
    conn.close()

    return render_template(
        "honeytrap_soc.html",
        logs=logs,
        blocked=blocked,
        breakdown=breakdown,
        trap_url=url_for("trap_portal", _external=True),
    )


@app.route("/trap-login", methods=["GET", "POST"])
def trap_portal():
    client_ip = get_client_ip()
    conn = get_db()
    cur = conn.cursor()

    blocked_row = cur.execute(
        "SELECT * FROM blocked_ips WHERE ip_address = ?", (client_ip,)
    ).fetchone()
    if blocked_row:
        conn.close()
        return render_template(
            "trap_portal.html",
            blocked=True,
            block_reason=blocked_row["reason"],
            client_ip=client_ip,
        ), 403

    error_msg = None
    if request.method == "POST":
        u_in = request.form.get("username", "")
        p_in = request.form.get("password", "")
        ua = request.headers.get("User-Agent", "Unknown")[:120]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        attack_type, severity = classify_payload(u_in, p_in)

        cur.execute(
            """
            INSERT INTO attack_logs
            (ip_address, target_endpoint, username_tried, payload_tried, attack_type, severity, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (client_ip, "/trap-login", u_in[:100], p_in[:150], attack_type, severity, ua, now),
        )

        hits = cur.execute(
            "SELECT COUNT(*) FROM attack_logs WHERE ip_address = ? AND target_endpoint = '/trap-login'",
            (client_ip,),
        ).fetchone()[0]

        if severity == "CRITICAL" or hits >= 3:
            reason = f"Auto-blocked: {attack_type} ({hits} intrusion attempts)"
            cur.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?)",
                (client_ip, reason, now),
            )
            conn.commit()
            conn.close()
            return render_template(
                "trap_portal.html",
                blocked=True,
                block_reason=reason,
                client_ip=client_ip,
            ), 403

        conn.commit()
        error_msg = f"Invalid employee credentials. (Attempt {hits}/3 logged)"

    conn.close()
    return render_template("trap_portal.html", blocked=False, error_msg=error_msg, client_ip=client_ip)


@app.route("/honeytrap/simulate", methods=["POST"])
@login_required
def simulate_attack():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    samples = [
        ("185.220.101.42", "admin' OR '1'='1' --", "pass123", "SQL Injection (SQLi)", "CRITICAL"),
        ("45.155.205.91", "<script>alert('hacked')</script>", "x", "Cross-Site Scripting (XSS)", "HIGH"),
        ("103.75.201.19", "root", "whoami && cat /etc/passwd", "OS Command Injection", "CRITICAL"),
    ]
    conn = get_db()
    cur = conn.cursor()
    for ip, u, p, atype, sev in samples:
        cur.execute(
            """
            INSERT INTO attack_logs
            (ip_address, target_endpoint, username_tried, payload_tried, attack_type, severity, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ip, "/trap-login", u, p, atype, sev, "Simulated-Scanner/2.4 (Demo)", now),
        )
        if sev == "CRITICAL":
            cur.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?)",
                (ip, f"Auto-blocked: {atype}", now),
            )
    conn.commit()
    conn.close()
    flash("Simulated 3 live cyber attacks (SQLi, XSS, Command Injection) into HoneyTrap!", "success")
    return redirect(url_for("honeytrap_soc"))


@app.route("/honeytrap/unblock", methods=["POST"])
@login_required
def unblock_ip():
    ip = request.form.get("ip", "").strip()
    conn = get_db()
    conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()
    flash(f"Unblocked IP address: {ip}", "success")
    return redirect(url_for("honeytrap_soc"))


@app.route("/honeytrap/clear", methods=["POST"])
@login_required
def clear_logs():
    conn = get_db()
    conn.execute("DELETE FROM attack_logs")
    conn.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    flash("Cleared all HoneyTrap logs and blocked IPs.", "warning")
    return redirect(url_for("honeytrap_soc"))


# ==========================================================
#  ROUTES: MODULE 2 — STEGOVAULT (STEGO, EXIF & HASH)
# ==========================================================
@app.route("/stegovault", methods=["GET", "POST"])
@login_required
def stegovault():
    result = None

    if request.method == "POST":
        tool = request.form.get("tool")
        uploaded = request.files.get("file")

        if not uploaded or uploaded.filename == "":
            flash("Please choose a file first.", "danger")
            return redirect(url_for("stegovault"))

        file_bytes = uploaded.read()
        filename = uploaded.filename
        sha256_val = hashlib.sha256(file_bytes).hexdigest()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            if tool == "encode":
                secret = request.form.get("secret_message", "").strip()
                if not secret:
                    flash("Enter a secret message to hide inside the image.", "danger")
                    return redirect(url_for("stegovault"))

                stego_buf = encode_lsb(file_bytes, secret)
                stego_hash = hashlib.sha256(stego_buf.getvalue()).hexdigest()

                conn = get_db()
                conn.execute(
                    "INSERT INTO stego_logs (analyst, action, filename, sha256_hash, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (session["username"], "LSB Encode", filename, stego_hash, f"Hidden {len(secret)} chars inside PNG pixels", now),
                )
                conn.commit()
                conn.close()

                base_name = os.path.splitext(filename)[0]
                return send_file(
                    stego_buf,
                    mimetype="image/png",
                    as_attachment=True,
                    download_name=f"yohoamn_stego_{base_name}.png",
                )

            elif tool == "decode":
                hidden_msg = decode_lsb(file_bytes)
                conn = get_db()
                conn.execute(
                    "INSERT INTO stego_logs (analyst, action, filename, sha256_hash, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        session["username"],
                        "LSB Decode",
                        filename,
                        sha256_val,
                        "Secret payload extracted" if hidden_msg else "No hidden payload found",
                        now,
                    ),
                )
                conn.commit()
                conn.close()
                result = {
                    "type": "decode",
                    "filename": filename,
                    "found": hidden_msg is not None,
                    "message": hidden_msg or "No yohoamn! LSB steganography payload detected in this image.",
                    "hash": sha256_val,
                }

            elif tool == "exif_inspect":
                exif_info = extract_exif_data(file_bytes)
                conn = get_db()
                conn.execute(
                    "INSERT INTO stego_logs (analyst, action, filename, sha256_hash, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (session["username"], "EXIF Inspect", filename, sha256_val, f"Found {len(exif_info)} metadata fields", now),
                )
                conn.commit()
                conn.close()
                result = {
                    "type": "exif",
                    "filename": filename,
                    "exif": exif_info,
                    "hash": sha256_val,
                }

            elif tool == "exif_strip":
                clean_buf = strip_exif_data(file_bytes)
                clean_hash = hashlib.sha256(clean_buf.getvalue()).hexdigest()
                conn = get_db()
                conn.execute(
                    "INSERT INTO stego_logs (analyst, action, filename, sha256_hash, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (session["username"], "EXIF Strip", filename, clean_hash, "All EXIF/GPS spy metadata wiped", now),
                )
                conn.commit()
                conn.close()
                base_name = os.path.splitext(filename)[0]
                return send_file(
                    clean_buf,
                    mimetype="image/png",
                    as_attachment=True,
                    download_name=f"yohoamn_clean_{base_name}.png",
                )

            elif tool == "hash_check":
                expected_hash = request.form.get("expected_hash", "").strip().lower()
                matched = (sha256_val == expected_hash) if expected_hash else None
                status_text = (
                    "Hash Generated"
                    if matched is None
                    else ("Integrity Verified (MATCH)" if matched else "TAMPERING DETECTED (MISMATCH)")
                )
                conn = get_db()
                conn.execute(
                    "INSERT INTO stego_logs (analyst, action, filename, sha256_hash, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (session["username"], "SHA-256 Check", filename, sha256_val, status_text, now),
                )
                conn.commit()
                conn.close()
                result = {
                    "type": "hash",
                    "filename": filename,
                    "size_kb": round(len(file_bytes) / 1024, 2),
                    "hash": sha256_val,
                    "expected": expected_hash,
                    "matched": matched,
                }

        except Exception as exc:
            flash(f"Forensics Error: {str(exc)}", "danger")

    conn = get_db()
    history = conn.execute("SELECT * FROM stego_logs ORDER BY id DESC LIMIT 15").fetchall()
    conn.close()
    return render_template("stegovault.html", result=result, history=history)


# ==========================================================
#  STEALTH OWNERSHIP PROOF ROUTE (/yohoamn)
# ==========================================================
@app.route("/yohoamn")
def verify_owner():
    return render_template("verify_owner.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)