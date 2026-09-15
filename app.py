import os
import re
import time
import sqlite3
import datetime
import requests as req_lib
from flask import (
    Flask, request, render_template, session,
    redirect, url_for, jsonify
)
from db import get_db, init_db

# ──────────────────────────────────────────────
#  App setup
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "shield_lab_secret_do_not_use_in_prod_xD"
# L3 XSS: Disable HttpOnly so document.cookie can steal the session
app.config['SESSION_COOKIE_HTTPONLY'] = False

LOG_DIR  = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "access.log")
os.makedirs(LOG_DIR, exist_ok=True)

STOLEN_COOKIES = []   # in-memory store for L3 XSS demo

# ──────────────────────────────────────────────
#  Logging middleware
# ──────────────────────────────────────────────
def write_log(extra=""):
    ts   = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0700")
    ip   = request.remote_addr or "127.0.0.1"
    meth = request.method
    path = request.full_path.rstrip("?") if not request.query_string else request.full_path
    ua   = request.headers.get("User-Agent", "-")[:60]
    line = f'[{ts}] {ip} - "{meth} {path} HTTP/1.1" {extra} "{ua}"\n'
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)

@app.before_request
def log_request():
    write_log()

# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────
def current_user():
    return session.get("username", None)

def current_user_id():
    return session.get("user_id", None)

# ──────────────────────────────────────────────
#  L6 – Login (Auth / Burp Repeater target)
#  OWASP A07:2021 – Identification and Authentication Failures
#  Vuln: role param not validated; weak session; no brute-force protection
# ──────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        # L6 VULN: 'role' param accepted from POST body — attacker can inject role=admin
        role_override = request.form.get("role", None)

        db = get_db()
        # NOTE: Uses parameterized query here (login is safe for SQL, vuln is in role param)
        row = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        db.close()

        if row:
            session["username"]  = row["username"]
            session["user_id"]   = row["id"]
            session["role"]      = role_override if role_override else row["role"]
            # Log the suspicious role override
            if role_override:
                write_log(f'[L6-VULN] role_override={role_override} INJECTED by {username}')
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials. Please try again."
            write_log(f'[AUTH-FAIL] username={username}')

    return render_template("login.html", error=error, user=current_user())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not current_user():
        return redirect(url_for("login"))
    role = session.get("role", "user")
    return render_template("dashboard.html", user=current_user(), role=role)

# ──────────────────────────────────────────────
#  Products list
# ──────────────────────────────────────────────
@app.route("/products")
def products():
    db = get_db()
    rows = db.execute("SELECT * FROM products").fetchall()
    db.close()
    return render_template("products.html", products=rows, user=current_user())

# ──────────────────────────────────────────────
#  L1 / L2 – SQLi (Union-based & Time-based blind)
#  OWASP A03:2021 – Injection
#  Endpoint: /product?id=<VULN_PARAM>
#  Vuln: raw string interpolation into SQL query
# ──────────────────────────────────────────────
@app.route("/product")
def product():
    pid = request.args.get("id", "1")

    # ── L2 Time-based blind: detect SLEEP and actually pause ──
    sleep_match = re.search(r"SLEEP\s*\(\s*(\d+)\s*\)", pid, re.IGNORECASE)
    if sleep_match:
        secs = min(int(sleep_match.group(1)), 10)
        time.sleep(secs)
        write_log(f"[L2-SQLI-TIMEBASED] SLEEP({secs}) detected! param={pid}")

    db  = get_db()
    db.close()  # we'll use a raw connection for the vuln demo
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "lab.db"))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    result     = None
    sql_error  = None
    union_data = []
    product_row = None

    # ── INTENTIONALLY VULNERABLE QUERY ──
    vuln_query = f"SELECT * FROM products WHERE id = {pid}"

    try:
        cursor.execute(vuln_query)
        rows = cursor.fetchall()

        # Detect UNION injection result (returns >1 col that doesn't match products schema)
        if rows:
            for row in rows:
                cols = [description[0] for description in cursor.description]
                row_dict = dict(zip(cols, row))
                union_data.append(row_dict)
            # If first row has 'id' that matches product id, it's the real product
            first = union_data[0]
            if str(first.get("id", "")) == str(pid).split()[0]:
                product_row = first
            else:
                product_row = first  # show whatever came back

        write_log(f"[L1-SQLI] query={vuln_query[:120]}")
    except Exception as e:
        sql_error = str(e)
        write_log(f"[L1-SQLI-ERROR] {sql_error} query={vuln_query[:80]}")

    conn.close()

    return render_template(
        "product.html",
        product=product_row,
        union_data=union_data,
        sql_error=sql_error,
        raw_query=vuln_query,
        user=current_user(),
        pid=pid,
    )

# ──────────────────────────────────────────────
#  L3 – Stored XSS
#  OWASP A03:2021 – Injection (XSS)
#  Endpoint: /comments  (GET=view, POST=submit)
#  Vuln: comment content stored & rendered without escaping (|safe filter)
# ──────────────────────────────────────────────
@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    if request.method == "POST":
        author  = request.form.get("author", "Anonymous").strip()
        content = request.form.get("content", "").strip()
        pid     = request.form.get("product_id", "1")

        # L3 VULN: No sanitization — raw HTML stored
        db.execute(
            "INSERT INTO comments (product_id, author, content) VALUES (?,?,?)",
            (pid, author, content)
        )
        db.commit()

        xss_detected = "<script" in content.lower() or "onerror" in content.lower() or "javascript:" in content.lower()
        if xss_detected:
            write_log(f"[L3-XSS-STORED] author={author} payload={content[:80]}")

    rows = db.execute(
        "SELECT c.*, p.name as product_name FROM comments c "
        "LEFT JOIN products p ON c.product_id=p.id ORDER BY c.id DESC"
    ).fetchall()
    products_rows = db.execute("SELECT id, name FROM products").fetchall()
    db.close()

    return render_template(
        "comments.html",
        comments=rows,
        products=products_rows,
        user=current_user(),
    )

# ── XSS cookie stealer receiver ──
@app.route("/steal")
def steal():
    cookie = request.args.get("c", "")
    ip     = request.remote_addr
    ts     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry  = {"timestamp": ts, "from_ip": ip, "cookie": cookie}
    STOLEN_COOKIES.append(entry)
    write_log(f"[L3-XSS-COOKIE-STOLEN] cookie={cookie[:80]} from={ip}")
    return "", 204  # Silently acknowledge

@app.route("/xss-log")
def xss_log():
    """Admin-facing page to see stolen cookies (lab demo)."""
    return render_template("steal_log.html", stolen=STOLEN_COOKIES, user=current_user())

# ──────────────────────────────────────────────
#  L4 – IDOR (Insecure Direct Object Reference)
#  OWASP A01:2021 – Broken Access Control
#  Endpoint: /api/invoice/<invoice_id>
#  Vuln: No ownership check — any invoice ID returns full data
# ──────────────────────────────────────────────
@app.route("/invoices")
def invoices():
    if not current_user():
        return redirect(url_for("login"))
    db   = get_db()
    uid  = current_user_id()
    rows = db.execute("SELECT * FROM invoices WHERE user_id=?", (uid,)).fetchall()
    db.close()
    return render_template("invoices.html", invoices=rows, user=current_user(), user_id=uid)

@app.route("/api/invoice/<int:invoice_id>")
def api_invoice(invoice_id):
    # L4 VULN: No session check → No ownership validation
    db  = get_db()
    row = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    db.close()

    if not row:
        return jsonify({"error": "Invoice not found"}), 404

    # Log IDOR access if user doesn't own this invoice
    uid = current_user_id()
    if uid and row["user_id"] != uid:
        write_log(f"[L4-IDOR] user_id={uid} accessed invoice_id={invoice_id} (owner={row['user_id']})")

    return jsonify({
        "invoice_id":   row["id"],
        "user_id":      row["user_id"],
        "username":     row["username"],
        "product":      row["product"],
        "amount":       row["amount"],
        "status":       row["status"],
        "card_last4":   row["card_last4"],
        "billing_addr": row["billing_addr"],
        "created_at":   row["created_at"],
    })

@app.route("/invoice/<int:invoice_id>")
def invoice_page(invoice_id):
    """HTML view for invoice — also vulnerable to IDOR."""
    db  = get_db()
    row = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    db.close()
    if not row:
        return render_template("404.html", user=current_user()), 404
    uid = current_user_id()
    if uid and row["user_id"] != uid:
        write_log(f"[L4-IDOR-HTML] user_id={uid} accessed invoice_id={invoice_id}")
    return render_template("invoice.html", invoice=row, user=current_user())

# ──────────────────────────────────────────────
#  L5 – SSRF (Server-Side Request Forgery)
#  OWASP A10:2021 – Server-Side Request Forgery
#  Endpoint: POST /fetch?url=<VULN_PARAM>
#  Vuln: No URL allowlist — server fetches arbitrary URLs
# ──────────────────────────────────────────────

# Simulated internal metadata responses (mimics AWS EC2 IMDS)
INTERNAL_RESPONSES = {
    "169.254.169.254": {
        "/latest/meta-data/": "ami-id\nami-launch-index\nami-manifest-path\nhostname\niam/\ninstance-id\ninstance-type\nlocal-ipv4\nmac\nnetwork/\nplacement/\nprofile\nreservation-id\nsecurity-groups",
        "/latest/meta-data/instance-id": "i-0a1b2c3d4e5f67890",
        "/latest/meta-data/hostname": "ip-172-31-42-10.ap-southeast-1.compute.internal",
        "/latest/meta-data/local-ipv4": "172.31.42.10",
        "/latest/meta-data/iam/": "security-credentials/",
        "/latest/meta-data/iam/security-credentials/": "ShieldLabEC2Role",
        "/latest/meta-data/iam/security-credentials/ShieldLabEC2Role":
            '{\n  "Code": "Success",\n  "Type": "AWS-HMAC",\n  "AccessKeyId": "ASIA3XAMPLEKEYID1234",\n  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  "Token": "AQoDYXdzEJr//////////wEaoAK...EXAMPLETOKEN",\n  "Expiration": "2024-12-31T23:59:59Z"\n}',
        "/latest/meta-data/instance-type": "t3.medium",
        "/latest/meta-data/security-groups": "shield-lab-sg\ndefault",
        "/latest/user-data": "#!/bin/bash\nexport DB_PASS=Pr0d_DB_S3cr3t_2024!\nexport API_KEY=sk-shield-live-xK9mP3qR7vL2nW5\nexport ADMIN_SECRET=ShieldAdm1n#2024",
    },
    "localhost": {
        "/": "<html>Internal admin: <a href='/admin'>/admin</a></html>",
        "/admin": "<h1>Internal Admin Panel</h1><p>DB: postgresql://admin:Pr0d_DB_S3cr3t@db:5432/shield</p>",
        "/health": '{"status":"ok","db":"connected","version":"shield-webapp 2.4.1"}',
    },
    "127.0.0.1": {
        "/": "<html>Internal server</html>",
        "/admin": "<h1>Admin</h1>",
        "/health": '{"status":"ok"}',
    }
}

def simulate_internal_fetch(url: str):
    """Return simulated internal response for SSRF demo."""
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    host   = parsed.netloc.split(":")[0]   # strip port
    path   = parsed.path or "/"
    if not path.endswith("/"):
        path_key = path
    else:
        path_key = path

    host_data = INTERNAL_RESPONSES.get(host, {})
    if path_key in host_data:
        return host_data[path_key], 200
    # Try prefix match
    for k, v in host_data.items():
        if path_key.startswith(k.rstrip("/")):
            return v, 200
    return f"404 — path '{path}' not found on {host}", 404

@app.route("/fetch", methods=["GET", "POST"])
def fetch_url():
    result      = None
    status_code = None
    fetched_url = None
    error       = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        fetched_url = url

        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            parsed = None

        is_internal = False
        if parsed:
            host = parsed.netloc.split(":")[0].lower()
            is_internal = host in ("169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0") \
                          or host.startswith("172.") \
                          or host.startswith("192.168.") \
                          or host.startswith("10.")

        if is_internal:
            # L5 VULN: Simulate fetching internal metadata / services
            result, status_code = simulate_internal_fetch(url)
            write_log(f"[L5-SSRF] INTERNAL url={url} → {status_code}")
        else:
            # For external URLs, actually try (or mock)
            try:
                resp = req_lib.get(url, timeout=5, allow_redirects=True)
                result      = resp.text[:4000]
                status_code = resp.status_code
                write_log(f"[L5-SSRF] EXTERNAL url={url} status={status_code}")
            except Exception as e:
                error = str(e)
                write_log(f"[L5-SSRF-ERROR] url={url} err={error}")

    return render_template(
        "fetch.html",
        result=result,
        status_code=status_code,
        fetched_url=fetched_url,
        error=error,
        user=current_user(),
    )

# ──────────────────────────────────────────────
#  Admin panel (accessible after privilege escalation)
# ──────────────────────────────────────────────
@app.route("/admin")
def admin():
    role = session.get("role", "user")
    if role != "admin":
        write_log(f"[ADMIN-DENY] user={current_user()} role={role}")
        return render_template("403.html", user=current_user()), 403
    db   = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    db.close()
    # Read last 50 lines of log
    log_lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, encoding="utf-8") as f:
            log_lines = f.readlines()[-50:]
    return render_template("admin.html", users=users, log_lines=log_lines, user=current_user())

# ──────────────────────────────────────────────
#  Log viewer (lab utility)
# ──────────────────────────────────────────────
@app.route("/logs")
def view_logs():
    log_lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, encoding="utf-8") as f:
            log_lines = f.readlines()[-100:]
    return render_template("logs.html", log_lines=log_lines, user=current_user())

# ──────────────────────────────────────────────
#  Error handlers
# ──────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", user=current_user()), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html", user=current_user()), 403

# ──────────────────────────────────────────────
#  Startup
# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  SHIELD-WEBAPP.LAB  —  OWASP Vuln Lab")
    print("  http://127.0.0.1:5000")
    print("  Credentials: pentester / T3st!ng2024")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
