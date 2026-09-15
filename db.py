import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # --- Users table (SQLi L1/L2 target) ---
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            session_token TEXT
        )
    """)
    users = [
        (1,  "admin",        "Adm1n@S3cur3!2024",  "admin@shield-webapp.lab",    "admin", "tok_admin_9f3a2"),
        (2,  "alice",        "Al1ce#P@ss2024",       "alice@shield-webapp.lab",   "user",  "tok_alice_1b2c3"),
        (3,  "bob",          "B0bSecure!456",        "bob@shield-webapp.lab",     "user",  "tok_bob_4d5e6"),
        (4,  "charlie",      "Ch4rli3Pass!",         "charlie@shield-webapp.lab", "user",  "tok_charlie_7f8g9"),
        (5,  "dave",         "D4ve!Pass2024",        "dave@shield-webapp.lab",    "user",  "tok_dave_h1i2j"),
        (6,  "pentester",    "T3st!ng2024",          "pen@shield-webapp.lab",     "user",  "tok_pen_k3l4m"),
    ]
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", users)

    # --- Products table (SQLi endpoint carrier) ---
    c.execute("DROP TABLE IF EXISTS products")
    c.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL,
            category TEXT
        )
    """)
    products = [
        (1, "Shield Pro VPN",        "Enterprise-grade encrypted VPN tunnel with zero-log policy",          299.99, "Network Security"),
        (2, "FireWall-X",            "Next-gen AI-powered firewall with deep packet inspection",             499.99, "Network Security"),
        (3, "CryptVault",            "Military-grade AES-256 file encryption and secure storage",           149.99, "Encryption"),
        (4, "ThreatRadar",           "Real-time threat intelligence and vulnerability scanner",              399.99, "Monitoring"),
        (5, "SecureAuth 2FA",        "Hardware-backed two-factor authentication module",                    89.99,  "Authentication"),
        (6, "PenKit Pro",            "All-in-one penetration testing toolkit for professionals",            599.99, "Pentesting"),
        (7, "LogShield",             "SIEM log aggregation and anomaly detection platform",                 349.99, "Monitoring"),
        (8, "ZeroTrust Gateway",     "Identity-aware proxy with zero-trust network access",                 799.99, "Network Security"),
    ]
    c.executemany("INSERT INTO products VALUES (?,?,?,?,?)", products)

    # --- Comments table (Stored XSS L3 target) ---
    c.execute("DROP TABLE IF EXISTS comments")
    c.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            author TEXT,
            content TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    comments = [
        (None, 1, "alice",     "Great VPN service! Super fast and secure. Highly recommended."),
        (None, 1, "bob",       "Been using Shield Pro for 6 months. Zero issues. Worth every penny!"),
        (None, 2, "charlie",   "FireWall-X blocked 3 intrusion attempts last week. Impressive AI detection."),
        (None, 3, "dave",      "CryptVault is exactly what I needed for my sensitive documents."),
        (None, 6, "alice",     "PenKit Pro has everything a pentester needs. Excellent tool coverage."),
    ]
    c.executemany("INSERT INTO comments VALUES (?,?,?,?,datetime('now'))", comments)

    # --- Invoices table (IDOR L4 target) ---
    c.execute("DROP TABLE IF EXISTS invoices")
    c.execute("""
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            username TEXT,
            product TEXT,
            amount REAL,
            status TEXT,
            card_last4 TEXT,
            billing_addr TEXT,
            created_at TEXT
        )
    """)
    invoices = [
        (1040, 2, "alice",     "Shield Pro VPN (Annual)",    3599.88, "PAID",    "4821", "12 Nguyen Hue, Quan 1, TP.HCM",      "2024-01-15 09:23:11"),
        (1041, 3, "bob",       "FireWall-X Enterprise",      4999.99, "PAID",    "7734", "45 Le Loi, Hoan Kiem, Ha Noi",        "2024-02-03 14:07:44"),
        (1042, 6, "pentester", "PenKit Pro License",         599.99,  "PAID",    "2291", "88 Tran Phu, Hai Chau, Da Nang",      "2024-03-10 11:45:22"),
        (1043, 4, "charlie",   "ZeroTrust Gateway (3yr)",   2399.97, "PAID",    "5567", "33 Dinh Tien Hoang, Q.Binh Thanh",    "2024-03-22 16:30:05"),
        (1044, 5, "dave",      "ThreatRadar + LogShield",   749.98,  "PENDING", "8843", "9 Hung Vuong, Phu Nhuan, TP.HCM",     "2024-04-01 08:12:59"),
        (1045, 1, "admin",     "Full Suite Enterprise",     9999.00, "PAID",    "0001", "Shield Corp HQ, 1 Cyber Plaza, Hanoi","2024-04-05 00:00:01"),
    ]
    c.executemany("INSERT INTO invoices VALUES (?,?,?,?,?,?,?,?,?)", invoices)

    conn.commit()
    conn.close()
    print("[DB] Database initialized with seed data.")

if __name__ == "__main__":
    init_db()
