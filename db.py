"""Database access + safe, repeatable migrations for the existing localpro.db."""
import sqlite3
from datetime import datetime

from flask import g, current_app
from werkzeug.security import generate_password_hash

PAID_STATUSES = ("Pre-Booked", "Confirmed", "Completed")
SLOT_BLOCKING = ("Pre-Booked", "Confirmed", "Completed")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _columns(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn, table, column, ddl):
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _is_hashed(pw):
    return bool(pw) and pw.startswith(("pbkdf2:", "scrypt:"))


def init_db(app):
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row

    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT, phone TEXT, email TEXT, password TEXT,
        role TEXT, service_type TEXT, city TEXT, area TEXT,
        pincode TEXT, image_url TEXT, description TEXT,
        status TEXT DEFAULT 'Available'
    )""")
    _add_column(conn, "users", "description", "TEXT")
    _add_column(conn, "users", "created_at", "TEXT")

    conn.execute("""CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER, worker_id INTEGER,
        customer_name TEXT, booking_date TEXT, time_slot TEXT,
        payment_id TEXT, razorpay_order_id TEXT,
        amount INTEGER DEFAULT 10,
        status TEXT DEFAULT 'Pending Payment'
    )""")
    _add_column(conn, "bookings", "job_details", "TEXT")
    _add_column(conn, "bookings", "created_at", "TEXT")
    _add_column(conn, "bookings", "note", "TEXT")  # e.g. refund result

    conn.execute("""CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL UNIQUE,
        customer_id INTEGER NOT NULL,
        worker_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TEXT,
        updated_at TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_worker ON reviews(worker_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bookings_worker ON bookings(worker_id, booking_date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bookings_customer ON bookings(customer_id)")

    # ---- data clean-up / migration ----
    conn.execute("UPDATE users SET role = LOWER(TRIM(role)) WHERE role IS NOT NULL")
    conn.execute("UPDATE users SET created_at = ? WHERE created_at IS NULL", (now_str(),))
    conn.execute("UPDATE bookings SET created_at = ? WHERE created_at IS NULL", (now_str(),))
    conn.execute("UPDATE bookings SET status='Confirmed' WHERE status='Confirmed / Pre-Booked'")
    conn.execute("UPDATE users SET status='Available' WHERE status IS NULL OR status=''")

    # Hash any legacy plain-text passwords (users keep logging in with the same password).
    for row in conn.execute("SELECT id, password FROM users").fetchall():
        if row["password"] and not _is_hashed(row["password"]):
            conn.execute("UPDATE users SET password=? WHERE id=?",
                         (generate_password_hash(row["password"]), row["id"]))

    # Admin accounts: upsert (keep ids stable), never wipe other admins' sessions.
    wanted = {email for email, _, _ in app.config["ADMINS"]}
    for email, pwd, name in app.config["ADMINS"]:
        row = conn.execute("SELECT id, password FROM users WHERE role='admin' AND LOWER(email)=?",
                           (email,)).fetchone()
        if row:
            # Only re-hash if the configured password no longer matches.
            from werkzeug.security import check_password_hash
            if not _is_hashed(row["password"]) or not check_password_hash(row["password"], pwd):
                conn.execute("UPDATE users SET password=?, fullname=? WHERE id=?",
                             (generate_password_hash(pwd), name, row["id"]))
        else:
            conn.execute(
                "INSERT INTO users (fullname, email, password, role, created_at) VALUES (?,?,?,?,?)",
                (name, email, generate_password_hash(pwd), "admin", now_str()))
    # Admins removed from config are removed from the DB too.
    if app.config["ADMINS"]:
        for row in conn.execute("SELECT id, email FROM users WHERE role='admin'").fetchall():
            if (row["email"] or "").lower() not in wanted:
                conn.execute("DELETE FROM users WHERE id=?", (row["id"],))

    conn.commit()
    conn.close()
