"""Shared helpers: auth decorators, CSRF, validation, uploads, email, payments."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import threading
import time
import urllib.request
from datetime import date, datetime
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse

from flask import (abort, current_app, flash, g, redirect, request, session,
                   url_for)

from db import get_db

# --------------------------------------------------------------------------
# Current user + access control
# --------------------------------------------------------------------------

def current_user():
    """Logged-in user row (always read fresh from the DB), or None."""
    if "user" in g:
        return g.user
    g.user = None
    uid = session.get("user_id")
    if uid:
        row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if row:
            g.user = row
        else:
            session.clear()
    return g.user


def home_endpoint(user):
    return {"worker": "worker.dashboard",
            "customer": "customer.dashboard",
            "admin": "admin.dashboard"}.get(user["role"] if user else None, "public.index")


def safe_next(target):
    """Only allow redirects to local paths (prevents open-redirect)."""
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


def login_required(*roles):
    """@login_required()            -> any signed-in user
       @login_required('customer')  -> only customers, etc."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please sign in to continue.", "warning")
                endpoint = "admin.login" if roles == ("admin",) else "auth.login"
                nxt = None
                if request.method == "GET":
                    nxt = request.full_path.rstrip("?")
                return redirect(url_for(endpoint, next=nxt))
            if roles and user["role"] not in roles:
                flash("That page isn't available for your account type.", "warning")
                return redirect(url_for(home_endpoint(user)))
            return view(*args, **kwargs)
        return wrapped
    return decorator


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def check_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken") or ""
        if not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Your session expired or the form was invalid. Please go back, refresh and try again.")


# --------------------------------------------------------------------------
# Sidebar navigation per role
# --------------------------------------------------------------------------

NAV = {
    "customer": [
        ("customer.dashboard", "Dashboard", "🏠"),
        ("public.workers", "Find Workers", "🔎"),
        ("customer.bookings", "My Bookings", "📅"),
        ("customer.reviews", "My Reviews", "⭐"),
        ("customer.profile", "My Profile", "👤"),
    ],
    "worker": [
        ("worker.dashboard", "Dashboard", "🏠"),
        ("worker.requests", "Job Requests", "🧰"),
        ("worker.reviews", "My Reviews", "⭐"),
        ("worker.profile", "My Profile", "👤"),
    ],
    "admin": [
        ("admin.dashboard", "Overview", "📊"),
        ("admin.users", "Users", "👥"),
        ("admin.bookings", "Bookings", "📅"),
        ("admin.reviews", "Reviews", "⭐"),
    ],
}


def nav_items(user):
    return NAV.get(user["role"], []) if user else []


# --------------------------------------------------------------------------
# Template filters
# --------------------------------------------------------------------------

STATUS_LABELS = {
    "Pending Payment": "Payment Pending",
    "Pre-Booked": "Awaiting Worker",
    "Confirmed": "Confirmed",
    "Completed": "Completed",
    "Declined": "Declined",
    "Cancelled": "Cancelled",
}


def status_label(status):
    return STATUS_LABELS.get(status, status or "")


def slugify(value):
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")


def fmt_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%d %b %Y")
    except (TypeError, ValueError):
        return value or ""


def short_name(value):
    parts = (value or "").split()
    if not parts:
        return "Customer"
    if len(parts) == 1:
        return parts[0].title()
    return f"{parts[0].title()} {parts[-1][0].upper()}."


def initials(value):
    parts = (value or "?").split()
    return "".join(p[0] for p in parts[:2]).upper() or "?"


def can_review(booking):
    """A booking can be reviewed once the job is done (or confirmed and its date has passed)."""
    status = booking["status"]
    if status == "Completed":
        return True
    return status == "Confirmed" and (booking["booking_date"] or "9999") <= date.today().isoformat()


# --------------------------------------------------------------------------
# Validation + uploads
# --------------------------------------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def clean_phone(raw):
    phone = re.sub(r"[\s\-()]", "", raw or "")
    return phone if re.fullmatch(r"\+?\d{10,13}", phone) else None


def clean_email(raw):
    raw = (raw or "").strip().lower()
    if not raw:
        return ""
    return raw if EMAIL_RE.match(raw) else None


def identity_taken(phone, email, exclude_id=None):
    """Is this phone/email already used by another account?"""
    db = get_db()
    exclude_id = exclude_id or -1
    if phone and db.execute("SELECT 1 FROM users WHERE phone=? AND id!=?", (phone, exclude_id)).fetchone():
        return "phone"
    if email and db.execute("SELECT 1 FROM users WHERE LOWER(email)=? AND id!=?", (email, exclude_id)).fetchone():
        return "email"
    return None


_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"RIFF")


def save_upload(file_storage):
    """Validate + store an uploaded profile image. Returns filename, '' if none, None if invalid."""
    if not file_storage or not file_storage.filename:
        return ""
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in current_app.config["ALLOWED_EXTENSIONS"]:
        return None
    head = file_storage.stream.read(12)
    file_storage.stream.seek(0)
    if not head.startswith(_MAGIC) or (head.startswith(b"RIFF") and head[8:12] != b"WEBP"):
        return None
    name = f"{secrets.token_hex(16)}.{ext}"
    file_storage.save(os.path.join(current_app.config["UPLOAD_FOLDER"], name))
    return name


def remove_upload_if_unused(filename):
    if not filename:
        return
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE image_url=?", (filename,)).fetchone():
        return
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    try:
        os.remove(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Login throttling (in-memory, per IP)
# --------------------------------------------------------------------------

_attempts = {}
MAX_ATTEMPTS, WINDOW = 8, 600


def too_many_attempts():
    now = time.time()
    hits = [t for t in _attempts.get(request.remote_addr, []) if now - t < WINDOW]
    _attempts[request.remote_addr] = hits
    return len(hits) >= MAX_ATTEMPTS


def record_failed_attempt():
    _attempts.setdefault(request.remote_addr, []).append(time.time())


def clear_attempts():
    _attempts.pop(request.remote_addr, None)


# --------------------------------------------------------------------------
# Email (optional, sent in a background thread so requests never block)
# --------------------------------------------------------------------------

def _mail_configured(cfg):
    user = cfg.get("MAIL_USERNAME", "")
    return bool(user and cfg.get("MAIL_PASSWORD") and "your_email" not in user
                and cfg.get("MAIL_PASSWORD") != "your_app_password")


def send_notification(to_email, subject, body):
    if not to_email:
        return
    cfg = {k: current_app.config.get(k) for k in
           ("MAIL_SERVER", "MAIL_PORT", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_SENDER")}
    if not _mail_configured(cfg):
        return

    def _send():
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = subject, cfg["MAIL_SENDER"], to_email
            msg.set_content(body)
            with smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=10) as smtp:
                smtp.starttls()
                smtp.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
                smtp.send_message(msg)
        except Exception as exc:  # never break the app because of email
            print(f"[mail] could not send to {to_email}: {exc}")

    threading.Thread(target=_send, daemon=True).start()


# --------------------------------------------------------------------------
# Razorpay (plain REST, no SDK needed)
# --------------------------------------------------------------------------

def razorpay_enabled():
    cfg = current_app.config
    return bool(cfg["RAZORPAY_KEY_ID"] and cfg["RAZORPAY_KEY_SECRET"])


def _rzp_request(path, payload):
    cfg = current_app.config
    token = base64.b64encode(f"{cfg['RAZORPAY_KEY_ID']}:{cfg['RAZORPAY_KEY_SECRET']}".encode()).decode()
    req = urllib.request.Request(
        f"https://api.razorpay.com/v1/{path}", data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.load(resp)


def create_payment_order(amount_paise, receipt):
    """Returns (order_id, is_demo) or (None, False) if no payment method is available."""
    if razorpay_enabled():
        try:
            order = _rzp_request("orders", {"amount": amount_paise, "currency": "INR",
                                            "receipt": receipt, "payment_capture": 1})
            return order["id"], False
        except Exception as exc:
            print(f"[razorpay] order creation failed: {exc}")
    if current_app.config["ALLOW_DEMO_PAYMENTS"]:
        return f"demo_{secrets.token_hex(8)}", True
    return None, False


def verify_payment_signature(order_id, payment_id, signature):
    secret = current_app.config["RAZORPAY_KEY_SECRET"].encode()
    expected = hmac.new(secret, f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def refund_payment(payment_id):
    """Best-effort refund. Returns a short note describing what happened."""
    if not payment_id:
        return "No payment to refund."
    if payment_id.startswith("DEMO-"):
        return "Demo payment - nothing to refund."
    if not razorpay_enabled():
        return "Refund pending (payment gateway not configured)."
    try:
        _rzp_request(f"payments/{payment_id}/refund", {})
        return "Refund initiated."
    except Exception as exc:
        print(f"[razorpay] refund failed for {payment_id}: {exc}")
        return "Refund could not be issued automatically - please contact support."


# --------------------------------------------------------------------------
# Booking helpers
# --------------------------------------------------------------------------

def slot_is_taken(worker_id, booking_date, time_slot, exclude_booking_id=None):
    row = get_db().execute(
        """SELECT 1 FROM bookings WHERE worker_id=? AND booking_date=? AND time_slot=?
           AND status IN ('Pre-Booked','Confirmed','Completed') AND id != ?""",
        (worker_id, booking_date, time_slot, exclude_booking_id or -1)).fetchone()
    return bool(row)
