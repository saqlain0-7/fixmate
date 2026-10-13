"""Central configuration. Secrets come from environment variables or a local
`.env` file (never hard-code them in source)."""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv(path):
    """Tiny .env loader (KEY=VALUE per line) so no extra dependency is needed."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(os.path.join(BASE_DIR, ".env"))


def _secret_key():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    # Generate once and persist so sessions survive restarts.
    inst = os.path.join(BASE_DIR, "instance")
    os.makedirs(inst, exist_ok=True)
    path = os.path.join(inst, ".secret_key")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key)
    return key


def _flag(name, default="0"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _parse_admins(raw):
    """ADMINS="email:password:Display Name;email:password:Display Name" """
    admins = []
    for chunk in (raw or "").split(";"):
        parts = [p.strip() for p in chunk.split(":", 2)]
        if len(parts) == 3 and parts[0] and parts[1]:
            admins.append((parts[0].lower(), parts[1], parts[2] or "Admin"))
    return admins


class Config:
    SECRET_KEY = _secret_key()
    DB_PATH = os.environ.get("DB_PATH") or os.path.join(BASE_DIR, "localpro.db")

    # Uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

    # Sessions / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _flag("SESSION_COOKIE_SECURE")  # set 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 7

    # Business rules
    SERVICES = ["Electrician", "Plumber", "Carpenter", "AC Repair"]
    TIME_SLOTS = [
        "09:00 AM - 12:00 PM",
        "01:00 PM - 04:00 PM",
        "05:00 PM - 08:00 PM",
    ]
    INSPECTION_FEE_RS = int(os.environ.get("INSPECTION_FEE_RS", "10"))
    MAX_BOOKING_DAYS_AHEAD = 90

    # Razorpay (test or live keys from your dashboard)
    RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
    RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
    # When Razorpay can't be reached, allow a fake "demo" payment so the flow
    # can still be tried. TURN THIS OFF (0) in production.
    ALLOW_DEMO_PAYMENTS = _flag("ALLOW_DEMO_PAYMENTS", "1")

    # Email notifications (optional; silently disabled if not configured)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_SENDER = os.environ.get("MAIL_SENDER", "") or os.environ.get("MAIL_USERNAME", "")

    # Fixed admin accounts (hashed in the DB at startup)
    ADMINS = _parse_admins(os.environ.get("ADMINS", ""))

    DEBUG = _flag("FLASK_DEBUG")
