import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env if present
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)


class Config:
    """Base Flask configuration."""

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # SQLite database by default (phishing_detector.db in project root)
    db_path = str(BASE_DIR / 'phishing_detector.db').replace('\\', '/')
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{db_path}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Folders
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    LOG_FOLDER    = os.getenv("LOG_FOLDER",    str(BASE_DIR / "logs"))

    # Security / auth
    SESSION_COOKIE_SECURE  = False   # set True if using HTTPS
    REMEMBER_COOKIE_SECURE = False

    # ── External security API keys ────────────────────────────────────────────
    # Leave blank to disable a check gracefully (no crash, just skipped).

    # Google Safe Browsing API v4
    # Docs: https://developers.google.com/safe-browsing/v4/get-started
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    # VirusTotal API v3
    # Docs: https://developers.virustotal.com/reference/overview
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

    # URLScan.io (optional – used for screenshot capture)
    # Docs: https://urlscan.io/docs/api/
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

    # ── API behaviour ─────────────────────────────────────────────────────────

    # Per-request timeout in seconds for all external HTTP calls
    API_TIMEOUT = int(os.getenv("API_TIMEOUT", "10"))

    # Seconds to wait between VirusTotal calls (free tier = 4 req/min → 15 s)
    VT_RATE_LIMIT_DELAY = float(os.getenv("VT_RATE_LIMIT_DELAY", "15"))

    # Cache TTL for external API responses (hours)
    API_CACHE_TTL_HOURS = int(os.getenv("API_CACHE_TTL_HOURS", "6"))

    # Set to "0" to disable URLScan.io (slow; opt-in only)
    ENABLE_URLSCAN = os.getenv("ENABLE_URLSCAN", "0") == "1"

    @classmethod
    def api_flags(cls) -> dict:
        """Return a dict of which API checks are enabled (key is set)."""
        return {
            "enable_gsb":     bool(cls.GOOGLE_SAFE_BROWSING_API_KEY),
            "enable_vt":      bool(cls.VIRUSTOTAL_API_KEY),
            "enable_whois":   True,          # no key needed
            "enable_ssl":     True,          # no key needed
            "enable_urlscan": cls.ENABLE_URLSCAN and bool(cls.URLSCAN_API_KEY),
        }


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE  = True
    REMEMBER_COOKIE_SECURE = True
