from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scans = db.relationship("ScanResult", back_populates="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email}>"


class ScanResult(db.Model):
    """
    Stores every URL scan performed by a user.

    Core heuristic columns
    ----------------------
    url, is_phishing, score

    External API enrichment columns (all nullable – filled only when
    the relevant API key is configured and the check succeeds)
    ---------------------------------------------------------------
    google_safe_status      : True = Google flagged the URL as unsafe
    virustotal_positives    : number of AV engines that flagged it
    virustotal_total        : total AV engines that scanned it
    virustotal_confidence   : positives / total  (0.0 – 1.0)
    virustotal_permalink    : link to VT report
    whois_creation_date     : when the domain was first registered
    whois_age_days          : domain age in days
    whois_registrar         : registrar name
    ssl_valid               : True if cert is valid and not expired
    ssl_issuer              : certificate issuer org/CN
    ssl_expiry_date         : certificate expiry datetime
    ssl_days_until_expiry   : days remaining on the cert
    ssl_is_self_signed      : True if cert is self-signed
    urlscan_uuid            : URLScan.io scan UUID
    urlscan_report_url      : link to URLScan.io report
    urlscan_screenshot_url  : direct URL to scan screenshot
    urlscan_malicious       : URLScan.io malicious verdict
    composite_risk_score    : aggregated risk 0.0 – 1.0
    risk_label              : "Clean" | "Low Risk" | "Medium Risk" | "High Risk"
    """

    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)

    # ── Core ──────────────────────────────────────────────────────────────────
    url = db.Column(db.String(2048), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    score = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="scans")

    # ── Google Safe Browsing ──────────────────────────────────────────────────
    google_safe_status = db.Column(db.Boolean, nullable=True)   # True = unsafe

    # ── VirusTotal ────────────────────────────────────────────────────────────
    virustotal_positives = db.Column(db.Integer, nullable=True)
    virustotal_total = db.Column(db.Integer, nullable=True)
    virustotal_confidence = db.Column(db.Float, nullable=True)
    virustotal_permalink = db.Column(db.String(512), nullable=True)

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    whois_creation_date = db.Column(db.DateTime, nullable=True)
    whois_age_days = db.Column(db.Integer, nullable=True)
    whois_registrar = db.Column(db.String(255), nullable=True)

    # ── SSL ───────────────────────────────────────────────────────────────────
    ssl_valid = db.Column(db.Boolean, nullable=True)
    ssl_issuer = db.Column(db.String(255), nullable=True)
    ssl_expiry_date = db.Column(db.DateTime, nullable=True)
    ssl_days_until_expiry = db.Column(db.Integer, nullable=True)
    ssl_is_self_signed = db.Column(db.Boolean, nullable=True)

    # ── URLScan.io ────────────────────────────────────────────────────────────
    urlscan_uuid = db.Column(db.String(64), nullable=True)
    urlscan_report_url = db.Column(db.String(512), nullable=True)
    urlscan_screenshot_url = db.Column(db.String(512), nullable=True)
    urlscan_malicious = db.Column(db.Boolean, nullable=True)

    # ── Composite ─────────────────────────────────────────────────────────────
    composite_risk_score = db.Column(db.Float, nullable=True)
    risk_label = db.Column(db.String(32), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ScanResult {self.url} phishing={self.is_phishing}>"


class ApiCache(db.Model):
    """
    Simple URL-keyed cache for external API responses.

    Prevents hitting rate limits by storing raw JSON results with
    a TTL. The cache key is a SHA-256 hash of the (url, api_name) pair.

    Usage
    -----
        cached = ApiCache.get(url, "virustotal")
        if cached:
            data = json.loads(cached.response_json)
        else:
            data = call_api(url)
            ApiCache.put(url, "virustotal", data, ttl_hours=6)
    """

    __tablename__ = "api_cache"

    id = db.Column(db.Integer, primary_key=True)
    cache_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    api_name = db.Column(db.String(32), nullable=False)
    url_checked = db.Column(db.String(2048), nullable=False)
    response_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    # ── Class helpers ─────────────────────────────────────────────────────────

    @classmethod
    def _make_key(cls, url: str, api_name: str) -> str:
        import hashlib
        raw = f"{api_name}:{url}".encode()
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def get(cls, url: str, api_name: str) -> "ApiCache | None":
        """Return a valid (non-expired) cache entry or None."""
        key = cls._make_key(url, api_name)
        entry = cls.query.filter_by(cache_key=key).first()
        if entry is None:
            return None
        if entry.expires_at < datetime.utcnow():
            db.session.delete(entry)
            db.session.commit()
            return None
        return entry

    @classmethod
    def put(cls, url: str, api_name: str, data: dict, ttl_hours: int = 6) -> None:
        """Upsert a cache entry with the given TTL."""
        import json
        from datetime import timedelta
        key = cls._make_key(url, api_name)
        now = datetime.utcnow()
        expires = now + timedelta(hours=ttl_hours)
        entry = cls.query.filter_by(cache_key=key).first()
        if entry:
            entry.response_json = json.dumps(data)
            entry.created_at = now
            entry.expires_at = expires
        else:
            entry = cls(
                cache_key=key,
                api_name=api_name,
                url_checked=url,
                response_json=json.dumps(data),
                created_at=now,
                expires_at=expires,
            )
            db.session.add(entry)
        db.session.commit()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ApiCache {self.api_name}:{self.url_checked[:60]}>"
