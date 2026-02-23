"""
services/security_apis.py
=========================
External security-API integrations for SafePhishi.

Integrations provided
---------------------
1. Google Safe Browsing API v4
2. VirusTotal API v3
3. WHOIS domain-age lookup (python-whois)
4. SSL certificate validation (stdlib ssl / socket)
5. URLScan.io (optional – screenshot + metadata)

Each function is completely independent. They all return a typed
dataclass so callers get IDE auto-completion and can safely access
`.error` to detect failures without crashing.

Environment variables consumed (set in .env):
  GOOGLE_SAFE_BROWSING_API_KEY
  VIRUSTOTAL_API_KEY
  URLSCAN_API_KEY          (optional)
  API_TIMEOUT              (seconds, default 10)
  VT_RATE_LIMIT_DELAY      (seconds between VT calls, default 15)
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ── Shared defaults ────────────────────────────────────────────────────────────

_TIMEOUT: int = int(os.getenv("API_TIMEOUT", "10"))
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "SafePhishi/1.0 (+https://github.com/safephishi)"})


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  1. GOOGLE SAFE BROWSING                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class SafeBrowsingResult:
    """Result from Google Safe Browsing API."""
    is_unsafe: bool = False          # True if any threat was found
    threats: list[str] = field(default_factory=list)  # e.g. ["MALWARE", "PHISHING"]
    error: Optional[str] = None


_GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_GSB_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",        # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_GSB_PLATFORM_TYPES = ["ANY_PLATFORM"]
_GSB_ENTRY_TYPES = ["URL"]


def check_google_safe_browsing(url: str) -> SafeBrowsingResult:
    """
    Query Google Safe Browsing API v4.

    Returns SafeBrowsingResult.is_unsafe = True if Google flags the URL.

    How to get an API key
    ---------------------
    1. Go to https://developers.google.com/safe-browsing/v4/get-started
    2. Create / select a Google Cloud project
    3. Enable the "Safe Browsing API" in the API console
    4. Create an API key under Credentials → API key
    5. Set GOOGLE_SAFE_BROWSING_API_KEY=<your-key> in .env

    Free quota: 10,000 queries / day.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return SafeBrowsingResult(error="GOOGLE_SAFE_BROWSING_API_KEY not set")

    payload = {
        "client": {"clientId": "safephishi", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": _GSB_THREAT_TYPES,
            "platformTypes": _GSB_PLATFORM_TYPES,
            "threatEntryTypes": _GSB_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = _SESSION.post(
            _GSB_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        if not matches:
            return SafeBrowsingResult(is_unsafe=False)

        threats = list({m.get("threatType", "UNKNOWN") for m in matches})
        return SafeBrowsingResult(is_unsafe=True, threats=threats)

    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        msg = f"GSB HTTP {status}: {exc}"
        logger.warning("Google Safe Browsing error for %s – %s", url, msg)
        return SafeBrowsingResult(error=msg)

    except requests.exceptions.Timeout:
        msg = "Google Safe Browsing request timed out"
        logger.warning(msg)
        return SafeBrowsingResult(error=msg)

    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected GSB error for %s", url)
        return SafeBrowsingResult(error=str(exc))


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  2. VIRUSTOTAL                                                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class VirusTotalResult:
    """Result from VirusTotal URL analysis."""
    positives: int = 0          # engines that flagged URL as malicious
    total_engines: int = 0      # total engines that scanned
    confidence: float = 0.0     # positives / total_engines
    permalink: Optional[str] = None
    stats: dict = field(default_factory=dict)  # full engine stats dict
    error: Optional[str] = None


_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_RATE_DELAY: float = float(os.getenv("VT_RATE_LIMIT_DELAY", "15"))
_vt_last_call: float = 0.0   # module-level state for rate limiting


def _vt_headers() -> dict[str, str]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    return {"x-apikey": key, "Accept": "application/json"}


def _vt_url_id(url: str) -> str:
    """VirusTotal uses URL-safe base64 of the URL as its identifier."""
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _vt_enforce_rate_limit() -> None:
    """Block until the free-tier 4 req/min window allows another call."""
    global _vt_last_call
    elapsed = time.monotonic() - _vt_last_call
    if elapsed < _VT_RATE_DELAY:
        time.sleep(_VT_RATE_DELAY - elapsed)
    _vt_last_call = time.monotonic()


def check_virustotal(url: str) -> VirusTotalResult:
    """
    Submit a URL to VirusTotal and return its analysis.

    Strategy
    --------
    1. Try to GET an existing report (no quota used if cached).
    2. If not found (404), submit the URL for analysis (POST /urls).
    3. Poll the analysis endpoint until finished or timeout.

    How to get an API key
    ---------------------
    1. Register at https://www.virustotal.com/
    2. Go to your profile → API key
    3. Set VIRUSTOTAL_API_KEY=<your-key> in .env

    Free tier: 4 requests/minute, 500 requests/day.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return VirusTotalResult(error="VIRUSTOTAL_API_KEY not set")

    _vt_enforce_rate_limit()
    headers = _vt_headers()
    url_id = _vt_url_id(url)

    try:
        # ── Step 1: Check existing cached report ──────────────────────────────
        resp = _SESSION.get(
            f"{_VT_BASE}/urls/{url_id}",
            headers=headers,
            timeout=_TIMEOUT,
        )

        if resp.status_code == 404:
            # ── Step 2: Submit URL for analysis ───────────────────────────────
            _vt_enforce_rate_limit()
            submit_resp = _SESSION.post(
                f"{_VT_BASE}/urls",
                headers=headers,
                data={"url": url},
                timeout=_TIMEOUT,
            )
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()["data"]["id"]

            # ── Step 3: Poll for results (up to 60 s) ─────────────────────────
            for attempt in range(6):
                time.sleep(10)
                _vt_enforce_rate_limit()
                poll_resp = _SESSION.get(
                    f"{_VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=_TIMEOUT,
                )
                poll_resp.raise_for_status()
                poll_data = poll_resp.json()
                status = poll_data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    return _parse_vt_attributes(
                        poll_data["data"]["attributes"],
                        permalink=f"https://www.virustotal.com/gui/url/{url_id}",
                    )

            return VirusTotalResult(error="VirusTotal analysis timed out after 60 s")

        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        return _parse_vt_attributes(
            attrs,
            permalink=f"https://www.virustotal.com/gui/url/{url_id}",
        )

    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        # 429 = rate limited
        if status == 429:
            msg = "VirusTotal rate limit reached – try again later"
        else:
            msg = f"VirusTotal HTTP {status}: {exc}"
        logger.warning("VirusTotal error for %s – %s", url, msg)
        return VirusTotalResult(error=msg)

    except requests.exceptions.Timeout:
        msg = "VirusTotal request timed out"
        logger.warning(msg)
        return VirusTotalResult(error=msg)

    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected VirusTotal error for %s", url)
        return VirusTotalResult(error=str(exc))


def _parse_vt_attributes(attrs: dict, permalink: Optional[str] = None) -> VirusTotalResult:
    """Parse VirusTotal analysis attributes into VirusTotalResult."""
    stats: dict = attrs.get("last_analysis_stats", {})
    positives: int = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total: int = sum(stats.values())
    confidence = round(positives / total, 4) if total > 0 else 0.0

    return VirusTotalResult(
        positives=positives,
        total_engines=total,
        confidence=confidence,
        permalink=permalink,
        stats=stats,
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  3. WHOIS DOMAIN-AGE CHECK                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class WhoisResult:
    """Result from a WHOIS domain-age lookup."""
    domain: str = ""
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    registrar: Optional[str] = None
    age_days: Optional[int] = None        # days since registration
    is_new_domain: bool = False           # True if domain < 30 days old
    error: Optional[str] = None


_YOUNG_DOMAIN_DAYS = 30   # threshold for "suspicious new domain"


def check_whois(url: str) -> WhoisResult:
    """
    Perform a WHOIS lookup and compute domain age.

    Requires: python-whois  (pip install python-whois)

    Young domains (< 30 days) are a strong phishing indicator.
    """
    try:
        import whois  # type: ignore[import]
    except ImportError:
        return WhoisResult(error="python-whois not installed – run: pip install python-whois")

    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    domain = parsed.hostname or ""
    if not domain:
        return WhoisResult(error=f"Cannot parse domain from URL: {url!r}")

    # Strip www.
    domain = domain.removeprefix("www.")

    try:
        w = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        msg = f"WHOIS lookup failed for {domain!r}: {exc}"
        logger.warning(msg)
        return WhoisResult(domain=domain, error=msg)

    creation = _first_date(w.creation_date)
    expiration = _first_date(w.expiration_date)
    registrar = w.registrar if isinstance(w.registrar, str) else (w.registrar[0] if w.registrar else None)

    age_days: Optional[int] = None
    is_new = False
    if creation:
        # Make timezone-aware for comparison
        now = datetime.now(tz=timezone.utc)
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (now - creation).days
        is_new = age_days < _YOUNG_DOMAIN_DAYS

    return WhoisResult(
        domain=domain,
        creation_date=creation,
        expiration_date=expiration,
        registrar=registrar,
        age_days=age_days,
        is_new_domain=is_new,
    )


def _first_date(value) -> Optional[datetime]:
    """WHOIS libraries return either a datetime or a list of datetimes."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value
    return None


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  4. SSL CERTIFICATE VALIDATION                                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class SSLResult:
    """Result from SSL certificate inspection."""
    is_valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expiry_date: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    error: Optional[str] = None


def check_ssl(url: str, port: int = 443) -> SSLResult:
    """
    Connect to the host and inspect its TLS/SSL certificate.

    No external dependencies — uses Python's stdlib ssl + socket.
    Checks:
    - Certificate validity (not expired)
    - Expiry date and days remaining
    - Issuer organisation
    - Self-signed detection (issuer == subject)
    """
    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    if not hostname:
        return SSLResult(error=f"Cannot parse hostname from URL: {url!r}")

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

    except ssl.SSLCertVerificationError as exc:
        # Certificate is present but invalid (expired, self-signed, wrong CN…)
        return SSLResult(is_valid=False, error=f"SSL verification failed: {exc.reason}")

    except (socket.timeout, TimeoutError):
        return SSLResult(error=f"Connection to {hostname}:{port} timed out")

    except OSError as exc:
        return SSLResult(error=f"Cannot connect to {hostname}:{port} – {exc}")

    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected SSL error for %s", url)
        return SSLResult(error=str(exc))

    # Parse expiry
    not_after_str = cert.get("notAfter", "")
    expiry: Optional[datetime] = None
    days_left: Optional[int] = None
    is_expired = False

    if not_after_str:
        try:
            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(tz=timezone.utc)
            days_left = (expiry - now).days
            is_expired = days_left < 0
        except ValueError:
            pass

    # Parse issuer and subject
    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    subject_dict = dict(x[0] for x in cert.get("subject", []))

    issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
    subject_cn = subject_dict.get("commonName")

    # Self-signed: issuer == subject on every field
    is_self_signed = cert.get("issuer") == cert.get("subject")

    return SSLResult(
        is_valid=not is_expired and not is_self_signed,
        issuer=issuer_org,
        subject=subject_cn,
        expiry_date=expiry,
        days_until_expiry=days_left,
        is_expired=is_expired,
        is_self_signed=is_self_signed,
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  5. URLSCAN.IO (optional)                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class URLScanResult:
    """Result from URLScan.io submission."""
    scan_uuid: Optional[str] = None
    scan_url: Optional[str] = None        # permalink to the scan report
    screenshot_url: Optional[str] = None  # direct screenshot image URL
    verdict_malicious: bool = False
    verdict_score: int = 0                # 0-100
    page_domain: Optional[str] = None
    page_ip: Optional[str] = None
    error: Optional[str] = None


_URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
_URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"


def check_urlscan(url: str, *, visibility: str = "unlisted") -> URLScanResult:
    """
    Submit a URL for scanning to URLScan.io and retrieve the result.

    How to get an API key
    ---------------------
    1. Register at https://urlscan.io/
    2. Go to Settings → API Keys → Create
    3. Set URLSCAN_API_KEY=<your-key> in .env

    Free tier: 5,000 private scans/day.

    Parameters
    ----------
    visibility : "public" | "unlisted" | "private"
        "unlisted"  – scan is reachable by link, not in public feed (recommended)
        "private"   – only visible to you (requires Pro plan)
        "public"    – appears in public feed
    """
    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        return URLScanResult(error="URLSCAN_API_KEY not set – integration is optional")

    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }

    try:
        # ── Submit ────────────────────────────────────────────────────────────
        submit = _SESSION.post(
            _URLSCAN_SUBMIT,
            headers=headers,
            json={"url": url, "visibility": visibility},
            timeout=_TIMEOUT,
        )
        if submit.status_code == 429:
            return URLScanResult(error="URLScan.io rate limit reached")
        submit.raise_for_status()

        scan_uuid = submit.json().get("uuid", "")
        scan_url = submit.json().get("result", "")

        # ── Poll for result (scans take ~10-30 s) ─────────────────────────────
        for attempt in range(8):
            time.sleep(10)
            result_resp = _SESSION.get(
                _URLSCAN_RESULT.format(uuid=scan_uuid),
                headers=headers,
                timeout=_TIMEOUT,
            )
            if result_resp.status_code == 404:
                continue  # still processing
            result_resp.raise_for_status()
            data = result_resp.json()

            verdicts = data.get("verdicts", {}).get("overall", {})
            page = data.get("page", {})
            task = data.get("task", {})

            return URLScanResult(
                scan_uuid=scan_uuid,
                scan_url=scan_url,
                screenshot_url=task.get("screenshotURL"),
                verdict_malicious=verdicts.get("malicious", False),
                verdict_score=verdicts.get("score", 0),
                page_domain=page.get("domain"),
                page_ip=page.get("ip"),
            )

        return URLScanResult(
            scan_uuid=scan_uuid,
            scan_url=scan_url,
            error="URLScan.io result not available after 80 s – check scan_url manually",
        )

    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        msg = f"URLScan.io HTTP {status}: {exc}"
        logger.warning("URLScan error for %s – %s", url, msg)
        return URLScanResult(error=msg)

    except requests.exceptions.Timeout:
        return URLScanResult(error="URLScan.io request timed out")

    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected URLScan error for %s", url)
        return URLScanResult(error=str(exc))


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  COMPOSITE SCANNER                                                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

@dataclass
class CompositeScanResult:
    """
    Aggregated result from all enabled API checks for a single URL.
    Feed this into the database and the template.
    """
    # Google Safe Browsing
    gsb_is_unsafe: bool = False
    gsb_threats: list[str] = field(default_factory=list)
    gsb_error: Optional[str] = None

    # VirusTotal
    vt_positives: int = 0
    vt_total_engines: int = 0
    vt_confidence: float = 0.0
    vt_permalink: Optional[str] = None
    vt_error: Optional[str] = None

    # WHOIS
    whois_domain: str = ""
    whois_creation_date: Optional[datetime] = None
    whois_expiration_date: Optional[datetime] = None
    whois_registrar: Optional[str] = None
    whois_age_days: Optional[int] = None
    whois_is_new_domain: bool = False
    whois_error: Optional[str] = None

    # SSL
    ssl_valid: bool = False
    ssl_issuer: Optional[str] = None
    ssl_subject: Optional[str] = None
    ssl_expiry_date: Optional[datetime] = None
    ssl_days_until_expiry: Optional[int] = None
    ssl_is_expired: bool = False
    ssl_is_self_signed: bool = False
    ssl_error: Optional[str] = None

    # URLScan (optional)
    urlscan_uuid: Optional[str] = None
    urlscan_url: Optional[str] = None
    urlscan_screenshot: Optional[str] = None
    urlscan_malicious: bool = False
    urlscan_score: int = 0
    urlscan_error: Optional[str] = None

    # Derived composite risk score (0.0 – 1.0)
    composite_risk_score: float = 0.0
    risk_label: str = "Unknown"

    def compute_composite_score(self) -> None:
        """
        Calculate a composite risk score (0.0 – 1.0) from all signals.
        Weights reflect practical importance of each signal.
        """
        score = 0.0

        # GSB: authoritative, weight 0.35
        if self.gsb_is_unsafe:
            score += 0.35

        # VirusTotal: multi-engine consensus, weight 0.30
        score += self.vt_confidence * 0.30

        # New domain (<30 days): strong indicator, weight 0.20
        if self.whois_is_new_domain:
            score += 0.20

        # Invalid SSL: weight 0.10
        if not self.ssl_valid:
            score += 0.10

        # URLScan malicious verdict: weight 0.05
        if self.urlscan_malicious:
            score += 0.05

        self.composite_risk_score = round(min(score, 1.0), 4)

        if self.composite_risk_score >= 0.65:
            self.risk_label = "High Risk"
        elif self.composite_risk_score >= 0.35:
            self.risk_label = "Medium Risk"
        elif self.composite_risk_score > 0.0:
            self.risk_label = "Low Risk"
        else:
            self.risk_label = "Clean"


def run_all_checks(
    url: str,
    *,
    enable_gsb: bool = True,
    enable_vt: bool = True,
    enable_whois: bool = True,
    enable_ssl: bool = True,
    enable_urlscan: bool = False,   # opt-in – slower
) -> CompositeScanResult:
    """
    Run all enabled security checks against a URL and return a
    CompositeScanResult with an aggregated risk score.

    Pass enable_* flags to toggle individual checks, e.g. when the
    corresponding API key is not configured.
    """
    result = CompositeScanResult()

    if enable_gsb:
        logger.info("Running GSB check for %s", url)
        gsb = check_google_safe_browsing(url)
        result.gsb_is_unsafe = gsb.is_unsafe
        result.gsb_threats = gsb.threats
        result.gsb_error = gsb.error

    if enable_vt:
        logger.info("Running VirusTotal check for %s", url)
        vt = check_virustotal(url)
        result.vt_positives = vt.positives
        result.vt_total_engines = vt.total_engines
        result.vt_confidence = vt.confidence
        result.vt_permalink = vt.permalink
        result.vt_error = vt.error

    if enable_whois:
        logger.info("Running WHOIS check for %s", url)
        w = check_whois(url)
        result.whois_domain = w.domain
        result.whois_creation_date = w.creation_date
        result.whois_expiration_date = w.expiration_date
        result.whois_registrar = w.registrar
        result.whois_age_days = w.age_days
        result.whois_is_new_domain = w.is_new_domain
        result.whois_error = w.error

    if enable_ssl:
        logger.info("Running SSL check for %s", url)
        s = check_ssl(url)
        result.ssl_valid = s.is_valid
        result.ssl_issuer = s.issuer
        result.ssl_subject = s.subject
        result.ssl_expiry_date = s.expiry_date
        result.ssl_days_until_expiry = s.days_until_expiry
        result.ssl_is_expired = s.is_expired
        result.ssl_is_self_signed = s.is_self_signed
        result.ssl_error = s.error

    if enable_urlscan:
        logger.info("Running URLScan.io check for %s", url)
        us = check_urlscan(url)
        result.urlscan_uuid = us.scan_uuid
        result.urlscan_url = us.scan_url
        result.urlscan_screenshot = us.screenshot_url
        result.urlscan_malicious = us.verdict_malicious
        result.urlscan_score = us.verdict_score
        result.urlscan_error = us.error

    result.compute_composite_score()
    logger.info("Composite score for %s: %.2f (%s)", url, result.composite_risk_score, result.risk_label)
    return result
