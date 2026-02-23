import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth import auth_bp, init_login_manager
from config import Config
from model.ml_model import PhishingModel
from models import ApiCache, ScanResult, User, db
from migrations import migrate_database
from admin_routes import admin_bp
from services.security_apis import CompositeScanResult, run_all_checks


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ── Database ──────────────────────────────────────────────────────────────
    db.init_app(app)
    with app.app_context():
        db.create_all()
        migrate_database(app)

    # ── Auth ──────────────────────────────────────────────────────────────────
    init_login_manager(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # ── ML model ──────────────────────────────────────────────────────────────
    phishing_model = PhishingModel()

    # ── Logging ───────────────────────────────────────────────────────────────
    _configure_logging(app)

    # =========================================================================
    # PUBLIC ROUTES
    # =========================================================================

    @app.route("/")
    def index():
        return render_template("index.html")

    # =========================================================================
    # USER DASHBOARD
    # =========================================================================

    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def dashboard():
        url_prediction    = None
        email_prediction  = None
        url               = ""
        email_text        = ""
        api_result: CompositeScanResult | None = None

        if request.method == "POST":
            url        = request.form.get("url",        "").strip()
            email_text = request.form.get("email_text", "").strip()

            if not url and not email_text:
                flash("Please enter a URL or email content to scan.", "warning")
            else:
                # ── URL scan ──────────────────────────────────────────────────
                if url:
                    # 1. Heuristic / ML prediction (always runs, fast)
                    is_phishing, score = phishing_model.predict(url)
                    url_prediction = {"is_phishing": is_phishing, "score": score}

                    # 2. External API enrichment (respects configured keys)
                    api_result = _run_api_checks(app, url)

                    # 3. Merge signals: if any external check flags phishing,
                    #    upgrade the result even if the heuristic said clean.
                    if api_result.composite_risk_score >= 0.35:
                        is_phishing = True

                    # 4. Persist to database
                    scan = ScanResult(
                        url=url,
                        is_phishing=is_phishing,
                        score=score,
                        user_id=current_user.id,
                        # Google Safe Browsing
                        google_safe_status=api_result.gsb_is_unsafe if not api_result.gsb_error else None,
                        # VirusTotal
                        virustotal_positives=api_result.vt_positives   if not api_result.vt_error   else None,
                        virustotal_total=api_result.vt_total_engines   if not api_result.vt_error   else None,
                        virustotal_confidence=api_result.vt_confidence if not api_result.vt_error   else None,
                        virustotal_permalink=api_result.vt_permalink,
                        # WHOIS
                        whois_creation_date=api_result.whois_creation_date,
                        whois_age_days=api_result.whois_age_days,
                        whois_registrar=api_result.whois_registrar,
                        # SSL
                        ssl_valid=api_result.ssl_valid               if not api_result.ssl_error   else None,
                        ssl_issuer=api_result.ssl_issuer,
                        ssl_expiry_date=api_result.ssl_expiry_date,
                        ssl_days_until_expiry=api_result.ssl_days_until_expiry,
                        ssl_is_self_signed=api_result.ssl_is_self_signed,
                        # URLScan.io
                        urlscan_uuid=api_result.urlscan_uuid,
                        urlscan_report_url=api_result.urlscan_url,
                        urlscan_screenshot_url=api_result.urlscan_screenshot,
                        urlscan_malicious=api_result.urlscan_malicious,
                        # Composite
                        composite_risk_score=api_result.composite_risk_score,
                        risk_label=api_result.risk_label,
                    )
                    db.session.add(scan)
                    db.session.commit()

                # ── Email scan (heuristic only – APIs are URL-based) ──────────
                if email_text:
                    is_phishing_email, score_email = phishing_model.predict_email(email_text)
                    email_prediction = {
                        "is_phishing": is_phishing_email,
                        "score": score_email,
                    }

        # ── Query history & metrics ───────────────────────────────────────────
        recent_scans = (
            ScanResult.query
            .filter_by(user_id=current_user.id)
            .order_by(ScanResult.created_at.desc())
            .limit(10)
            .all()
        )
        total_scans    = ScanResult.query.filter_by(user_id=current_user.id).count()
        phishing_scans = ScanResult.query.filter_by(user_id=current_user.id, is_phishing=True).count()
        safe_scans     = total_scans - phishing_scans if total_scans else 0

        return render_template(
            "dashboard.html",
            url_prediction=url_prediction,
            email_prediction=email_prediction,
            url=url,
            email_text=email_text,
            api_result=api_result,
            recent_scans=recent_scans,
            total_scans=total_scans,
            phishing_scans=phishing_scans,
            safe_scans=safe_scans,
        )

    # =========================================================================
    # PROFILE
    # =========================================================================

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user=current_user)

    # ── Health Check ──────────────────────────────────────────────────────────
    @app.route("/health")
    def health():
        return {"status": "healthy", "database": "connected"}, 200

    # ── Error Handlers ────────────────────────────────────────────────────────
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("index.html", error="Page not found"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("index.html", error="Internal server error"), 500


    return app


# =============================================================================
# HELPERS
# =============================================================================

def _run_api_checks(app: Flask, url: str) -> CompositeScanResult:
    """
    Run all configured external API checks for a URL.

    Results are cached in the ApiCache table (default TTL = 6 h) so
    repeated submissions of the same URL don't burn API quota.
    """
    import json
    from dataclasses import asdict

    cache_key_name = "composite"
    ttl = app.config.get("API_CACHE_TTL_HOURS", 6)

    # ── Check cache first ─────────────────────────────────────────────────────
    cached = ApiCache.get(url, cache_key_name)
    if cached:
        app.logger.info("API cache hit for %s", url)
        try:
            raw = json.loads(cached.response_json)
            # Re-hydrate the dataclass from cached dict
            result = _dict_to_composite(raw)
            return result
        except Exception:  # noqa: BLE001
            app.logger.warning("Cache deserialisation failed for %s – re-running checks", url)

    # ── Run live checks ───────────────────────────────────────────────────────
    flags = app.config.get("api_flags", Config.api_flags)()
    result = run_all_checks(url, **flags)

    # ── Store in cache (serialise datetimes as ISO strings) ───────────────────
    try:
        from dataclasses import fields as dc_fields
        raw: dict = {}
        for f in dc_fields(result):
            val = getattr(result, f.name)
            if isinstance(val, __import__("datetime").datetime):
                val = val.isoformat()
            raw[f.name] = val
        ApiCache.put(url, cache_key_name, raw, ttl_hours=ttl)
    except Exception:  # noqa: BLE001
        app.logger.warning("Failed to cache API result for %s", url)

    return result


def _dict_to_composite(raw: dict) -> CompositeScanResult:
    """Re-hydrate a CompositeScanResult from a cached JSON dict."""
    from datetime import datetime as _dt
    r = CompositeScanResult()
    for key, val in raw.items():
        if hasattr(r, key):
            # Parse ISO datetime strings back to datetime objects
            if isinstance(val, str) and key.endswith(("_date", "_at")):
                try:
                    val = _dt.fromisoformat(val)
                except ValueError:
                    pass
            setattr(r, key, val)
    return r


def _configure_logging(app: Flask) -> None:
    log_folder = Path(app.config.get("LOG_FOLDER", "logs"))
    log_folder.mkdir(parents=True, exist_ok=True)
    log_path = log_folder / "app.log"

    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


if __name__ == "__main__":
    import os
    
    # Configuration from environment variables for flexible local hosting
    HOST = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
    PORT = int(os.getenv("FLASK_RUN_PORT", 5000))
    DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"
    
    app = create_app()
    
    print(f"\n * SafePhishi starting on http://{HOST}:{PORT}")
    print(f" * Debug mode: {'Enabled' if DEBUG else 'Disabled'}")
    
    try:
        app.run(host=HOST, port=PORT, debug=DEBUG)
    except OSError as e:
        if "address already in use" in str(e).lower():
            print(f"\n[ERROR] Port {PORT} is already in use.")
            print(f"        Try running on a different port: set FLASK_RUN_PORT=5001")
        else:
            raise e
