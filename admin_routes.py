from functools import wraps
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from models import db, User, ScanResult, ApiCache
from sqlalchemy import func

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Access denied — admins only.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Basic metrics
    total_users = User.query.count()
    total_scans = ScanResult.query.count()
    phishing_scans = ScanResult.query.filter_by(is_phishing=True).count()
    
    # Active today (users who scanned today)
    today = datetime.utcnow().date()
    active_today = db.session.query(func.count(func.distinct(ScanResult.user_id))).filter(func.date(ScanResult.created_at) == today).scalar()
    
    # Recent scans
    recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(15).all()
    
    # Recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    # System info
    import os
    db_file = current_app.config.get('SQLALCHEMY_DATABASE_URI', '').replace('sqlite:///', '')
    db_size = 0
    if os.path.exists(db_file):
        db_size = os.path.getsize(db_file) / (1024 * 1024) # MB

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_scans=total_scans,
        phishing_scans=phishing_scans,
        active_today=active_today,
        recent_scans=recent_scans,
        recent_users=recent_users,
        db_size=f"{db_size:.2f} MB" if db_size else "Unknown"
    )

@admin_bp.route('/stats')
@login_required
@admin_required
def stats():
    # Time-series data: scans per day (last 7 days)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    
    # Fill missing days with zero
    day_map = {}
    for i in range(8):
        d = (start_date + timedelta(days=i)).date().isoformat()
        day_map[d] = {'scans': 0, 'phishing': 0}

    scans_per_day = db.session.query(
        func.date(ScanResult.created_at).label('date'),
        func.count(ScanResult.id).label('count')
    ).filter(ScanResult.created_at >= start_date).group_by(func.date(ScanResult.created_at)).all()
    
    for r in scans_per_day:
        if str(r.date) in day_map:
            day_map[str(r.date)]['scans'] = r.count
            
    phishing_per_day = db.session.query(
        func.date(ScanResult.created_at).label('date'),
        func.count(ScanResult.id).label('count')
    ).filter(ScanResult.created_at >= start_date, ScanResult.is_phishing == True).group_by(func.date(ScanResult.created_at)).all()
    
    for r in phishing_per_day:
        if str(r.date) in day_map:
            day_map[str(r.date)]['phishing'] = r.count
            
    # Risk distribution (handle nulls)
    risk_dist_raw = db.session.query(
        ScanResult.risk_label,
        func.count(ScanResult.id)
    ).group_by(ScanResult.risk_label).all()
    
    risk_labels = []
    risk_values = []
    for label, count in risk_dist_raw:
        risk_labels.append(label if label else "Unlabeled")
        risk_values.append(count)
    
    # Top Phishing Domains (Simple extraction)
    # We can't easily parse domains in SQL, so we'll do it in Python for the recent high-risk ones
    from urllib.parse import urlparse
    recent_phishing = ScanResult.query.filter_by(is_phishing=True).limit(100).all()
    domain_counts = {}
    for s in recent_phishing:
        try:
            domain = urlparse(s.url).netloc
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except: continue
        
    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return jsonify({
        'time_series': {
            'labels': [d[5:] for d in day_map.keys()], # Truncate year for labels
            'scans': [v['scans'] for v in day_map.values()],
            'phishing': [v['phishing'] for v in day_map.values()]
        },
        'risk_dist': {
            'labels': risk_labels,
            'values': risk_values
        },
        'top_domains': {
            'labels': [d[0] for d in sorted_domains],
            'values': [d[1] for d in sorted_domains]
        }
    })

@admin_bp.route('/users')
@login_required
@admin_required
def users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    # Annotate with scan counts
    for user in users:
        user.scan_count = ScanResult.query.filter_by(user_id=user.id).count()
    return render_template("admin_users.html", users=users)

@admin_bp.route('/user/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    if user_id == current_user.id:
        flash("You cannot revoke your own admin status.", "warning")
        return redirect(url_for('admin.dashboard'))
        
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"Admin status for {user.email} updated.", "success")
    return redirect(request.referrer or url_for('admin.dashboard'))

@admin_bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash("Scan result deleted.", "info")
    return redirect(request.referrer or url_for('admin.dashboard'))

@admin_bp.route('/system/clear-cache', methods=['POST'])
@login_required
@admin_required
def clear_cache():
    num_deleted = ApiCache.query.delete()
    db.session.commit()
    flash(f"Cache cleared: {num_deleted} entries removed.", "success")
    return redirect(url_for('admin.dashboard'))
