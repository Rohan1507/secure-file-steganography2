"""
dashboard.py
============
Landing page, dashboard, history, and help/about pages.
"""
from flask import Blueprint, render_template
from flask_login import login_required, current_user

from ..models import FileOperation, StegoFile

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    return render_template("index.html")


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    total_embedded = FileOperation.query.filter_by(
        user_id=current_user.id, operation_type="embed", status="success"
    ).count()
    total_extracted = FileOperation.query.filter_by(
        user_id=current_user.id, operation_type="extract", status="success"
    ).count()
    recent_ops = FileOperation.query.filter_by(user_id=current_user.id) \
        .order_by(FileOperation.timestamp.desc()).limit(8).all()

    return render_template(
        "dashboard.html",
        total_embedded=total_embedded,
        total_extracted=total_extracted,
        recent_ops=recent_ops,
    )


@dashboard_bp.route("/history")
@login_required
def history():
    operations = FileOperation.query.filter_by(user_id=current_user.id) \
        .order_by(FileOperation.timestamp.desc()).all()
    stego_files = {sf.id: sf for sf in StegoFile.query.filter_by(user_id=current_user.id).all()}
    return render_template("history.html", operations=operations, stego_files=stego_files)


@dashboard_bp.route("/help")
def help_page():
    return render_template("help.html")
