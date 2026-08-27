"""
analysis.py
===========
Security Analysis / Steganalysis page: MSE, PSNR, SSIM, chi-square,
cover-vs-stego visual comparison and difference image.
"""
import os
import logging

from flask import (
    Blueprint, render_template, current_app, abort, send_from_directory
)
from flask_login import login_required, current_user

from ..models import db, StegoFile, SecurityAnalysis
from ..services import analysis_service, file_service

analysis_bp = Blueprint("analysis", __name__)
logger = logging.getLogger(__name__)


@analysis_bp.route("/analysis/<int:stego_id>")
@login_required
def analysis(stego_id):
    record = StegoFile.query.get_or_404(stego_id)
    if record.user_id != current_user.id:
        abort(403)

    generated_dir = current_app.config["GENERATED_FOLDER"]
    upload_dir = current_app.config["UPLOAD_FOLDER"]

    cover_path = file_service.safe_join(upload_dir, record.cover_filename)
    stego_path = file_service.safe_join(generated_dir, record.filename)

    if not os.path.exists(cover_path) or not os.path.exists(stego_path):
        return render_template(
            "analysis.html", record=record, unavailable=True,
            message="Original cover image is no longer available on the server "
                    "(temporary uploads may have been cleaned up), so a fresh "
                    "comparison cannot be generated. Historical results are shown if available."
        )

    diff_name = f"diff_{record.id}.png"
    diff_path = file_service.safe_join(generated_dir, diff_name)

    try:
        results = analysis_service.full_analysis(
            cover_path, stego_path,
            payload_bytes=record.payload_size,
            capacity_bytes=_recompute_capacity(cover_path),
            diff_output_path=diff_path,
        )

        existing = SecurityAnalysis.query.filter_by(stego_file_id=record.id).first()
        if not existing:
            existing = SecurityAnalysis(stego_file_id=record.id)
            db.session.add(existing)

        existing.mse = results["mse"]
        existing.psnr = results["psnr"]
        existing.ssim = results["ssim"]
        existing.capacity_bytes = results["capacity_bytes"]
        existing.payload_bytes = results["payload_bytes"]
        existing.payload_ratio = results["payload_ratio"]
        existing.chi_square = results["chi_square"]
        db.session.commit()

        cover_size = os.path.getsize(cover_path)
        stego_size = os.path.getsize(stego_path)

        return render_template(
            "analysis.html",
            record=record,
            results=results,
            diff_filename=diff_name,
            cover_size=cover_size,
            stego_size=stego_size,
            unavailable=False,
        )
    except Exception:
        logger.exception("Analysis failed")
        return render_template(
            "analysis.html", record=record, unavailable=True,
            message="Security analysis could not be completed for this file."
        )


def _recompute_capacity(cover_path: str) -> int:
    from ..services import stego_service
    cap = stego_service.calculate_capacity(cover_path)
    return cap["usable_capacity_bytes"]


@analysis_bp.route("/analysis/image/cover/<int:stego_id>")
@login_required
def serve_cover_image(stego_id):
    record = StegoFile.query.get_or_404(stego_id)
    if record.user_id != current_user.id:
        abort(403)
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], record.cover_filename)


@analysis_bp.route("/analysis/image/stego/<int:stego_id>")
@login_required
def serve_stego_image(stego_id):
    record = StegoFile.query.get_or_404(stego_id)
    if record.user_id != current_user.id:
        abort(403)
    return send_from_directory(current_app.config["GENERATED_FOLDER"], record.filename)


@analysis_bp.route("/analysis/image/diff/<int:stego_id>")
@login_required
def serve_diff_image(stego_id):
    record = StegoFile.query.get_or_404(stego_id)
    if record.user_id != current_user.id:
        abort(403)
    diff_name = f"diff_{record.id}.png"
    diff_path = file_service.safe_join(current_app.config["GENERATED_FOLDER"], diff_name)
    if not os.path.exists(diff_path):
        abort(404)
    return send_from_directory(current_app.config["GENERATED_FOLDER"], diff_name)
