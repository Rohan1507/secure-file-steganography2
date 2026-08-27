"""
steganography.py
=================
Embed / Extract / Download / Capacity-calculation routes.
This is where the full pipeline comes together:

  SECRET FILE -> ENCRYPT (AES-256-GCM) -> BUILD PAYLOAD -> LSB EMBED -> STEGO IMAGE
  STEGO IMAGE -> LSB EXTRACT -> PARSE PAYLOAD -> DECRYPT -> VERIFY SHA-256 -> ORIGINAL FILE
"""
import os
import logging

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    send_from_directory, current_app, abort, jsonify
)
from flask_login import login_required, current_user

from ..models import db, FileOperation, StegoFile
from ..services import crypto_service, stego_service, file_service

stego_bp = Blueprint("stego", __name__)
logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# EMBED
# --------------------------------------------------------------------------- #

@stego_bp.route("/embed", methods=["GET", "POST"])
@login_required
def embed():
    if request.method == "GET":
        return render_template("embed.html")

    cover_file = request.files.get("cover_image")
    secret_file = request.files.get("secret_file")
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    # --- Basic validation ---
    if not cover_file or cover_file.filename == "":
        flash("Please select a cover image.", "danger")
        return redirect(url_for("stego.embed"))
    if not secret_file or secret_file.filename == "":
        flash("Please select a secret file to hide.", "danger")
        return redirect(url_for("stego.embed"))
    if not file_service.allowed_file(cover_file.filename, current_app.config["ALLOWED_COVER_EXTENSIONS"]):
        flash("Cover image must be PNG or BMP.", "danger")
        return redirect(url_for("stego.embed"))
    if not file_service.allowed_file(secret_file.filename, current_app.config["ALLOWED_SECRET_EXTENSIONS"]):
        flash("This secret file type is not supported.", "danger")
        return redirect(url_for("stego.embed"))
    if password != confirm_password:
        flash("Encryption passwords do not match.", "danger")
        return redirect(url_for("stego.embed"))
    if len(password) < 8:
        flash("Encryption password must be at least 8 characters.", "danger")
        return redirect(url_for("stego.embed"))

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    generated_dir = current_app.config["GENERATED_FOLDER"]

    # --- Save cover image to disk with a random safe filename ---
    cover_safe_name = file_service.generate_safe_filename(cover_file.filename)
    cover_path = file_service.safe_join(upload_dir, cover_safe_name)
    cover_file.save(cover_path)

    if not file_service.validate_image_magic_bytes(cover_path):
        os.remove(cover_path)
        flash("The uploaded cover image is not a valid PNG/BMP file.", "danger")
        return redirect(url_for("stego.embed"))

    try:
        # --- Read secret file fully into memory as binary; never trust its name ---
        original_filename = secret_file.filename
        secret_bytes = secret_file.read()
        secret_size = len(secret_bytes)

        if secret_size == 0:
            raise ValueError("Secret file is empty.")

        sha256_original = crypto_service.sha256_of_bytes(secret_bytes)
        extension = file_service.get_extension(original_filename)
        safe_display_name = os.path.basename(original_filename)[:200]

        # --- Capacity check ---
        capacity = stego_service.calculate_capacity(cover_path)

        # --- Encrypt ---
        enc = crypto_service.encrypt_data(secret_bytes, password)

        # --- Build structured payload ---
        payload = stego_service.build_payload(
            filename=safe_display_name,
            extension=extension,
            salt=enc["salt"],
            nonce=enc["nonce"],
            iterations=enc["iterations"],
            sha256_original=sha256_original,
            ciphertext=enc["ciphertext"],
        )

        if len(payload) > capacity["usable_capacity_bytes"]:
            raise stego_service.InsufficientCapacityError(
                "Secret file is too large for this cover image. Please select a larger image. "
                f"(payload needs {len(payload)} bytes, image can hold "
                f"{capacity['usable_capacity_bytes']} bytes)"
            )

        # --- Embed ---
        stego_safe_name = file_service.generate_safe_filename("stego.png")
        stego_path = file_service.safe_join(generated_dir, stego_safe_name)
        embed_info = stego_service.embed_payload_into_image(cover_path, payload, stego_path)

        # --- Self-validate the pipeline immediately ---
        extracted_check = stego_service.extract_payload_from_image(stego_path)
        if extracted_check != payload:
            raise stego_service.StegoError("Internal validation failed after embedding.")

        # --- Persist records ---
        stego_record = StegoFile(
            user_id=current_user.id,
            filename=stego_safe_name,
            cover_filename=cover_safe_name,
            carrier_type="image",
            secret_filename=safe_display_name,
            payload_size=len(payload),
            sha256_original=sha256_original,
        )
        db.session.add(stego_record)
        db.session.flush()  # get stego_record.id

        op = FileOperation(
            user_id=current_user.id,
            operation_type="embed",
            original_filename=safe_display_name,
            carrier_filename=cover_safe_name,
            result_filename=stego_safe_name,
            stego_file_id=stego_record.id,
            file_size=secret_size,
            status="success",
            sha256_original=sha256_original,
            verification="N/A",
        )
        db.session.add(op)
        db.session.commit()

        flash("Secret file embedded successfully.", "success")
        return render_template(
            "embed.html",
            result=True,
            stego_id=stego_record.id,
            operation_id=op.id,
            capacity=capacity,
            embed_info=embed_info,
            payload_size=len(payload),
        )

    except stego_service.InsufficientCapacityError as e:
        db.session.rollback()
        flash(str(e), "danger")
    except Exception as e:
        db.session.rollback()
        logger.exception("Embed operation failed")
        flash("Embedding failed due to an internal error. Please check your files and try again.", "danger")
        FileOperation_ = FileOperation(
            user_id=current_user.id, operation_type="embed",
            original_filename=secret_file.filename if secret_file else None,
            carrier_filename=cover_safe_name, status="failed",
        )
        db.session.add(FileOperation_)
        db.session.commit()
    finally:
        # Cover image copy in uploads/ is no longer needed after embedding (only generated stego matters)
        pass

    return redirect(url_for("stego.embed"))


# --------------------------------------------------------------------------- #
# EXTRACT
# --------------------------------------------------------------------------- #

@stego_bp.route("/extract", methods=["GET", "POST"])
@login_required
def extract():
    if request.method == "GET":
        return render_template("extract.html")

    stego_upload = request.files.get("stego_image")
    password = request.form.get("password", "")

    if not stego_upload or stego_upload.filename == "":
        flash("Please upload a stego image.", "danger")
        return redirect(url_for("stego.extract"))
    if not file_service.allowed_file(stego_upload.filename, {"png", "bmp"}):
        flash("Stego image must be a PNG (or BMP) file.", "danger")
        return redirect(url_for("stego.extract"))
    if not password:
        flash("Please enter the decryption password.", "danger")
        return redirect(url_for("stego.extract"))

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    generated_dir = current_app.config["GENERATED_FOLDER"]

    stego_safe_name = file_service.generate_safe_filename(stego_upload.filename)
    stego_path = file_service.safe_join(upload_dir, stego_safe_name)
    stego_upload.save(stego_path)

    if not file_service.validate_image_magic_bytes(stego_path):
        os.remove(stego_path)
        flash("The uploaded file is not a valid PNG/BMP image.", "danger")
        return redirect(url_for("stego.extract"))

    op = FileOperation(
        user_id=current_user.id, operation_type="extract",
        carrier_filename=stego_safe_name, status="failed", verification="FAIL",
    )

    try:
        payload = stego_service.extract_payload_from_image(stego_path)
        parsed = stego_service.parse_payload(payload)

        plaintext = crypto_service.decrypt_data(
            ciphertext=parsed["ciphertext"],
            password=password,
            salt=parsed["salt"],
            nonce=parsed["nonce"],
            iterations=parsed["iterations"],
        )

        sha256_extracted = crypto_service.sha256_of_bytes(plaintext)
        verification = "PASS" if sha256_extracted == parsed["sha256_original"] else "FAIL"

        # Save recovered file
        recovered_name = file_service.generate_safe_filename(
            f"recovered.{parsed['extension'] or 'bin'}"
        )
        recovered_path = file_service.safe_join(generated_dir, recovered_name)
        with open(recovered_path, "wb") as f:
            f.write(plaintext)

        op.status = "success"
        op.original_filename = parsed["filename"]
        op.result_filename = recovered_name
        op.file_size = len(plaintext)
        op.sha256_original = parsed["sha256_original"]
        op.sha256_result = sha256_extracted
        op.verification = verification
        db.session.add(op)
        db.session.commit()

        flash("File extracted and verified successfully." if verification == "PASS"
              else "File extracted, but integrity verification FAILED.",
              "success" if verification == "PASS" else "warning")

        return render_template(
            "extract.html",
            result=True,
            operation_id=op.id,
            filename=parsed["filename"],
            extension=parsed["extension"],
            file_size=len(plaintext),
            sha256_original=parsed["sha256_original"],
            sha256_result=sha256_extracted,
            verification=verification,
        )

    except stego_service.NoPayloadFoundError:
        db.session.add(op)
        db.session.commit()
        flash("No valid hidden data was detected.", "danger")
    except crypto_service.DecryptionError:
        db.session.add(op)
        db.session.commit()
        flash("Decryption failed. Invalid password or corrupted hidden data.", "danger")
    except Exception:
        logger.exception("Extraction operation failed")
        db.session.add(op)
        db.session.commit()
        flash("Extraction failed due to an internal error.", "danger")

    return redirect(url_for("stego.extract"))


# --------------------------------------------------------------------------- #
# CAPACITY API
# --------------------------------------------------------------------------- #

@stego_bp.route("/api/calculate-capacity", methods=["POST"])
@login_required
def api_calculate_capacity():
    cover_file = request.files.get("cover_image")
    secret_size = request.form.get("secret_size", type=int, default=0)

    if not cover_file or cover_file.filename == "":
        return jsonify({"error": "No cover image provided."}), 400
    if not file_service.allowed_file(cover_file.filename, current_app.config["ALLOWED_COVER_EXTENSIONS"]):
        return jsonify({"error": "Cover image must be PNG or BMP."}), 400

    tmp_name = file_service.generate_safe_filename(cover_file.filename)
    tmp_path = file_service.safe_join(current_app.config["UPLOAD_FOLDER"], tmp_name)
    cover_file.save(tmp_path)

    try:
        if not file_service.validate_image_magic_bytes(tmp_path):
            return jsonify({"error": "Invalid PNG/BMP image."}), 400

        capacity = stego_service.calculate_capacity(tmp_path)
        # payload has ~68 bytes of fixed overhead + filename/extension - estimate conservatively
        overhead_estimate = 68 + 64
        required = secret_size + overhead_estimate if secret_size else 0
        remaining = capacity["usable_capacity_bytes"] - required

        return jsonify({
            "width": capacity["width"],
            "height": capacity["height"],
            "channels": capacity["channels"],
            "usable_capacity_bytes": capacity["usable_capacity_bytes"],
            "secret_size_bytes": secret_size,
            "estimated_required_bytes": required,
            "remaining_bytes": remaining,
            "sufficient": remaining >= 0,
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# --------------------------------------------------------------------------- #
# DOWNLOADS (authenticated, ownership-checked)
# --------------------------------------------------------------------------- #

@stego_bp.route("/download/stego/<int:stego_id>")
@login_required
def download_stego(stego_id):
    record = StegoFile.query.get_or_404(stego_id)
    if record.user_id != current_user.id:
        abort(403)
    return send_from_directory(
        current_app.config["GENERATED_FOLDER"], record.filename,
        as_attachment=True, download_name=f"stego_{stego_id}.png"
    )


@stego_bp.route("/download/extracted/<int:operation_id>")
@login_required
def download_extracted(operation_id):
    op = FileOperation.query.get_or_404(operation_id)
    if op.user_id != current_user.id:
        abort(403)
    if not op.result_filename or op.status != "success":
        abort(404)
    download_name = op.original_filename or op.result_filename
    return send_from_directory(
        current_app.config["GENERATED_FOLDER"], op.result_filename,
        as_attachment=True, download_name=download_name
    )
