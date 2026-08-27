"""
SQLAlchemy models for the Secure File Sharing with Steganography app.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

db = SQLAlchemy()
_ph = PasswordHasher()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    operations = db.relationship("FileOperation", backref="user", lazy=True,
                                  cascade="all, delete-orphan")
    stego_files = db.relationship("StegoFile", backref="user", lazy=True,
                                   cascade="all, delete-orphan")

    def set_password(self, raw_password: str) -> None:
        self.password_hash = _ph.hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        try:
            return _ph.verify(self.password_hash, raw_password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False


class FileOperation(db.Model):
    """A log entry for every embed / extract operation a user performs."""
    __tablename__ = "file_operations"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    operation_type = db.Column(db.String(20), nullable=False)  # 'embed' | 'extract'
    original_filename = db.Column(db.String(255))
    carrier_filename = db.Column(db.String(255))
    result_filename = db.Column(db.String(255))   # server-side generated output file (stego image or recovered secret)
    stego_file_id = db.Column(db.Integer, db.ForeignKey("stego_files.id"), nullable=True)
    file_size = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="success")  # success | failed
    sha256_original = db.Column(db.String(64))
    sha256_result = db.Column(db.String(64))
    verification = db.Column(db.String(10))  # PASS | FAIL | N/A


class StegoFile(db.Model):
    """Metadata about a generated stego image, used later for analysis/history."""
    __tablename__ = "stego_files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)          # stego image on disk
    cover_filename = db.Column(db.String(255))                    # original cover copy on disk
    carrier_type = db.Column(db.String(10), default="image")      # image | audio
    secret_filename = db.Column(db.String(255))
    payload_size = db.Column(db.Integer)
    sha256_original = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    analysis = db.relationship("SecurityAnalysis", backref="stego_file", uselist=False,
                                cascade="all, delete-orphan")


class SecurityAnalysis(db.Model):
    __tablename__ = "security_analyses"

    id = db.Column(db.Integer, primary_key=True)
    stego_file_id = db.Column(db.Integer, db.ForeignKey("stego_files.id"), nullable=False)
    mse = db.Column(db.Float)
    psnr = db.Column(db.Float)
    ssim = db.Column(db.Float)
    capacity_bytes = db.Column(db.Integer)
    payload_bytes = db.Column(db.Integer)
    payload_ratio = db.Column(db.Float)
    chi_square = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
