"""
Application configuration.
All secrets are loaded from environment variables (.env file).
Never hard-code secrets in this file.
"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # --- Core Flask ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-me-in-.env")
    if SECRET_KEY == "dev-key-change-me-in-.env":
        print("WARNING: Using default SECRET_KEY. Set SECRET_KEY in your .env file for production.")

    # --- Database ---
    _raw_db_url = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(basedir, 'stego_app.db')}"
    )
    if _raw_db_url.startswith("postgres://"):
        _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _raw_db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Sessions / cookies ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False") == "True"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # --- Uploads ---
    UPLOAD_FOLDER = os.path.join(basedir, "uploads")
    GENERATED_FOLDER = os.path.join(basedir, "generated")
    MAX_CONTENT_LENGTH = 60 * 1024 * 1024  # 60 MB hard ceiling for any single request

    ALLOWED_COVER_EXTENSIONS = {"png", "bmp"}
    ALLOWED_AUDIO_EXTENSIONS = {"wav"}
    ALLOWED_SECRET_EXTENSIONS = {
        "txt", "pdf", "docx", "xlsx", "zip", "png", "jpg", "jpeg",
        "mp3", "mp4", "csv", "json", "gif", "bmp", "doc", "pptx", "rar", "7z"
    }

    # --- Crypto ---
    PBKDF2_ITERATIONS = 390_000

    # --- Rate limiting (simple in-memory) ---
    LOGIN_ATTEMPT_LIMIT = 5
    LOGIN_ATTEMPT_WINDOW_SECONDS = 300


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
