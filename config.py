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
        # Loud warning so students remember to set a real key for real deployments
        print("WARNING: Using default SECRET_KEY. Set SECRET_KEY in your .env file for production.")

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(basedir, 'stego_app.db')}"
    )
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
    # Secret files can reasonably be almost anything - treated as raw binary.
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
