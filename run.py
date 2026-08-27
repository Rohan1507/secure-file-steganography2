"""
Entry point for the Secure File Sharing with Steganography application.

Usage:
    python run.py
"""
import os
from dotenv import load_dotenv

load_dotenv()  # loads variables from a local .env file, if present

from app import create_app
from config import DevelopmentConfig, ProductionConfig

env = os.environ.get("FLASK_ENV", "development")
config_class = ProductionConfig if env == "production" else DevelopmentConfig

app = create_app(config_class)

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "True") == "True"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
