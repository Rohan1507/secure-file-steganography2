"""
Application factory for the Secure File Sharing with Steganography project.
"""
import os
from flask import Flask, render_template
from flask_login import LoginManager
from flask_wtf import CSRFProtect

from config import Config
from .models import db, User

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["GENERATED_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # --- Security headers on every response ---
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    # --- Blueprints ---
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.steganography import stego_bp
    from .routes.analysis import analysis_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(stego_bp)
    app.register_blueprint(analysis_bp)

    # --- Error handlers (never leak stack traces to users) ---
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors.html", code=404,
                                message="Page not found."), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors.html", code=403,
                                message="You do not have permission to access this resource."), 403

    @app.errorhandler(413)
    def too_large(e):
        return render_template("errors.html", code=413,
                                message="Uploaded file is too large."), 413

    @app.errorhandler(500)
    def server_error(e):
        app.logger.error(f"Internal server error: {e}")
        return render_template("errors.html", code=500,
                                message="An internal error occurred. Please try again."), 500

    with app.app_context():
        db.create_all()

    return app
