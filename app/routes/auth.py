"""
auth.py
=======
Registration, login, logout. Passwords are hashed with Argon2 (via User model).
Includes a simple in-memory rate limiter on login attempts to slow brute force.
"""
import re
import time
from collections import defaultdict

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from ..models import db, User

auth_bp = Blueprint("auth", __name__)

# --- Very simple in-memory rate limiter: {ip: [timestamps]} ---
_login_attempts = defaultdict(list)
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 300

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def _password_is_strong(password: str) -> str:
    """Returns an error message if weak, or '' if strong enough."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password):
        return "Password must contain at least one special character."
    return ""


def _rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts[ip] if now - t < LOGIN_ATTEMPT_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= LOGIN_ATTEMPT_LIMIT


def _record_attempt(ip: str) -> None:
    _login_attempts[ip].append(time.time())


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        if not EMAIL_RE.match(email):
            errors.append("Please provide a valid email address.")
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-30 characters (letters, numbers, underscore only).")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        pw_error = _password_is_strong(password)
        if pw_error:
            errors.append(pw_error)

        if not errors:
            if User.query.filter_by(email=email).first():
                errors.append("An account with this email already exists.")
            if User.query.filter_by(username=username).first():
                errors.append("This username is already taken.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", full_name=full_name, email=email, username=username)

        user = User(full_name=full_name, email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _rate_limited(ip):
            flash("Too many login attempts. Please wait a few minutes and try again.", "danger")
            return render_template("login.html"), 429

        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f"Welcome back, {user.full_name}.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.dashboard"))

        _record_attempt(ip)
        flash("Invalid username/email or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
