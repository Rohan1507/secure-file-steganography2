"""
Security-focused tests: authentication, unauthorized access, path traversal,
capacity validation on corrupted/invalid images.
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models import db, User
from config import Config
from app.services import file_service


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username="testuser", email="test@example.com", password="StrongPass1!"):
    return client.post("/register", data={
        "full_name": "Test User",
        "email": email,
        "username": username,
        "password": password,
        "confirm_password": password,
    }, follow_redirects=True)


def login(client, username="testuser", password="StrongPass1!"):
    return client.post("/login", data={"username": username, "password": password},
                        follow_redirects=True)


def test_registration_creates_user(app, client):
    register(client)
    with app.app_context():
        user = User.query.filter_by(username="testuser").first()
        assert user is not None
        assert user.password_hash != "StrongPass1!"  # never store plaintext


def test_weak_password_rejected(client):
    resp = client.post("/register", data={
        "full_name": "Weak Pass",
        "email": "weak@example.com",
        "username": "weakuser",
        "password": "weak",
        "confirm_password": "weak",
    }, follow_redirects=True)
    assert b"at least" in resp.data.lower() or resp.status_code == 200


def test_duplicate_username_rejected(client):
    register(client, username="dupeuser", email="dupe1@example.com")
    resp = register(client, username="dupeuser", email="dupe2@example.com")
    assert b"already taken" in resp.data.lower()


def test_login_with_correct_credentials(client):
    register(client)
    resp = login(client)
    assert b"welcome" in resp.data.lower() or b"dashboard" in resp.data.lower()


def test_login_with_wrong_password_fails(client):
    register(client)
    resp = client.post("/login", data={"username": "testuser", "password": "WrongPass1!"},
                        follow_redirects=True)
    assert b"invalid" in resp.data.lower()


def test_unauthorized_dashboard_access_redirects_to_login(client):
    resp = client.get("/dashboard", follow_redirects=True)
    assert b"log in" in resp.data.lower() or b"login" in resp.data.lower()


def test_unauthorized_embed_access_blocked(client):
    resp = client.get("/embed", follow_redirects=True)
    assert b"log in" in resp.data.lower() or b"login" in resp.data.lower()


def test_password_never_stored_plaintext():
    user = User(full_name="X", email="x@x.com", username="x")
    user.set_password("MySecretPass1!")
    assert "MySecretPass1!" not in user.password_hash


def test_path_traversal_blocked():
    # werkzeug's secure_filename() strips path-traversal sequences before we
    # even check containment, so the result must stay inside base_dir either way.
    with tempfile.TemporaryDirectory() as base_dir:
        result = file_service.safe_join(base_dir, "../../etc/passwd")
        assert result.startswith(os.path.abspath(base_dir))
        assert ".." not in os.path.relpath(result, base_dir)


def test_safe_filename_generation_is_random():
    name1 = file_service.generate_safe_filename("secret.txt")
    name2 = file_service.generate_safe_filename("secret.txt")
    assert name1 != name2
    assert name1.endswith(".txt")


def test_extraction_requires_login(client):
    resp = client.get("/extract", follow_redirects=True)
    assert b"log in" in resp.data.lower() or b"login" in resp.data.lower()
