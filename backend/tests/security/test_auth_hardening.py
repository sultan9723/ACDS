"""Regression tests for authentication hardening controls."""

import os

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-for-auth-hardening-32-chars")

from database import models as database_models
from models import schemas as api_schemas
from api.routes import auth as auth_routes
from main import app


client = TestClient(app)


STRONG_PASSWORD = "ValidPass123!"
NEW_STRONG_PASSWORD = "NewValidPass123!"


@pytest.fixture(autouse=True)
def isolated_auth_state(monkeypatch):
    monkeypatch.setattr(auth_routes, "USE_DATABASE", False)
    auth_routes.users_db.clear()
    auth_routes.login_rate_limits.clear()
    auth_routes.revoked_token_expirations.clear()
    yield
    auth_routes.users_db.clear()
    auth_routes.login_rate_limits.clear()
    auth_routes.revoked_token_expirations.clear()


def add_user(email, password=STRONG_PASSWORD, role="user", user_id=None, is_active=True):
    normalized_email = email.lower()
    auth_routes.users_db[normalized_email] = {
        "id": user_id or normalized_email,
        "email": normalized_email,
        "name": "Test User",
        "role": role,
        "password_hash": auth_routes.hash_password(password),
        "created_at": "2026-07-27T00:00:00+00:00",
        "last_login": None,
        "is_active": is_active,
        "login_count": 0,
    }
    return auth_routes.users_db[normalized_email]


def login(email, password=STRONG_PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_verify_password_is_bcrypt_only():
    bcrypt_hash = auth_routes.hash_password(STRONG_PASSWORD)
    legacy_sha256_hash = "617d6d7c17c6c68a7e3d9d1efccaa64e3c633e99af4f2b3f37d0b82e7b82f9fd"

    assert auth_routes.verify_password(STRONG_PASSWORD, bcrypt_hash) is True
    assert auth_routes.verify_password(STRONG_PASSWORD, legacy_sha256_hash) is False
    assert auth_routes.verify_password(STRONG_PASSWORD, "not-a-bcrypt-hash") is False


def test_auth_models_validate_email_and_new_password_complexity():
    with pytest.raises(ValidationError):
        auth_routes.UserLogin(email="not-an-email", password="anything")

    with pytest.raises(ValidationError):
        auth_routes.UserCreate(
            email="new@example.com",
            name="New User",
            password="weak",
            role="user",
        )

    with pytest.raises(ValidationError):
        auth_routes.ChangePasswordRequest(
            current_password="current",
            new_password="lowercaseonly123",
        )

    with pytest.raises(ValidationError):
        auth_routes.AdminResetPasswordRequest(new_password="NoSpecial123")

    with pytest.raises(ValidationError):
        database_models.UserCreate(
            email="not-an-email",
            name="New User",
            password=STRONG_PASSWORD,
            role=database_models.UserRole.USER,
        )

    with pytest.raises(ValidationError):
        api_schemas.UserCreate(
            email="schema@example.com",
            name="Schema User",
            password="weak",
            role="user",
        )


def test_login_failure_lockout_blocks_later_correct_password(monkeypatch):
    monkeypatch.setattr(auth_routes, "LOGIN_FAILURE_LIMIT", 2)
    add_user("lockout@example.com")

    assert login("lockout@example.com", "wrong-one").status_code == 401
    assert login("lockout@example.com", "wrong-two").status_code == 401

    response = login("lockout@example.com", STRONG_PASSWORD)

    assert response.status_code == 429
    assert response.json()["detail"] == "Too many login attempts. Try again later."


def test_successful_login_emits_audit_and_does_not_store_active_token(monkeypatch):
    events = []
    monkeypatch.setattr(
        auth_routes,
        "record_auth_audit_event",
        lambda **kwargs: events.append(kwargs),
    )
    add_user("success@example.com", role="admin")

    response = login("success@example.com")

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert not hasattr(auth_routes, "active_tokens")
    assert events[-1]["action"] == "login_success"
    assert events[-1]["success"] is True


def test_logout_revokes_token_and_emits_audit(monkeypatch):
    events = []
    monkeypatch.setattr(
        auth_routes,
        "record_auth_audit_event",
        lambda **kwargs: events.append(kwargs),
    )
    add_user("logout@example.com")
    token = login("logout@example.com").json()["access_token"]

    assert client.post("/api/v1/auth/validate-token", headers=bearer(token)).json()["valid"] is True

    response = client.post("/api/v1/auth/logout", headers=bearer(token))

    assert response.status_code == 200
    assert client.post("/api/v1/auth/validate-token", headers=bearer(token)).json()["valid"] is False
    assert events[-1]["action"] == "logout"
    assert events[-1]["success"] is True


def test_register_and_users_use_admin_dependency():
    add_user("normal@example.com", role="user")
    token = login("normal@example.com").json()["access_token"]

    register_response = client.post(
        "/api/v1/auth/register",
        headers=bearer(token),
        json={
            "email": "created@example.com",
            "name": "Created User",
            "password": STRONG_PASSWORD,
            "role": "user",
        },
    )
    users_response = client.get("/api/v1/auth/users", headers=bearer(token))

    assert register_response.status_code == 403
    assert users_response.status_code == 403
    assert register_response.json()["detail"] == "Admin access required"


def test_admin_can_reset_user_password_and_old_password_stops_working(monkeypatch):
    events = []
    monkeypatch.setattr(
        auth_routes,
        "record_auth_audit_event",
        lambda **kwargs: events.append(kwargs),
    )
    add_user("admin@example.com", role="admin", user_id="admin-1")
    add_user("target@example.com", role="user", user_id="target-1")
    admin_token = login("admin@example.com").json()["access_token"]

    reset_response = client.post(
        "/api/v1/auth/users/target-1/reset-password",
        headers=bearer(admin_token),
        json={"new_password": NEW_STRONG_PASSWORD},
    )

    assert reset_response.status_code == 200
    assert login("target@example.com", NEW_STRONG_PASSWORD).status_code == 200
    assert login("target@example.com", STRONG_PASSWORD).status_code == 401
    assert any(event["action"] == "admin_reset_password" and event["success"] for event in events)


def test_change_password_audits_failure_and_success(monkeypatch):
    events = []
    monkeypatch.setattr(
        auth_routes,
        "record_auth_audit_event",
        lambda **kwargs: events.append(kwargs),
    )
    add_user("change@example.com")
    token = login("change@example.com").json()["access_token"]

    failed = client.post(
        "/api/v1/auth/change-password",
        headers=bearer(token),
        json={"current_password": "wrong", "new_password": NEW_STRONG_PASSWORD},
    )
    succeeded = client.post(
        "/api/v1/auth/change-password",
        headers=bearer(token),
        json={"current_password": STRONG_PASSWORD, "new_password": NEW_STRONG_PASSWORD},
    )

    assert failed.status_code == 400
    assert succeeded.status_code == 200
    assert any(event["action"] == "change_password" and not event["success"] for event in events)
    assert any(event["action"] == "change_password" and event["success"] for event in events)
