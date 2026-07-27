# Authentication Hardening Baseline

Date: 2026-07-27
Branch: `develop`

## Objective

This baseline fixes the authentication issues identified during review without changing the successful login response contract used by the frontend.

## Fixed Issues

- Removed SHA-256 password fallback from `verify_password`; bcrypt is the only accepted password hash format.
- Reused `get_current_admin` for admin-only user registration and user listing.
- Added login rate limiting using the existing `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW` settings.
- Added failed-login lockout with `LOGIN_FAILURE_LIMIT` and `LOGIN_LOCKOUT_SECONDS`.
- Removed the write-only `active_tokens` in-memory store.
- Replaced unbounded `revoked_token_ids` with Mongo-backed token revocation plus bounded in-memory fallback.
- Added insert-only auth audit events for login success, login failure, logout, password change, and admin password reset.
- Added `EmailStr` validation for auth request models and user-create schemas.
- Added password complexity validation for registration, password change, and admin password reset.
- Added admin-assisted password reset at `POST /api/v1/auth/users/{user_id}/reset-password`.

## Persistent State

Migration `v007_auth_hardening_state_indexes.py` creates and indexes:

- `auth_rate_limits`
- `revoked_tokens`

Both collections have TTL cleanup through `expires_at`.

## Auth Audit Events

Auth audit events are best-effort writes to `audit_logs` with:

- `action_type = authentication`
- no passwords
- no password hashes
- no JWTs
- no authorization headers
- stable error reasons such as `invalid_credentials`, `rate_limited`, and `current_password_incorrect`

Audit persistence failure does not change the user-facing auth response.

## Validation

Passed:

- `python -m py_compile backend/api/routes/auth.py backend/config/settings.py backend/core/password_policy.py backend/database/models.py backend/models/schemas.py backend/database/migrations/versions/v007_auth_hardening_state_indexes.py`
- `python -m pytest backend/tests/security/test_auth_hardening.py -q`: `8 passed`
- `python -m pytest backend/tests/security -q`: `8 passed`
- `python -m compileall backend`
- `git diff --check`

Full suite status:

- `python -m pytest -q` still fails during collection on the existing phishing module import mismatch: `PHISHING_KEYWORDS` is not exported from `backend.src.services.phishing_detection.detection_agent`.

## Residual Notes

The login throttle and token revocation state are Mongo-backed for multi-worker and restart safety. If MongoDB is unavailable, the service falls back to bounded in-memory state to keep local development usable, but production should run with MongoDB available.
