"""
Authentication API Routes
==========================
API endpoints for user authentication and authorization.
Uses MongoDB database with fallback to in-memory storage.
"""

import logging
import uuid
import jwt
import bcrypt
from datetime import datetime, timezone, timedelta
from typing import Any, Literal, Optional
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from pydantic import BaseModel, EmailStr, Field, field_validator

from core.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_complexity,
)

try:
    from bson import ObjectId
except ImportError:  # pragma: no cover - bson is provided by pymongo in deployments
    ObjectId = None


MAX_IN_MEMORY_AUTH_KEYS = 10000
AUTH_RATE_LIMIT_COLLECTION = "auth_rate_limits"
REVOKED_TOKENS_COLLECTION = "revoked_tokens"

# Define models locally to avoid import issues
class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH)

class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    role: Literal["admin", "user"] = "user"

    @field_validator("password")
    @classmethod
    def password_meets_complexity(cls, value: str) -> str:
        return validate_password_complexity(value)

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("new_password")
    @classmethod
    def new_password_meets_complexity(cls, value: str) -> str:
        return validate_password_complexity(value)

class AdminResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("new_password")
    @classmethod
    def new_password_meets_complexity(cls, value: str) -> str:
        return validate_password_complexity(value)

# Import settings. Authentication must fail closed if configuration is broken.
from config.settings import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    BOOTSTRAP_ADMIN_ENABLED,
    BOOTSTRAP_ADMIN_EMAIL,
    BOOTSTRAP_ADMIN_PASSWORD,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW,
    LOGIN_FAILURE_LIMIT,
    LOGIN_LOCKOUT_SECONDS,
)

# Import database (optional - fallback to in-memory)
try:
    from database.connection import get_collection
    USE_DATABASE = True
except ImportError:
    USE_DATABASE = False
    get_collection = None

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if not request or not request.client:
        return None
    return request.client.host


def _normalize_email(email: Any) -> str:
    return str(email).strip().lower()


def _collection(name: str):
    if not USE_DATABASE or not get_collection:
        return None
    try:
        return get_collection(name)
    except Exception as exc:
        logger.warning("Database collection lookup failed for %s: %s", name, exc)
        return None


def _user_id(user: Optional[dict]) -> Optional[str]:
    if not user:
        return None
    value = user.get("id") or user.get("_id")
    return str(value) if value else None


def _rate_limit_key(kind: str, value: Optional[str]) -> str:
    normalized = value or "unknown"
    return f"{kind}:{uuid.uuid5(uuid.NAMESPACE_URL, f'acds-auth:{kind}:{normalized}')}"


def _prune_memory_auth_state(now: datetime) -> None:
    expired_revocations = [
        token_id
        for token_id, expires_at in revoked_token_expirations.items()
        if expires_at <= now
    ]
    for token_id in expired_revocations:
        revoked_token_expirations.pop(token_id, None)

    expired_rate_keys = [
        key
        for key, record in login_rate_limits.items()
        if _aware_datetime(record.get("expires_at")) and _aware_datetime(record["expires_at"]) <= now
    ]
    for key in expired_rate_keys:
        login_rate_limits.pop(key, None)

    if len(login_rate_limits) > MAX_IN_MEMORY_AUTH_KEYS:
        oldest_keys = sorted(
            login_rate_limits,
            key=lambda key: _aware_datetime(login_rate_limits[key].get("updated_at")) or now,
        )
        for key in oldest_keys[: len(login_rate_limits) - MAX_IN_MEMORY_AUTH_KEYS]:
            login_rate_limits.pop(key, None)


def record_auth_audit_event(
    *,
    action: str,
    success: bool,
    request: Optional[Request] = None,
    user: Optional[dict] = None,
    email: Optional[str] = None,
    resource_type: str = "auth_session",
    resource_id: Optional[str] = None,
    error_message: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """Best-effort insert-only auth audit event with no sensitive payload data."""
    collection = _collection("audit_logs")
    if collection is None:
        return

    user_email = _normalize_email(email or (user or {}).get("email", "")) or None
    document = {
        "action": action,
        "action_type": "authentication",
        "user_id": _user_id(user),
        "user_email": user_email,
        "ip_address": _client_ip(request),
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
        "success": success,
        "error_message": error_message,
        "timestamp": _utcnow(),
    }
    try:
        collection.insert_one(document)
    except Exception as exc:
        logger.warning("Auth audit write failed: %s", exc.__class__.__name__)


def _load_rate_record(key: str, now: datetime) -> dict:
    collection = _collection(AUTH_RATE_LIMIT_COLLECTION)
    if collection is not None:
        try:
            return collection.find_one({"key": key}) or {}
        except Exception as exc:
            logger.warning("Auth rate-limit lookup failed: %s", exc.__class__.__name__)

    _prune_memory_auth_state(now)
    return login_rate_limits.get(key, {})


def _save_rate_record(key: str, record: dict, now: datetime) -> None:
    record["key"] = key
    record["updated_at"] = now
    locked_until = _aware_datetime(record.get("locked_until"))
    window_started_at = _aware_datetime(record.get("window_started_at")) or now
    window_expires_at = window_started_at + timedelta(seconds=RATE_LIMIT_WINDOW)
    record["expires_at"] = max(locked_until or window_expires_at, window_expires_at)

    collection = _collection(AUTH_RATE_LIMIT_COLLECTION)
    if collection is not None:
        try:
            collection.update_one({"key": key}, {"$set": record}, upsert=True)
            return
        except Exception as exc:
            logger.warning("Auth rate-limit update failed: %s", exc.__class__.__name__)

    _prune_memory_auth_state(now)
    login_rate_limits[key] = record


def _fresh_rate_record(record: dict, now: datetime) -> dict:
    window_started_at = _aware_datetime(record.get("window_started_at"))
    if not window_started_at or now >= window_started_at + timedelta(seconds=RATE_LIMIT_WINDOW):
        return {
            "window_started_at": now,
            "request_count": 0,
            "failure_count": 0,
            "locked_until": None,
        }
    return {
        "window_started_at": window_started_at,
        "request_count": int(record.get("request_count", 0)),
        "failure_count": int(record.get("failure_count", 0)),
        "locked_until": _aware_datetime(record.get("locked_until")),
    }


def check_login_rate_limit(email: str, request: Optional[Request]) -> list[str]:
    """Record a login attempt and fail closed for brute-force windows."""
    now = _utcnow()
    keys = [
        _rate_limit_key("email", _normalize_email(email)),
        _rate_limit_key("ip", _client_ip(request)),
    ]

    for key in keys:
        record = _fresh_rate_record(_load_rate_record(key, now), now)
        locked_until = _aware_datetime(record.get("locked_until"))
        if locked_until and locked_until > now:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        if int(record.get("request_count", 0)) >= RATE_LIMIT_REQUESTS:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        record["request_count"] = int(record.get("request_count", 0)) + 1
        _save_rate_record(key, record, now)

    return keys


def record_login_failure(rate_limit_keys: list[str]) -> None:
    now = _utcnow()
    for key in rate_limit_keys:
        record = _fresh_rate_record(_load_rate_record(key, now), now)
        record["failure_count"] = int(record.get("failure_count", 0)) + 1
        if record["failure_count"] >= LOGIN_FAILURE_LIMIT:
            record["locked_until"] = now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
        _save_rate_record(key, record, now)


def clear_login_failures(rate_limit_keys: list[str]) -> None:
    now = _utcnow()
    for key in rate_limit_keys:
        record = _fresh_rate_record(_load_rate_record(key, now), now)
        record["failure_count"] = 0
        record["locked_until"] = None
        _save_rate_record(key, record, now)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, stored_hash: Optional[str]) -> bool:
    """Verify password against bcrypt only."""
    if not stored_hash:
        return False

    if not stored_hash.startswith("$2"):
        return False

    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            stored_hash.encode("utf-8"),
        )
    except Exception:
        return False

# In-memory user store is only used when explicit bootstrap is enabled and the
# database is unavailable. Product deployments should provision users in MongoDB.
users_db = {}
if BOOTSTRAP_ADMIN_ENABLED and BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD:
    bootstrap_email = BOOTSTRAP_ADMIN_EMAIL.strip().lower()
    users_db[bootstrap_email] = {
        "id": "bootstrap-admin",
        "email": bootstrap_email,
        "name": "System Administrator",
        "role": "admin",
        "password_hash": hash_password(BOOTSTRAP_ADMIN_PASSWORD),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login": None,
        "is_active": True,
    }

# Local fallbacks are bounded and used only when MongoDB is unavailable.
revoked_token_expirations: dict[str, datetime] = {}
login_rate_limits: dict[str, dict[str, Any]] = {}


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email from database or in-memory store."""
    email = email.strip().lower()
    
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                user = collection.find_one({"email": email})
                if user:
                    user["id"] = str(user.get("_id", ""))
                    return user
        except Exception as e:
            logger.warning("Database lookup failed during authentication: %s", e)
    
    # Fallback to in-memory store
    return users_db.get(email)


def update_user_login(user_id: str, email: str):
    """Update user's last login timestamp."""
    email = email.strip().lower()
    
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                collection.update_one(
                    {"email": email},
                    {
                        "$set": {"last_login": datetime.now(timezone.utc)},
                        "$inc": {"login_count": 1}
                    }
                )
        except Exception as e:
            logger.warning("Database login update failed: %s", e)
    
    # Also update in-memory
    if email in users_db:
        users_db[email]["last_login"] = datetime.now(timezone.utc).isoformat()


def _expiration_from_payload(payload: dict) -> datetime:
    expires_at = _aware_datetime(payload.get("exp"))
    return expires_at or (_utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS))


def is_token_revoked(token_id: Optional[str]) -> bool:
    if not token_id:
        return False

    now = _utcnow()
    collection = _collection(REVOKED_TOKENS_COLLECTION)
    if collection is not None:
        try:
            return collection.find_one(
                {"jti": token_id, "expires_at": {"$gt": now}},
                {"_id": 1},
            ) is not None
        except Exception as exc:
            logger.warning("Token revocation lookup failed: %s", exc.__class__.__name__)

    _prune_memory_auth_state(now)
    expires_at = revoked_token_expirations.get(token_id)
    return bool(expires_at and expires_at > now)


def revoke_token(token_id: str, expires_at: datetime, payload: Optional[dict] = None) -> None:
    now = _utcnow()
    expires_at = _aware_datetime(expires_at) or (now + timedelta(hours=JWT_EXPIRATION_HOURS))
    if expires_at <= now:
        return

    document = {
        "jti": token_id,
        "user_id": (payload or {}).get("sub"),
        "user_email": (payload or {}).get("email"),
        "revoked_at": now,
        "expires_at": expires_at,
    }

    collection = _collection(REVOKED_TOKENS_COLLECTION)
    if collection is not None:
        try:
            collection.update_one({"jti": token_id}, {"$set": document}, upsert=True)
            return
        except Exception as exc:
            logger.warning("Token revocation write failed: %s", exc.__class__.__name__)

    _prune_memory_auth_state(now)
    revoked_token_expirations[token_id] = expires_at


def _object_id(value: str):
    if ObjectId is None:
        return None
    try:
        return ObjectId(value)
    except Exception:
        return None


def find_user_by_identifier(identifier: str) -> Optional[dict]:
    normalized = _normalize_email(identifier)
    if "@" in normalized:
        return get_user_by_email(normalized)

    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                queries = [{"id": identifier}]
                object_id = _object_id(identifier)
                if object_id is not None:
                    queries.insert(0, {"_id": object_id})
                for query in queries:
                    user = collection.find_one(query)
                    if user:
                        user["id"] = str(user.get("_id") or user.get("id", ""))
                        return user
        except Exception as exc:
            logger.warning("Database user lookup failed for password reset: %s", exc)

    for user in users_db.values():
        if str(user.get("id")) == identifier:
            return user
    return None


def update_user_password(identifier: str, new_hash: str) -> bool:
    user = find_user_by_identifier(identifier)
    if not user:
        return False

    email = _normalize_email(user.get("email"))
    updated = False

    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                queries = [{"email": email}]
                object_id = _object_id(identifier)
                if object_id is not None:
                    queries.insert(0, {"_id": object_id})
                for query in queries:
                    result = collection.update_one(
                        query,
                        {"$set": {"password_hash": new_hash, "password_changed_at": _utcnow()}},
                    )
                    if result.matched_count:
                        updated = True
                        break
        except Exception as exc:
            logger.warning("Database password update failed: %s", exc)

    if email in users_db:
        users_db[email]["password_hash"] = new_hash
        users_db[email]["password_changed_at"] = _utcnow().isoformat()
        updated = True

    return updated


def ensure_admin_exists():
    """Optionally create a bootstrap admin in database for first local setup."""
    if not BOOTSTRAP_ADMIN_ENABLED:
        return

    if not BOOTSTRAP_ADMIN_EMAIL or not BOOTSTRAP_ADMIN_PASSWORD:
        logger.warning("Admin bootstrap enabled but email/password are not fully configured")
        return

    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                bootstrap_email = BOOTSTRAP_ADMIN_EMAIL.strip().lower()
                admin = collection.find_one({"email": bootstrap_email})
                if not admin:
                    collection.insert_one({
                        "email": bootstrap_email,
                        "name": "System Administrator",
                        "role": "admin",
                        "password_hash": hash_password(BOOTSTRAP_ADMIN_PASSWORD),
                        "created_at": datetime.now(timezone.utc),
                        "last_login": None,
                        "is_active": True,
                        "login_count": 0,
                        "preferences": {}
                    })
                    logger.info("Created bootstrap admin user in database")
        except Exception as e:
            logger.warning("Bootstrap admin creation failed: %s", e)


# Ensure admin exists on module load
ensure_admin_exists()


def create_token(user_id: str, email: str, role: str) -> tuple:
    """Create a JWT token."""
    expiration = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    token_id = uuid.uuid4().hex
    
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "jti": token_id,
        "exp": expiration,
        "iat": datetime.now(timezone.utc)
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, expiration, token_id


def verify_token(token: str) -> Optional[dict]:
    """Verify a JWT token and return the payload."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if is_token_revoked(payload.get("jti")):
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(authorization: str = Header(None)):
    """Dependency to get current authenticated user."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Extract token from "Bearer <token>"
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication header")
    
    token = parts[1]
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user_email = payload.get("email")
    user = get_user_by_email(user_email)
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    return user


async def get_current_admin(user: dict = Depends(get_current_user)):
    """Dependency to enforce admin-only access."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.post("/login")
async def login(credentials: UserLogin, request: Request):
    """
    Authenticate user and return access token.
    
    Use email and password to authenticate.
    Returns JWT token for subsequent API calls.
    """
    email = _normalize_email(credentials.email)
    try:
        rate_limit_keys = check_login_rate_limit(email, request)
    except HTTPException:
        record_auth_audit_event(
            action="login_failure",
            success=False,
            request=request,
            email=email,
            error_message="rate_limited",
            details={"reason": "rate_limited"},
        )
        raise
    
    # Get user from database or in-memory
    user = get_user_by_email(email)
    
    if not user:
        record_login_failure(rate_limit_keys)
        record_auth_audit_event(
            action="login_failure",
            success=False,
            request=request,
            email=email,
            error_message="invalid_credentials",
            details={"reason": "invalid_credentials"},
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check if active
    if not user.get("is_active", True):
        record_login_failure(rate_limit_keys)
        record_auth_audit_event(
            action="login_failure",
            success=False,
            request=request,
            user=user,
            email=email,
            error_message="account_disabled",
            details={"reason": "account_disabled"},
        )
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    # Verify password with bcrypt only.
    if not verify_password(credentials.password, user.get("password_hash")):
        record_login_failure(rate_limit_keys)
        record_auth_audit_event(
            action="login_failure",
            success=False,
            request=request,
            user=user,
            email=email,
            error_message="invalid_credentials",
            details={"reason": "invalid_credentials"},
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Get user ID (from MongoDB _id or id field)
    user_id = user.get("id") or str(user.get("_id", "unknown"))
    
    # Create token
    token, expiration, token_id = create_token(user_id, user["email"], user.get("role", "user"))
    
    # Update last login
    update_user_login(user_id, email)
    clear_login_failures(rate_limit_keys)
    record_auth_audit_event(
        action="login_success",
        success=True,
        request=request,
        user=user,
        email=email,
        resource_id=token_id,
        details={"token_type": "bearer"},
    )
    
    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "user": {
            "id": user_id,
            "email": user["email"],
            "name": user.get("name", "User"),
            "role": user.get("role", "user")
        }
    }


@router.get("/profile")
async def get_user_profile(user: dict = Depends(get_current_user)):
    """Frontend compatibility alias for /me."""
    return await get_current_user_info(user)


@router.post("/logout")
async def logout(request: Request, authorization: str = Header(None)):
    """
    Logout user and invalidate token.
    """
    audit_user = None
    audit_email = None
    audit_success = True
    audit_error = None

    if authorization:
        parts = authorization.split()
        if len(parts) == 2:
            token = parts[1]
            try:
                payload = jwt.decode(
                    token,
                    JWT_SECRET_KEY,
                    algorithms=[JWT_ALGORITHM],
                    options={"verify_exp": False},
                )
                token_id = payload.get("jti")
                if token_id:
                    revoke_token(token_id, _expiration_from_payload(payload), payload)
                audit_email = payload.get("email")
                audit_user = get_user_by_email(audit_email) if audit_email else None
            except jwt.InvalidTokenError:
                audit_success = False
                audit_error = "invalid_token"

    record_auth_audit_event(
        action="logout",
        success=audit_success,
        request=request,
        user=audit_user,
        email=audit_email,
        error_message=audit_error,
    )
    
    return {
        "success": True,
        "message": "Logged out successfully"
    }


@router.get("/me")
async def get_current_user_info(user: dict = Depends(get_current_user)):
    """
    Get current authenticated user information.
    """
    user_id = user.get("id") or str(user.get("_id", ""))
    return {
        "success": True,
        "user": {
            "id": user_id,
            "email": user.get("email"),
            "name": user.get("name", "User"),
            "role": user.get("role", "user"),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login")
        }
    }


@router.post("/register")
async def register_user(
    user_data: UserCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
):
    """
    Register a new user (admin only).
    """
    email = _normalize_email(user_data.email)
    
    # Check if user exists
    existing = get_user_by_email(email)
    if existing:
        record_auth_audit_event(
            action="register_user",
            success=False,
            request=request,
            user=current_user,
            email=email,
            resource_type="user",
            error_message="user_already_exists",
            details={"role": user_data.role},
        )
        raise HTTPException(status_code=400, detail="User already exists")
    
    new_user = {
        "email": email,
        "name": user_data.name,
        "role": user_data.role,
        "password_hash": hash_password(user_data.password),
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
        "is_active": True,
        "login_count": 0,
        "preferences": {}
    }
    
    # Save to database
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                result = collection.insert_one(new_user)
                new_user["id"] = str(result.inserted_id)
        except Exception as e:
            logger.warning("Database insert failed while registering user: %s", e)
            new_user["id"] = f"user-{len(users_db) + 1:03d}"
    else:
        new_user["id"] = f"user-{len(users_db) + 1:03d}"
    
    # Also add to in-memory store
    users_db[email] = new_user
    record_auth_audit_event(
        action="register_user",
        success=True,
        request=request,
        user=current_user,
        email=email,
        resource_type="user",
        resource_id=new_user.get("id"),
        details={"role": new_user["role"]},
    )
    
    return {
        "success": True,
        "message": "User registered successfully",
        "user": {
            "id": new_user.get("id"),
            "email": new_user["email"],
            "name": new_user["name"],
            "role": new_user["role"]
        }
    }


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    user: dict = Depends(get_current_user)
):
    """
    Change current user's password.
    """
    # Verify current password
    if not verify_password(payload.current_password, user.get("password_hash")):
        record_auth_audit_event(
            action="change_password",
            success=False,
            request=request,
            user=user,
            resource_type="user_password",
            resource_id=_user_id(user),
            error_message="current_password_incorrect",
        )
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    new_hash = hash_password(payload.new_password)
    email = user.get("email", "").lower()
    
    # Update in database
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                collection.update_one(
                    {"email": email},
                    {"$set": {"password_hash": new_hash}}
                )
        except Exception as e:
            logger.warning("Database password update failed: %s", e)
    
    # Update in-memory store
    if email in users_db:
        users_db[email]["password_hash"] = new_hash
        users_db[email]["password_changed_at"] = _utcnow().isoformat()

    record_auth_audit_event(
        action="change_password",
        success=True,
        request=request,
        user=user,
        resource_type="user_password",
        resource_id=_user_id(user),
    )
    
    return {
        "success": True,
        "message": "Password changed successfully"
    }


@router.post("/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    payload: AdminResetPasswordRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
):
    """
    Reset a user's password as an administrator.
    """
    target_user = find_user_by_identifier(user_id)
    if not target_user:
        record_auth_audit_event(
            action="admin_reset_password",
            success=False,
            request=request,
            user=current_user,
            resource_type="user_password",
            resource_id=user_id,
            error_message="user_not_found",
        )
        raise HTTPException(status_code=404, detail="User not found")

    new_hash = hash_password(payload.new_password)
    if not update_user_password(user_id, new_hash):
        record_auth_audit_event(
            action="admin_reset_password",
            success=False,
            request=request,
            user=current_user,
            resource_type="user_password",
            resource_id=user_id,
            error_message="password_update_failed",
        )
        raise HTTPException(status_code=500, detail="Password reset failed")

    record_auth_audit_event(
        action="admin_reset_password",
        success=True,
        request=request,
        user=current_user,
        resource_type="user_password",
        resource_id=_user_id(target_user) or user_id,
        details={"target_email": _normalize_email(target_user.get("email"))},
    )

    return {
        "success": True,
        "message": "Password reset successfully",
        "user": {
            "id": _user_id(target_user) or user_id,
            "email": target_user.get("email"),
        },
    }


@router.post("/validate-token")
async def validate_token(authorization: str = Header(None)):
    """
    Validate a JWT token.
    """
    if not authorization:
        return {"valid": False, "reason": "No token provided"}
    
    parts = authorization.split()
    if len(parts) != 2:
        return {"valid": False, "reason": "Invalid header format"}
    
    token = parts[1]
    payload = verify_token(token)
    
    if not payload:
        return {"valid": False, "reason": "Invalid or expired token"}
    
    return {
        "valid": True,
        "user_id": payload.get("sub"),
        "email": payload.get("email"),
        "role": payload.get("role"),
        "jti": payload.get("jti"),
        "expires": payload.get("exp")
    }


@router.post("/verify")
async def verify_token_alias(authorization: str = Header(None)):
    """Frontend compatibility alias for /validate-token."""
    return await validate_token(authorization)


@router.get("/users")
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_admin)
):
    """
    List all users (admin only).
    """
    users_list = []
    
    # Try database first
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("users")
            if collection is not None:
                cursor = collection.find({}, {"password_hash": 0}).skip(skip).limit(limit)
                for user in cursor:
                    users_list.append({
                        "id": str(user.get("_id", "")),
                        "email": user.get("email"),
                        "name": user.get("name", "User"),
                        "role": user.get("role", "user"),
                        "is_active": user.get("is_active", True),
                        "created_at": user.get("created_at"),
                        "last_login": user.get("last_login")
                    })
                total = collection.count_documents({})
                return {"success": True, "users": users_list, "count": len(users_list), "total": total}
        except Exception as e:
            logger.warning("Database user listing failed: %s", e)
    
    # Fallback to in-memory
    for email, user in users_db.items():
        users_list.append({
            "id": user.get("id"),
            "email": user["email"],
            "name": user.get("name", "User"),
            "role": user.get("role", "user"),
            "is_active": user.get("is_active", True),
            "created_at": user["created_at"],
            "last_login": user["last_login"]
        })
    
    return {
        "success": True,
        "users": users_list[skip:skip + limit],
        "count": len(users_list[skip:skip + limit]),
        "total": len(users_list)
    }

