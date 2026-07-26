"""
Authentication API Routes
==========================
API endpoints for user authentication and authorization.
Uses MongoDB database with fallback to in-memory storage.
"""

import hashlib
import logging
import uuid
import jwt
import bcrypt
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel

# Define models locally to avoid import issues
class UserLogin(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    email: str
    name: str
    password: str
    role: str = "user"

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

# Import settings. Authentication must fail closed if configuration is broken.
from config.settings import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    BOOTSTRAP_ADMIN_ENABLED,
    BOOTSTRAP_ADMIN_EMAIL,
    BOOTSTRAP_ADMIN_PASSWORD,
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


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def _legacy_hash_password(password: str) -> str:
    """Legacy SHA-256 hash (kept only for backward compatibility)."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, stored_hash: Optional[str]) -> bool:
    """Verify password against bcrypt hash with legacy SHA-256 fallback."""
    if not stored_hash:
        return False

    # bcrypt hashes start with $2a$, $2b$, or $2y$
    if stored_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                stored_hash.encode("utf-8"),
            )
        except Exception:
            return False

    return _legacy_hash_password(plain_password) == stored_hash

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

# Active tokens store
active_tokens = {}
revoked_token_ids = set()


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
        if payload.get("jti") in revoked_token_ids:
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
async def login(credentials: UserLogin):
    """
    Authenticate user and return access token.
    
    Use email and password to authenticate.
    Returns JWT token for subsequent API calls.
    """
    email = credentials.email.strip().lower()
    
    # Get user from database or in-memory
    user = get_user_by_email(email)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check if active
    if not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    # Verify password (bcrypt with legacy fallback)
    if not verify_password(credentials.password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Get user ID (from MongoDB _id or id field)
    user_id = user.get("id") or str(user.get("_id", "unknown"))
    
    # Create token
    token, expiration, token_id = create_token(user_id, user["email"], user.get("role", "user"))
    
    # Store active token
    active_tokens[token_id] = {
        "user_id": user_id,
        "email": user["email"],
        "expires": expiration.isoformat()
    }
    
    # Update last login
    update_user_login(user_id, email)
    
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
async def logout(authorization: str = Header(None)):
    """
    Logout user and invalidate token.
    """
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
                    revoked_token_ids.add(token_id)
                    active_tokens.pop(token_id, None)
            except jwt.InvalidTokenError:
                pass
    
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
async def register_user(user_data: UserCreate, current_user: dict = Depends(get_current_user)):
    """
    Register a new user (admin only).
    """
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    email = user_data.email.lower()
    
    # Check if user exists
    existing = get_user_by_email(email)
    if existing:
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
    request: ChangePasswordRequest,
    user: dict = Depends(get_current_user)
):
    """
    Change current user's password.
    """
    # Verify current password
    if not verify_password(request.current_password, user.get("password_hash")):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    new_hash = hash_password(request.new_password)
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
    
    return {
        "success": True,
        "message": "Password changed successfully"
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
    current_user: dict = Depends(get_current_user)
):
    """
    List all users (admin only).
    """
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
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

