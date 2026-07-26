"""
Authentication Service for ACDS Backend
Handles admin login, JWT token generation, and validation
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
import hashlib
import secrets
import json
from config.settings import (
    JWT_SECRET_KEY,
    BOOTSTRAP_ADMIN_ENABLED,
    BOOTSTRAP_ADMIN_EMAIL,
    BOOTSTRAP_ADMIN_PASSWORD,
)


@dataclass
class User:
    id: int
    email: str
    name: str
    role: str
    password_hash: str


@dataclass
class TokenPayload:
    user_id: int
    email: str
    role: str
    exp: datetime


class AuthService:
    """
    Authentication service for admin portal.
    Handles user authentication, token generation, and validation.
    """

    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or JWT_SECRET_KEY
        self.token_expiry_hours = 24

        # Compatibility-only in-memory user store. The production auth route uses
        # MongoDB users; this service does not create credentials unless explicit
        # bootstrap variables are enabled for local setup.
        self.users: Dict[str, User] = {}
        if BOOTSTRAP_ADMIN_ENABLED and BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD:
            admin_email = BOOTSTRAP_ADMIN_EMAIL.strip().lower()
            self.users[admin_email] = User(
                id=1,
                email=admin_email,
                name="Admin User",
                role="admin",
                password_hash=self._hash_password(BOOTSTRAP_ADMIN_PASSWORD),
            )
        
        # Active tokens store (replace with Redis in production)
        self.active_tokens: Dict[str, TokenPayload] = {}

    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256."""
        return hashlib.sha256(
            (password + self.secret_key).encode()
        ).hexdigest()

    def _generate_token(self) -> str:
        """Generate a secure random token."""
        return secrets.token_urlsafe(32)

    def authenticate(self, email: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user with email and password.
        
        Args:
            email: User's email address
            password: User's password
            
        Returns:
            Dictionary with success status, token, and user info
        """
        user = self.users.get(email)
        
        if not user:
            return {
                "success": False,
                "error": "Invalid email or password"
            }

        if user.password_hash != self._hash_password(password):
            return {
                "success": False,
                "error": "Invalid email or password"
            }

        # Generate token
        token = self._generate_token()
        expiry = datetime.now() + timedelta(hours=self.token_expiry_hours)
        
        # Store token
        self.active_tokens[token] = TokenPayload(
            user_id=user.id,
            email=user.email,
            role=user.role,
            exp=expiry
        )

        return {
            "success": True,
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role
            },
            "expires_at": expiry.isoformat()
        }

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT token.
        
        Args:
            token: The token to validate
            
        Returns:
            Dictionary with validation status and user info
        """
        payload = self.active_tokens.get(token)
        
        if not payload:
            return {
                "valid": False,
                "error": "Invalid token"
            }

        if datetime.now() > payload.exp:
            # Token expired, remove it
            del self.active_tokens[token]
            return {
                "valid": False,
                "error": "Token expired"
            }

        user = self.users.get(payload.email)
        
        return {
            "valid": True,
            "user": {
                "id": payload.user_id,
                "email": payload.email,
                "role": payload.role,
                "name": user.name if user else "Unknown"
            }
        }

    def logout(self, token: str) -> Dict[str, Any]:
        """
        Invalidate a token (logout).
        
        Args:
            token: The token to invalidate
            
        Returns:
            Dictionary with logout status
        """
        if token in self.active_tokens:
            del self.active_tokens[token]
            return {"success": True, "message": "Logged out successfully"}
        
        return {"success": True, "message": "Token not found or already expired"}

    def create_user(
        self,
        email: str,
        password: str,
        name: str,
        role: str = "analyst"
    ) -> Dict[str, Any]:
        """
        Create a new user (admin only).
        
        Args:
            email: User's email address
            password: User's password
            name: User's display name
            role: User's role (admin, analyst)
            
        Returns:
            Dictionary with creation status
        """
        if email in self.users:
            return {
                "success": False,
                "error": "User already exists"
            }

        new_id = max((u.id for u in self.users.values()), default=0) + 1
        
        self.users[email] = User(
            id=new_id,
            email=email,
            name=name,
            role=role,
            password_hash=self._hash_password(password)
        )

        return {
            "success": True,
            "user": {
                "id": new_id,
                "email": email,
                "name": name,
                "role": role
            }
        }

    def change_password(
        self,
        email: str,
        old_password: str,
        new_password: str
    ) -> Dict[str, Any]:
        """
        Change user's password.
        
        Args:
            email: User's email address
            old_password: Current password
            new_password: New password
            
        Returns:
            Dictionary with change status
        """
        user = self.users.get(email)
        
        if not user:
            return {"success": False, "error": "User not found"}

        if user.password_hash != self._hash_password(old_password):
            return {"success": False, "error": "Invalid current password"}

        user.password_hash = self._hash_password(new_password)
        
        return {"success": True, "message": "Password changed successfully"}


# Singleton instance
auth_service = AuthService()


# Example usage
if __name__ == "__main__":
    if not auth_service.users:
        raise SystemExit("Set BOOTSTRAP_ADMIN_ENABLED=true with bootstrap credentials to test AuthService locally.")

    admin_user = next(iter(auth_service.users.values()))
    result = auth_service.authenticate(
        admin_user.email,
        BOOTSTRAP_ADMIN_PASSWORD,
    )
    print("Login result:", json.dumps(result, indent=2, default=str))
    
    if result["success"]:
        token = result["token"]
        
        # Validate token
        validation = auth_service.validate_token(token)
        print("\nToken validation:", json.dumps(validation, indent=2))
        
        # Logout
        logout_result = auth_service.logout(token)
        print("\nLogout result:", json.dumps(logout_result, indent=2))
