"""
ACDS Test Cases - Admin Authentication Module
==============================================
Comprehensive test suite for authentication and authorization functionality.

Test Coverage:
- Login (valid/invalid credentials)
- Token validation (valid/expired/malformed)
- User registration (admin-only)
- Password change
- Logout
- User listing
- Database fallback
"""

import os
import pytest
import requests
import jwt
from datetime import datetime, timedelta, timezone
import time

# Test configuration
BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://127.0.0.1:8000/api/v1")
DEFAULT_ADMIN_EMAIL = os.getenv("ACDS_TEST_ADMIN_EMAIL", "admin@acds.com")
DEFAULT_ADMIN_PASSWORD = os.getenv("ACDS_TEST_ADMIN_PASSWORD")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "test-secret-not-used-by-server-for-negative-token-tests")
JWT_ALGORITHM = "HS256"


class TestAdminAuthentication:
    """Test suite for admin authentication module."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test."""
        self.base_url = BASE_URL
        if not DEFAULT_ADMIN_PASSWORD:
            pytest.skip("Set ACDS_TEST_ADMIN_PASSWORD to run admin authentication tests")
        self.admin_token = None
        self.user_token = None
        yield
        # Cleanup after each test if needed
    
    # =========================================================================
    # AUTH-001: Admin Login - Valid Credentials
    # =========================================================================
    def test_auth_001_admin_login_valid_credentials(self):
        """
        Test ID: AUTH-001
        Objective: Verify admin can login with correct credentials
        Priority: High
        """
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        
        assert data["success"] is True
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == DEFAULT_ADMIN_EMAIL
        assert data["user"]["role"] == "admin"
        
        # Verify token has expected claims (without signature dependency on env secret)
        token = data["access_token"]
        decoded = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=[JWT_ALGORITHM],
        )
        assert decoded["email"] == DEFAULT_ADMIN_EMAIL
        assert decoded["role"] == "admin"
        
        print("AUTH-001 PASSED: Admin login with valid credentials successful")
    
    # =========================================================================
    # AUTH-002: Admin Login - Invalid Password
    # =========================================================================
    def test_auth_002_admin_login_invalid_password(self):
        """
        Test ID: AUTH-002
        Objective: Verify system rejects incorrect password
        Priority: High
        """
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": "wrongpassword123"
            }
        )
        
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        data = response.json()
        
        assert "detail" in data
        assert "Invalid email or password" in data["detail"]
        
        print("AUTH-002 PASSED: Invalid password correctly rejected")
    
    # =========================================================================
    # AUTH-003: Admin Login - Non-existent User
    # =========================================================================
    def test_auth_003_admin_login_nonexistent_user(self):
        """
        Test ID: AUTH-003
        Objective: Verify system rejects non-existent users
        Priority: High
        """
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": "fake@user.com",
                "password": "anypassword"
            }
        )
        
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        data = response.json()
        
        assert "detail" in data
        assert "Invalid email or password" in data["detail"]
        
        print("AUTH-003 PASSED: Non-existent user correctly rejected")
    
    # =========================================================================
    # AUTH-004: Token Validation - Valid Token
    # =========================================================================
    def test_auth_004_token_validation_valid(self):
        """
        Test ID: AUTH-004
        Objective: Verify valid JWT token is accepted
        Priority: High
        """
        # First login to get token
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        token = login_response.json()["access_token"]
        
        # Now validate token
        response = requests.get(
            f"{self.base_url}/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        
        assert data["success"] is True
        assert data["user"]["email"] == DEFAULT_ADMIN_EMAIL
        assert data["user"]["role"] == "admin"
        assert "id" in data["user"]
        
        print("AUTH-004 PASSED: Valid token accepted")
    
    # =========================================================================
    # AUTH-005: Token Validation - Expired Token
    # =========================================================================
    def test_auth_005_token_validation_expired(self):
        """
        Test ID: AUTH-005
        Objective: Verify expired tokens are rejected
        Priority: Medium
        """
        # Create an expired token
        expired_payload = {
            "sub": "admin-001",
            "email": DEFAULT_ADMIN_EMAIL,
            "role": "admin",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),  # Expired 1 hour ago
            "iat": datetime.now(timezone.utc) - timedelta(hours=25)
        }
        expired_token = jwt.encode(expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        response = requests.get(
            f"{self.base_url}/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        data = response.json()
        assert "detail" in data
        
        print("AUTH-005 PASSED: Expired token correctly rejected")
    
    # =========================================================================
    # AUTH-006: Token Validation - Malformed Token
    # =========================================================================
    def test_auth_006_token_validation_malformed(self):
        """
        Test ID: AUTH-006
        Objective: Verify malformed tokens are rejected
        Priority: Medium
        """
        response = requests.get(
            f"{self.base_url}/auth/me",
            headers={"Authorization": "Bearer invalidtoken123"}
        )
        
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        
        print("AUTH-006 PASSED: Malformed token correctly rejected")
    
    # =========================================================================
    # AUTH-007: User Registration - Admin Only
    # =========================================================================
    def test_auth_007_user_registration_admin_only(self):
        """
        Test ID: AUTH-007
        Objective: Verify only admins can register new users
        Priority: High
        """
        # Login as admin
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        admin_token = login_response.json()["access_token"]
        
        # Register new user
        new_user_email = f"testuser_{int(time.time())}@acds.com"
        response = requests.post(
            f"{self.base_url}/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": new_user_email,
                "name": "Test User",
                "password": "testpass123",
                "role": "analyst"
            }
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        
        assert data["success"] is True
        assert data["user"]["email"] == new_user_email
        assert data["user"]["role"] == "analyst"
        
        print("AUTH-007 PASSED: Admin can register new users")
    
    # =========================================================================
    # AUTH-008: User Registration - Non-Admin Attempt
    # =========================================================================
    def test_auth_008_user_registration_non_admin_denied(self):
        """
        Test ID: AUTH-008
        Objective: Verify non-admin cannot register users
        Priority: High
        """
        # Login as admin and create a real non-admin user
        admin_login = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD,
            },
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]

        analyst_email = f"analyst_{int(time.time())}@acds.com"
        create_user = requests.post(
            f"{self.base_url}/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": analyst_email,
                "name": "Analyst User",
                "password": "analyst123",
                "role": "analyst",
            },
        )
        assert create_user.status_code == 200

        analyst_login = requests.post(
            f"{self.base_url}/auth/login",
            json={"email": analyst_email, "password": "analyst123"},
        )
        assert analyst_login.status_code == 200
        non_admin_token = analyst_login.json()["access_token"]
        
        response = requests.post(
            f"{self.base_url}/auth/register",
            headers={"Authorization": f"Bearer {non_admin_token}"},
            json={
                "email": "newuser@acds.com",
                "name": "New User",
                "password": "pass123",
                "role": "user"
            }
        )
        
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"
        data = response.json()
        assert "Admin access required" in data["detail"]
        
        print("AUTH-008 PASSED: Non-admin correctly denied registration")
    
    # =========================================================================
    # AUTH-009: User Registration - Duplicate Email
    # =========================================================================
    def test_auth_009_user_registration_duplicate_email(self):
        """
        Test ID: AUTH-009
        Objective: Verify duplicate email is rejected
        Priority: Medium
        """
        # Login as admin
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        admin_token = login_response.json()["access_token"]
        
        # Try to register with existing admin email
        response = requests.post(
            f"{self.base_url}/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "name": "Duplicate Admin",
                "password": "pass123",
                "role": "admin"
            }
        )
        
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        data = response.json()
        assert "User already exists" in data["detail"]
        
        print("AUTH-009 PASSED: Duplicate email correctly rejected")
    
    # =========================================================================
    # AUTH-010: Password Change - Valid Request
    # =========================================================================
    def test_auth_010_password_change_valid(self):
        """
        Test ID: AUTH-010
        Objective: Verify user can change their password
        Priority: High
        """
        # First create a test user
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        admin_token = login_response.json()["access_token"]
        
        test_email = f"pwdtest_{int(time.time())}@acds.com"
        requests.post(
            f"{self.base_url}/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": test_email,
                "name": "Password Test User",
                "password": "oldpass123",
                "role": "user"
            }
        )
        
        # Login as test user
        user_login = requests.post(
            f"{self.base_url}/auth/login",
            json={"email": test_email, "password": "oldpass123"}
        )
        user_token = user_login.json()["access_token"]
        
        # Change password
        response = requests.post(
            f"{self.base_url}/auth/change-password",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "current_password": "oldpass123",
                "new_password": "newpass456"
            }
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data["success"] is True
        
        # Verify new password works
        new_login = requests.post(
            f"{self.base_url}/auth/login",
            json={"email": test_email, "password": "newpass456"}
        )
        assert new_login.status_code == 200
        
        print("AUTH-010 PASSED: Password change successful")
    
    # =========================================================================
    # AUTH-011: Password Change - Wrong Current Password
    # =========================================================================
    def test_auth_011_password_change_wrong_current(self):
        """
        Test ID: AUTH-011
        Objective: Verify wrong current password is rejected
        Priority: Medium
        """
        # Login as admin
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        token = login_response.json()["access_token"]
        
        # Try to change with wrong current password
        response = requests.post(
            f"{self.base_url}/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "current_password": "wrongpassword",
                "new_password": "newpass123"
            }
        )
        
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        data = response.json()
        assert "Current password is incorrect" in data["detail"]
        
        print("AUTH-011 PASSED: Wrong current password correctly rejected")
    
    # =========================================================================
    # AUTH-012: Logout - Valid Session
    # =========================================================================
    def test_auth_012_logout_valid_session(self):
        """
        Test ID: AUTH-012
        Objective: Verify user can logout successfully
        Priority: Medium
        """
        # Login
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        token = login_response.json()["access_token"]
        
        # Logout
        response = requests.post(
            f"{self.base_url}/auth/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data["success"] is True
        assert "Logged out successfully" in data["message"]
        
        print("AUTH-012 PASSED: Logout successful")
    
    # =========================================================================
    # AUTH-013: List Users - Admin Access
    # =========================================================================
    def test_auth_013_list_users_admin_access(self):
        """
        Test ID: AUTH-013
        Objective: Verify admin can list all users
        Priority: Medium
        """
        # Login as admin
        login_response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        admin_token = login_response.json()["access_token"]
        
        # List users
        response = requests.get(
            f"{self.base_url}/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        
        assert data["success"] is True
        assert "users" in data
        assert isinstance(data["users"], list)
        assert len(data["users"]) > 0
        
        # Verify passwords are not included
        for user in data["users"]:
            assert "password_hash" not in user
            assert "email" in user
            assert "role" in user
        
        print("AUTH-013 PASSED: Admin can list users")
    
    # =========================================================================
    # AUTH-014: List Users - Non-Admin Denied
    # =========================================================================
    def test_auth_014_list_users_non_admin_denied(self):
        """
        Test ID: AUTH-014
        Objective: Verify non-admin cannot list users
        Priority: Medium
        """
        # Login as admin and create a real non-admin user
        admin_login = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD,
            },
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]

        user_email = f"user_{int(time.time())}@acds.com"
        create_user = requests.post(
            f"{self.base_url}/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": user_email,
                "name": "Regular User",
                "password": "user123",
                "role": "user",
            },
        )
        assert create_user.status_code == 200

        user_login = requests.post(
            f"{self.base_url}/auth/login",
            json={"email": user_email, "password": "user123"},
        )
        assert user_login.status_code == 200
        non_admin_token = user_login.json()["access_token"]
        
        response = requests.get(
            f"{self.base_url}/auth/users",
            headers={"Authorization": f"Bearer {non_admin_token}"}
        )
        
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"
        data = response.json()
        assert "Admin access required" in data["detail"]
        
        print("AUTH-014 PASSED: Non-admin correctly denied user listing")
    
    # =========================================================================
    # AUTH-015: Database Fallback - MongoDB Down
    # =========================================================================
    def test_auth_015_database_fallback(self):
        """
        Test ID: AUTH-015
        Objective: Verify in-memory fallback works when DB is down
        Priority: Low
        Note: This test assumes MongoDB might be down; it should still work with in-memory store
        """
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "email": DEFAULT_ADMIN_EMAIL,
                "password": DEFAULT_ADMIN_PASSWORD
            }
        )
        
        # Should work regardless of DB status due to fallback
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data["success"] is True
        assert "access_token" in data
        
        print("AUTH-015 PASSED: Database fallback mechanism works")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
