"""Shared password policy for account creation and password changes."""

import re

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
PASSWORD_COMPLEXITY_MESSAGE = (
    "Password must be 12-128 characters and include uppercase, lowercase, "
    "number, and special character."
)


def validate_password_complexity(password: str) -> str:
    """Validate product password policy for new passwords."""
    if not isinstance(password, str):
        raise ValueError(PASSWORD_COMPLEXITY_MESSAGE)
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        raise ValueError(PASSWORD_COMPLEXITY_MESSAGE)
    checks = (
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"\d", password),
        re.search(r"[^A-Za-z0-9]", password),
    )
    if not all(checks):
        raise ValueError(PASSWORD_COMPLEXITY_MESSAGE)
    return password
