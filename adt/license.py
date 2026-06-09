"""License key validation for Agent Debug Toolkit Pro features.

License keys use HMAC-SHA256 signing. Format: email:expiry_date:signature_hex
"""

import hashlib
import hmac
import time
from typing import NamedTuple


class LicenseInfo(NamedTuple):
    email: str
    expiry: float  # Unix timestamp
    valid: bool
    reason: str


class LicenseManager:
    """Manages license key generation and validation."""

    # Secret key for HMAC — in production this would be stored securely
    SECRET_KEY = b"adt-pro-secret-key-v1-2024"

    @staticmethod
    def generate(email: str, days: int = 365) -> str:
        """Generate a license key for testing."""
        expiry = time.time() + days * 86400
        msg = f"{email}:{int(expiry)}".encode("utf-8")
        sig = hmac.new(LicenseManager.SECRET_KEY, msg, hashlib.sha256).hexdigest()[:16]
        return f"{email}:{int(expiry)}:{sig}"

    @staticmethod
    def validate(key: str) -> LicenseInfo:
        """Validate a license key and return license info."""
        try:
            parts = key.strip().split(":")
            if len(parts) != 3:
                return LicenseInfo("", 0, False, "Invalid license key format")

            email, expiry_str, sig = parts
            expiry = float(expiry_str)

            # Verify signature
            msg = f"{email}:{int(expiry)}".encode("utf-8")
            expected_sig = hmac.new(
                LicenseManager.SECRET_KEY, msg, hashlib.sha256
            ).hexdigest()[:16]

            if not hmac.compare_digest(sig, expected_sig):
                return LicenseInfo(email, expiry, False, "Invalid signature")

            # Check expiry
            if time.time() > expiry:
                return LicenseInfo(email, expiry, False, "License expired")

            return LicenseInfo(email, expiry, True, "Valid")

        except (ValueError, IndexError, TypeError):
            return LicenseInfo("", 0, False, "Malformed license key")
