import hashlib
import hmac
import os
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import bcrypt as _bcrypt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"


# Track .env.local mtime so we reload env vars whenever the file changes.
# This means rotating JWT_SECRET immediately invalidates all live sessions.
_ENV_FILE = Path(".env.local")
_env_mtime: float = 0.0


def _reload_env_if_changed() -> None:
    """Re-read .env.local into os.environ when the file has been modified."""
    global _env_mtime
    if not _ENV_FILE.exists():
        return
    mtime = _ENV_FILE.stat().st_mtime
    if mtime != _env_mtime:
        load_dotenv(dotenv_path=_ENV_FILE, override=True)
        _env_mtime = mtime
        logger.info(".env.local changed — env reloaded")

_bearer = HTTPBearer(auto_error=False)
_api_key_validator: Optional[Callable[[str], Optional["UserPrincipal"]]] = None


def _prehash(plain: str) -> bytes:
    """SHA-256 pre-hash → 32 bytes, always under bcrypt's 72-byte limit."""
    return hashlib.sha256(plain.encode("utf-8")).digest()


def hash_api_key(raw_key: str) -> str:
    """Returns 'salt_hex:sha256(salt_bytes + key_bytes)' for DB storage.
    Each call produces a different stored value due to fresh random salt.
    """
    salt = secrets.token_bytes(32)
    digest = hashlib.sha256(salt + (raw_key or "").encode("utf-8")).hexdigest()
    return f"{salt.hex()}:{digest}"


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Constant-time verification against a stored hash.
    Handles both legacy (unsalted SHA-256) and current (salted) formats.
    """
    if ":" not in stored_hash:
        # Legacy path: key was stored before salting was introduced
        legacy = hashlib.sha256((raw_key or "").encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, stored_hash)
    salt_hex, expected_digest = stored_hash.split(":", 1)
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    actual = hashlib.sha256(salt + (raw_key or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual, expected_digest)


@dataclass
class UserPrincipal:
    id: str
    username: str
    role: str  # "admin" | "analyst"

_BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(_prehash(plain), _bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison — safe against timing attacks."""
    return _bcrypt.checkpw(_prehash(plain), hashed.encode("utf-8"))


def _jwt_secret() -> str:
    _reload_env_if_changed()
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET env var must be set")
    return secret


def create_token(principal: UserPrincipal) -> str:
    # exp must be an integer Unix timestamp — passing a datetime can produce
    # a float in some python-jose versions, which breaks standard JWT decoders.
    # Read expiry at call time so .env.local changes take effect on next login.
    expire_minutes = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    now = int(time.time())
    payload = {
        "sub": principal.id,
        "username": principal.username,
        "role": principal.role,
        "iat": now,
        "exp": now + (expire_minutes * 60),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=_ALGORITHM)


def _decode_token(token: str) -> UserPrincipal:
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=[_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc

    sub = payload.get("sub")
    username = payload.get("username")
    role = payload.get("role")
    if not sub or not username or not role:
        raise HTTPException(status_code=401, detail="Malformed token claims")

    return UserPrincipal(id=sub, username=username, role=role)


def set_api_key_validator(validator: Callable[[str], Optional[UserPrincipal]]) -> None:
    global _api_key_validator
    _api_key_validator = validator


def require_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer),
) -> UserPrincipal:
    """Dependency: any authenticated user."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = (credentials.credentials or "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # JWT auth path
    if token.count(".") == 2:
        try:
            return _decode_token(token)
        except HTTPException:
            # Fall through to API key check so "Bearer <api-key>" works.
            pass

    # API key auth path
    if _api_key_validator is not None:
        principal = _api_key_validator(token)
        if principal is not None:
            return principal

    raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_admin(principal: UserPrincipal = Depends(require_user)) -> UserPrincipal:
    """Dependency: authenticated user with admin role."""
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return principal
