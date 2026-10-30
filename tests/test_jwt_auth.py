import time

import jwt
import pytest
from fastapi import HTTPException

from api.auth import UserPrincipal, _decode_token, create_token

_SECRET = "a" * 32
_PRINCIPAL = UserPrincipal(id="42", username="alice", role="analyst")


@pytest.fixture(autouse=True)
def _jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", _SECRET)


def test_token_round_trip():
    """A token we issue must decode back to the same principal."""
    assert _decode_token(create_token(_PRINCIPAL)) == _PRINCIPAL


def test_short_secret_rejected(monkeypatch):
    """Secrets under 32 bytes must be refused, not silently used."""
    monkeypatch.setenv("JWT_SECRET", "a" * 31)
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        create_token(_PRINCIPAL)


def test_missing_secret_rejected(monkeypatch):
    """An unset secret must be refused."""
    monkeypatch.delenv("JWT_SECRET")
    with pytest.raises(RuntimeError, match="must be set"):
        create_token(_PRINCIPAL)


def test_wrong_secret_rejected():
    """A token signed with a different key must not verify."""
    token = jwt.encode({"sub": "42", "username": "alice", "role": "admin"}, "b" * 32, algorithm="HS256")
    with pytest.raises(HTTPException) as exc:
        _decode_token(token)
    assert exc.value.status_code == 401


def test_expired_token_rejected():
    """A token past its exp must not verify."""
    now = int(time.time())
    token = jwt.encode(
        {"sub": "42", "username": "alice", "role": "analyst", "iat": now - 120, "exp": now - 60},
        _SECRET,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        _decode_token(token)
    assert exc.value.status_code == 401


def test_alg_none_rejected():
    """An unsigned token (alg=none) must not be accepted."""
    token = jwt.encode({"sub": "42", "username": "alice", "role": "admin"}, None, algorithm="none")
    with pytest.raises(HTTPException) as exc:
        _decode_token(token)
    assert exc.value.status_code == 401


def test_missing_claims_rejected():
    """A validly signed token without the expected claims is malformed."""
    token = jwt.encode({"sub": "42", "exp": int(time.time()) + 60}, _SECRET, algorithm="HS256")
    with pytest.raises(HTTPException) as exc:
        _decode_token(token)
    assert exc.value.detail == "Malformed token claims"
