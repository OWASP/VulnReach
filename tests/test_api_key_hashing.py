from api.auth import hash_api_key, verify_api_key


def test_hash_api_key_includes_salt():
    """Stored hash must contain salt separator."""
    stored = hash_api_key("vrk_ab12.testsecret")
    assert ":" in stored
    salt_hex, _ = stored.split(":", 1)
    assert len(salt_hex) == 64  # 32 bytes = 64 hex chars


def test_hash_api_key_different_each_call():
    """Same key hashed twice must produce different stored values (random salt)."""
    key = "vrk_ab12.testsecret"
    assert hash_api_key(key) != hash_api_key(key)


def test_verify_api_key_correct():
    """Correct key must verify against its stored hash."""
    key = "vrk_ab12.testsecret"
    stored = hash_api_key(key)
    assert verify_api_key(key, stored) is True


def test_verify_api_key_wrong_key():
    """Wrong key must not verify."""
    stored = hash_api_key("vrk_ab12.correct")
    assert verify_api_key("vrk_ab12.wrong", stored) is False


def test_verify_api_key_empty_key():
    """Empty key must not verify against a real key's hash."""
    stored = hash_api_key("vrk_ab12.testsecret")
    assert verify_api_key("", stored) is False


def test_verify_api_key_legacy_format():
    """Legacy unsalted hash (no colon) must still verify via SHA-256 fallback."""
    import hashlib
    raw_key = "vrk_ab12.legacysecret"
    legacy_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    # Legacy hash has no colon — verify must use old SHA-256 path
    assert verify_api_key(raw_key, legacy_hash) is True


def test_verify_api_key_legacy_wrong_key():
    """Wrong key against a legacy hash must not verify."""
    import hashlib
    legacy_hash = hashlib.sha256(b"vrk_ab12.correct")
    assert verify_api_key("vrk_ab12.wrong", legacy_hash.hexdigest()) is False


def test_verify_api_key_malformed_hash():
    """Malformed salt in stored hash must return False, not raise."""
    assert verify_api_key("vrk_ab12.key", "notvalidhex:abc123") is False
