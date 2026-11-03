from pwdlib import PasswordHash

MAX_PASSWORD_BYTES = 1024

# Use pwdlib's recommended Argon2id configuration.
_password_hasher = PasswordHash.recommended()


def _validate_password(password: str) -> None:
    """Validate password type, non-empty value and byte length."""

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password must not be empty.")

    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Password contains invalid Unicode.") from exc

    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password exceeds {MAX_PASSWORD_BYTES} UTF-8 bytes."
        )


def hash_password(password: str) -> str:
    """Return a salted Argon2id password hash."""

    _validate_password(password)
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a candidate password against its stored hash."""

    _validate_password(password)

    if not isinstance(password_hash, str) or not password_hash:
        raise ValueError("A valid password hash is required.")

    return _password_hasher.verify(password, password_hash)