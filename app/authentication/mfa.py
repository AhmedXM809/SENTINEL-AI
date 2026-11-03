import base64
import hashlib
import hmac
import math
import os
import re
import secrets
import time

from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet, InvalidToken


MFA_ENCRYPTION_ENV_NAME = "SENTINEL_MFA_ENCRYPTION_KEY"

TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
TOTP_ALLOWED_WINDOW = 1

TOTP_SECRET_BYTES = 20
RECOVERY_CODE_BYTES = 16
RECOVERY_CODE_COUNT = 10

_SECRET_PATTERN = re.compile(r"^[A-Z2-7]{32}$")
_CODE_PATTERN = re.compile(r"^[0-9]{6}$")
_HEX_PATTERN = re.compile(r"^[A-F0-9]{32}$")


class MFAConfigurationError(ValueError):
    """Raised when MFA cryptographic configuration is invalid."""


class MFAInputError(ValueError):
    """Raised when MFA input is malformed."""


def load_mfa_fernet() -> Fernet:
    """Load the persistent MFA encryption key from the environment."""

    value = os.environ.get(MFA_ENCRYPTION_ENV_NAME)

    if not value:
        raise MFAConfigurationError(
            "MFA encryption key is not configured."
        )

    try:
        key = value.encode("ascii")
        return Fernet(key)
    except (UnicodeEncodeError, ValueError):
        raise MFAConfigurationError(
            "MFA encryption key has an invalid format."
        ) from None


def _validate_totp_secret(secret: str) -> bytes:
    if not isinstance(secret, str):
        raise MFAInputError("TOTP secret must be text.")

    if not _SECRET_PATTERN.fullmatch(secret):
        raise MFAInputError("TOTP secret has an invalid format.")

    try:
        decoded = base64.b32decode(secret, casefold=False)
    except (ValueError, base64.binascii.Error):
        raise MFAInputError("TOTP secret is invalid.") from None

    if len(decoded) != TOTP_SECRET_BYTES:
        raise MFAInputError("TOTP secret has an invalid length.")

    return decoded


def generate_totp_secret() -> str:
    """Generate a 160-bit random Base32 TOTP secret."""

    random_bytes = secrets.token_bytes(TOTP_SECRET_BYTES)

    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def encrypt_totp_secret(secret: str) -> str:
    """Encrypt a Base32 TOTP secret using Fernet."""

    _validate_totp_secret(secret)

    cipher = load_mfa_fernet()

    encrypted = cipher.encrypt(
        secret.encode("ascii")
    )

    return encrypted.decode("ascii")


def decrypt_totp_secret(ciphertext: str) -> str:
    """Decrypt and validate a stored TOTP secret."""

    if not isinstance(ciphertext, str) or not ciphertext:
        raise MFAInputError("Encrypted TOTP secret is invalid.")

    cipher = load_mfa_fernet()

    try:
        plaintext = cipher.decrypt(
            ciphertext.encode("ascii"),
            ttl=None,
        )

        secret = plaintext.decode("ascii")

    except (InvalidToken, UnicodeEncodeError, UnicodeDecodeError):
        raise MFAConfigurationError(
            "Unable to decrypt MFA secret."
        ) from None

    _validate_totp_secret(secret)

    return secret


def current_totp_step(now: float | None = None) -> int:
    """Return the current RFC 6238 time counter."""

    timestamp = time.time() if now is None else now

    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
        or timestamp < 0
    ):
        raise MFAInputError("Invalid TOTP timestamp.")

    return int(timestamp // TOTP_PERIOD_SECONDS)


def totp_code(
    secret: str,
    *,
    step: int,
    digits: int = TOTP_DIGITS,
) -> str:
    """Calculate an RFC 6238 TOTP value for a specified time step."""

    key = _validate_totp_secret(secret)

    if (
        isinstance(step, bool)
        or not isinstance(step, int)
        or step < 0
    ):
        raise MFAInputError("Invalid TOTP time step.")

    if digits not in (6, 8):
        raise MFAInputError("TOTP digits must be 6 or 8.")

    counter = step.to_bytes(8, "big")

    digest = hmac.new(
        key,
        counter,
        hashlib.sha1,
    ).digest()

    offset = digest[-1] & 0x0F

    binary = int.from_bytes(
        digest[offset:offset + 4],
        "big",
    ) & 0x7FFFFFFF

    return f"{binary % (10 ** digits):0{digits}d}"


def verify_totp_code(
    secret: str,
    code: str,
    *,
    now: float | None = None,
    last_used_step: int | None = None,
) -> int | None:
    """
    Verify a six-digit TOTP value.

    Returns the accepted time step, or None if invalid or replayed.
    The caller must persist the accepted step atomically.
    """

    _validate_totp_secret(secret)

    if not isinstance(code, str) or not _CODE_PATTERN.fullmatch(code):
        return None

    if last_used_step is not None and (
        isinstance(last_used_step, bool)
        or not isinstance(last_used_step, int)
        or last_used_step < 0
    ):
        raise MFAInputError("Invalid last-used TOTP step.")

    current_step = current_totp_step(now)

    candidates = (
        current_step,
        current_step - 1,
        current_step + 1,
    )

    matched = []

    for candidate_step in candidates:
        if candidate_step < 0:
            continue

        if (
            last_used_step is not None
            and candidate_step <= last_used_step
        ):
            continue

        expected = totp_code(
            secret,
            step=candidate_step,
            digits=TOTP_DIGITS,
        )

        if hmac.compare_digest(expected, code):
            matched.append(candidate_step)

    if not matched:
        return None

    # Prefer the current step if a six-digit collision occurs.
    matched.sort(
        key=lambda value: (
            abs(value - current_step),
            value,
        )
    )

    return matched[0]


def generate_recovery_codes(
    count: int = RECOVERY_CODE_COUNT,
) -> list[str]:
    """Generate high-entropy, single-use recovery codes."""

    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= 20
    ):
        raise MFAInputError(
            "Recovery-code count must be between 1 and 20."
        )

    codes = []

    for _ in range(count):
        raw = secrets.token_bytes(RECOVERY_CODE_BYTES)
        hexadecimal = raw.hex().upper()

        # Human-readable 128-bit value, grouped for manual entry.
        formatted = "-".join(
            hexadecimal[index:index + 8]
            for index in range(0, len(hexadecimal), 8)
        )

        codes.append(formatted)

    return codes


def normalize_recovery_code(code: str) -> str:
    if not isinstance(code, str):
        raise MFAInputError("Recovery code must be text.")

    normalized = "".join(
        character
        for character in code.upper()
        if character not in "- \t\r\n"
    )

    if not _HEX_PATTERN.fullmatch(normalized):
        raise MFAInputError("Recovery code has an invalid format.")

    return normalized


def hash_recovery_code(code: str) -> str:
    """Hash a 128-bit random recovery code for database storage."""

    normalized = normalize_recovery_code(code)
    raw = bytes.fromhex(normalized)

    digest = hashlib.sha256(
        b"sentinel-mfa-recovery:v1\x00" + raw
    ).hexdigest()

    return digest


def create_otpauth_uri(
    secret: str,
    username: str,
    issuer: str = "SENTINEL AI",
) -> str:
    """Create a standard authenticator-app provisioning URI."""

    _validate_totp_secret(secret)

    if (
        not isinstance(username, str)
        or not username.strip()
        or len(username) > 64
        or not isinstance(issuer, str)
        or not issuer.strip()
        or len(issuer) > 64
    ):
        raise MFAInputError("Invalid TOTP account label.")

    issuer = issuer.strip()
    username = username.strip()

    label = quote(
        f"{issuer}:{username}",
        safe="",
    )

    query = urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD_SECONDS,
    })

    return f"otpauth://totp/{label}?{query}"