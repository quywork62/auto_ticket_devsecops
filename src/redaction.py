"""Mask likely credentials before content is logged, emailed, or ticketed."""

import re

MASK = "XXXXXX"
LAST_FOUR_LENGTH = 4
MIN_PARTIAL_MASK_LENGTH = 8

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b("
    r"api[_\s-]*key|secret[_\s-]*key|access[_\s-]*token|auth[_\s-]*token|"
    r"client[_\s-]*secret|refresh[_\s-]*token|session[_\s-]*(?:token|cookie)|"
    r"private[_\s-]*key|jwt|password|passwd|pwd"
    r")\b\s*([:=])\s*([\"']?)([^\s\"';&<>]{4,})([\"']?)"
)

_AUTH_HEADER = re.compile(
    r"(?i)\b(Authorization\s*:\s*(?:Token|Bearer|Basic))\s+([^\s]+)"
)

_AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{12,}\b")
_LONG_HEX_SECRET = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_JWT = re.compile(
    r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
    re.DOTALL,
)

_FULL_MASK_LABELS = {
    "jwt",
    "password",
    "passwd",
    "private_key",
    "pwd",
    "refresh_token",
    "session_cookie",
    "session_token",
}


def _partial_mask(secret: str) -> str:
    """Mask a secret while retaining its final four characters for correlation."""
    if len(secret) <= LAST_FOUR_LENGTH:
        return MASK
    hidden_length = max(len(secret) - LAST_FOUR_LENGTH, MIN_PARTIAL_MASK_LENGTH)
    return "*" * hidden_length + secret[-LAST_FOUR_LENGTH:]


def _looks_like_jwt(secret: str) -> bool:
    """Return whether a complete value has the three-part JWT structure."""
    return _JWT.fullmatch(secret) is not None


def _normalize_secret_label(label: str) -> str:
    """Normalize credential labels before applying the masking policy."""
    return re.sub(r"[\s-]+", "_", label.strip().lower())


def _mask_assignment(match: re.Match[str]) -> str:
    """Mask one labeled credential assignment before template rendering."""
    label = match.group(1)
    secret = match.group(4)
    normalized_label = _normalize_secret_label(label)
    masked = (
        MASK
        if normalized_label in _FULL_MASK_LABELS or _looks_like_jwt(secret)
        else _partial_mask(secret)
    )
    return f"{label}{match.group(2)}{match.group(3)}{masked}{match.group(5)}"


def _mask_authorization_header(match: re.Match[str]) -> str:
    """Mask authorization credentials according to scheme and token structure."""
    header = match.group(1)
    credential = match.group(2)
    full_mask_required = header.lower().endswith("basic") or _looks_like_jwt(
        credential
    )
    masked = MASK if full_mask_required else _partial_mask(credential)
    return f"{header} {masked}"


def redact_secrets(value: object) -> str:
    """Mask likely secrets before content is sent by email or stored in templates."""
    if value is None:
        return "N/A"

    text = _PRIVATE_KEY_BLOCK.sub(MASK, str(value))
    text = _AUTH_HEADER.sub(_mask_authorization_header, text)
    text = _SECRET_ASSIGNMENT.sub(_mask_assignment, text)
    text = _JWT.sub(MASK, text)
    text = _AWS_ACCESS_KEY.sub(lambda match: _partial_mask(match.group(0)), text)
    text = _GITHUB_TOKEN.sub(lambda match: _partial_mask(match.group(0)), text)
    text = _LONG_HEX_SECRET.sub(lambda match: _partial_mask(match.group(0)), text)
    return text
