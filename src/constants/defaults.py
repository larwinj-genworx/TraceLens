from __future__ import annotations

import re

# ─────────────────────────────────────────────────────────────────────────────
# Sensitive field detection
# ─────────────────────────────────────────────────────────────────────────────

# Long, specific substrings that are unambiguously sensitive wherever they appear
# as a substring of a field name.  These are safe for substring matching.
SENSITIVE_FIELD_MARKERS: frozenset[str] = frozenset({
    "password",
    "passwd",
    "_token",        # catches: access_token, refresh_token, auth_token, id_token, etc.
                     # does NOT match: token_count, token_type (no leading underscore)
    "secret",
    "api_key",
    "authorization",
    "refresh_token",
    "access_token",
    "private_key",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
})

# Short tokens that should only match when the entire field name (or one of its
# underscore-delimited word segments) equals the token.  Prevents collateral
# matches like "token_count" or "primary_key" from being flagged as sensitive.
SENSITIVE_WORD_TOKENS: frozenset[str] = frozenset({"token", "secret", "key"})

# Field names that are sensitive when the whole lowercased name equals them.
SENSITIVE_EXACT_NAMES: frozenset[str] = frozenset({"token", "password", "passwd", "secret"})


def is_sensitive_field_name(name: str) -> bool:
    """
    Return ``True`` when a model field name indicates sensitive / secret data.

    Three-tier check:
    1. Exact full-name match  (e.g., a field literally called ``token``).
    2. Substring match for long, unambiguous markers
       (e.g., ``access_token``, ``stripe_api_key``).
    3. Word-segment match: split on ``_`` / ``-`` / ``.`` and check each part
       against ``SENSITIVE_WORD_TOKENS``
       (e.g., ``auth_token`` → segment ``token`` → sensitive;
              ``token_count`` → segment ``count`` is last → ``token`` is not
              the last segment, so this path only fires when it IS the last).

    The word-segment check is applied only to the *last* segment so that
    ``pagination_token`` (last segment = ``token``) is still flagged – cursor
    tokens can be sensitive – while ``token_count`` (last segment = ``count``)
    is correctly cleared.
    """
    lowered = name.strip().lower()

    # Tier 1: exact whole-name match
    if lowered in SENSITIVE_EXACT_NAMES:
        return True

    # Tier 2: substring match (for long, specific markers)
    if any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS):
        return True

    # Tier 3: word-segment – only the last segment to prevent "token_count"
    # from being false-positive while keeping "access_token" covered by tier 2.
    parts = re.split(r"[_\-\.]", lowered)
    if parts and parts[-1] in SENSITIVE_WORD_TOKENS:
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Other constants
# ─────────────────────────────────────────────────────────────────────────────

PUBLIC_PATH_MARKERS: frozenset[str] = frozenset({
    "/health",
    "/docs",
    "/openapi.json",
    "/login",
    "/signup",
    "/register",
})

HTTP_METHODS: frozenset[str] = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
})
