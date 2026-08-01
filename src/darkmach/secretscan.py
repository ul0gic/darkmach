"""Credential detection over binary strings — named formats ranked above keyword noise."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from typing import NamedTuple

_RANK = {"high": 0, "medium": 1, "low": 2}


class CredentialHit(NamedTuple):
    """`value` is the credential itself; `context` is the whole binary string it sits in."""

    shape: str
    confidence: str
    value: str
    context: str


_HIGH_SHAPES: tuple[tuple[str, str], ...] = (
    ("private-key-pem", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?"),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AGPA|APKA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("google-oauth-client-id", r"\b\d{9,}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b"),
    ("fcm-server-key", r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}"),
    ("firebase-database-url", r"\bhttps://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)\b"),
    ("stripe-publishable-key", r"\bpk_(?:live|test)_[A-Za-z0-9+/=_-]{16,}"),
    ("stripe-secret-key", r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,}\b"),
    ("stripe-webhook-secret", r"\bwhsec_[A-Za-z0-9]{24,}\b"),
    ("supabase-key", r"\bsb_(?:publishable|secret)_[A-Za-z0-9_-]{20,}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("github-fine-grained-pat", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("slack-token", r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
    ("slack-webhook", r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/\w+"),
    ("openai-api-key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}"),
    ("anthropic-api-key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
    ("huggingface-token", r"\bhf_[A-Za-z0-9]{34}\b"),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("pypi-token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    ("sendgrid-api-key", r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b"),
    ("mailgun-api-key", r"\bkey-[0-9a-f]{32}\b"),
    ("mailchimp-api-key", r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    ("twilio-api-key-sid", r"\bSK[0-9a-f]{32}\b"),
    ("twilio-account-sid", r"\bAC[0-9a-f]{32}\b"),
    ("square-access-token", r"\b(?:sq0atp|sq0csp)-[A-Za-z0-9_-]{22,}\b"),
    ("square-oauth-token", r"\bEAAA[A-Za-z0-9_-]{58,}\b"),
    ("facebook-access-token", r"\bEAA[A-Za-z0-9]{80,}\b"),
    ("braintree-tokenization-key", r"\b(?:production|sandbox)_[a-z0-9]{8}_[a-z0-9]{16}\b"),
    (
        "braintree-access-token",
        r"\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[0-9a-f]{32}",
    ),
    ("branch-key", r"\bkey_(?:live|test)_[A-Za-z0-9]{32}\b"),
    ("sentry-dsn", r"\bhttps://[0-9a-f]{32,}(?::[0-9a-f]{32})?@[A-Za-z0-9.-]+/\d+"),
    ("recaptcha-key", r"\b6L[A-Za-z0-9_-]{38}\b"),
    ("telegram-bot-token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    ("shopify-token", r"\bshp(?:at|ca|pa|ss)_[0-9a-f]{32}\b"),
    ("azure-storage-key", r"\bAccountKey=[A-Za-z0-9+/=]{60,}"),
    ("basic-auth-url", r"\b[a-z][a-z0-9+.-]*://[^\s:/@]{1,64}:[^\s:/@]{1,64}@[A-Za-z0-9.-]+"),
)

_MEDIUM_SHAPES: tuple[tuple[str, str], ...] = (
    ("google-api-key-partial", r"\bAIza[0-9A-Za-z_-]{20,34}\b"),
    ("google-oauth-refresh-token", r"\b1//[0-9A-Za-z_-]{30,}"),
    ("discord-bot-token", r"\b[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b"),
    ("notion-integration-token", r"\bsecret_[A-Za-z0-9]{43}\b"),
    ("ssh-public-key", r"\bssh-(?:rsa|ed25519|dss) AAAA[A-Za-z0-9+/]{20,}"),
    ("basic-auth-header", r"\bBasic [A-Za-z0-9+/]{16,}={0,2}"),
)

_KEYWORD_RE = re.compile(
    r"api[._-]?key|apikey|secret|token|bearer|authorization|password|credential",
    re.IGNORECASE,
)

_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[._-]?key|apikey|secret|token|password|passwd|credential|auth)\w*"
    r"['\"\s]*[:=]\s*['\"]?([A-Za-z0-9+/=_.-]{16,})"
)

_STANDALONE_RE = re.compile(r"^[A-Za-z0-9+/_-]{28,}={0,2}$")

# Mangled Swift/ObjC symbols are the exact profile an entropy test mistakes for a key.
_MANGLED_RE = re.compile(
    r"^_?\$[sS]|^_T|^\d{1,3}[A-Za-z][a-z]{2,}|_[A-Z]?\d+_|^S[oS]\d|_S[a-zA-Z]\d|_p(?:Sg)?$"
)

_PLACEHOLDER_RE = re.compile(r"(?i)example|placeholder|redacted|your[_-]?|xxxx|null|none|dummy")

_HOSTNAME_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")

# Six-plus same-case letters in a row is a dictionary word, not entropy.
_MAX_SAME_CASE_RUN = 5
_MIN_ENTROPY_BITS = 4.0
_MAX_CHAR_SHARE = 0.25


def _build_scanner(shapes: tuple[tuple[str, str], ...]) -> tuple[re.Pattern[str], dict[str, str]]:
    parts = []
    names = {}
    for index, (shape, pattern) in enumerate(shapes):
        group = f"g{index}"
        names[group] = shape
        parts.append(f"(?P<{group}>{pattern})")
    return re.compile("|".join(parts)), names


_HIGH_SCANNER, _HIGH_NAMES = _build_scanner(_HIGH_SHAPES)
_MEDIUM_SCANNER, _MEDIUM_NAMES = _build_scanner(_MEDIUM_SHAPES)


def _shannon_bits(value: str) -> float:
    total = len(value)
    counts = Counter(value).values()
    return -sum((c / total) * math.log2(c / total) for c in counts)


def _longest_case_run(value: str) -> int:
    lower = upper = longest = 0
    for char in value:
        lower = lower + 1 if char.islower() else 0
        upper = upper + 1 if char.isupper() else 0
        longest = max(longest, lower, upper)
    return longest


def _looks_random(value: str) -> bool:
    if _MANGLED_RE.search(value) or _PLACEHOLDER_RE.search(value):
        return False
    digits = sum(char.isdigit() for char in value)
    if digits < 2 or digits > len(value) * 0.5:
        return False
    if _longest_case_run(value) > _MAX_SAME_CASE_RUN:
        return False
    if _shannon_bits(value) < _MIN_ENTROPY_BITS:
        return False
    return max(Counter(value).values()) / len(value) <= _MAX_CHAR_SHARE


def _clerk_domain(value: str) -> str | None:
    """Decoded instance host, or None when the key is not Clerk-issued."""
    payload = value.rsplit("_", 1)[-1]
    try:
        decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not decoded.endswith("$"):
        return None
    host = decoded[:-1]
    return host if _HOSTNAME_RE.fullmatch(host) else None


def _refine(shape: str, value: str) -> str:
    # Clerk and Stripe share the pk_live_ prefix; only Clerk's suffix decodes to "<host>$".
    if shape == "stripe-publishable-key" and _clerk_domain(value):
        return "clerk-publishable-key"
    return shape


def _named_hits(strings: list[str]) -> list[CredentialHit]:
    hits = []
    for scanner, names, confidence in (
        (_HIGH_SCANNER, _HIGH_NAMES, "high"),
        (_MEDIUM_SCANNER, _MEDIUM_NAMES, "medium"),
    ):
        for line in strings:
            context = line.strip()
            for match in scanner.finditer(context):
                value = match.group(0)
                shape = _refine(names[match.lastgroup], value)
                hits.append(CredentialHit(shape, confidence, value, context))
    return hits


def _assignment_hits(strings: list[str]) -> list[CredentialHit]:
    hits = []
    for line in strings:
        context = line.strip()
        for match in _ASSIGNMENT_RE.finditer(context):
            value = match.group(1)
            if _looks_random(value):
                hits.append(CredentialHit("keyword-anchored-value", "medium", value, context))
    return hits


def _entropy_hits(strings: list[str], claimed: set[str]) -> list[CredentialHit]:
    hits = []
    for line in strings:
        context = line.strip()
        if not _STANDALONE_RE.match(context) or not _looks_random(context):
            continue
        if any(known in context or context in known for known in claimed):
            continue
        hits.append(CredentialHit("high-entropy-string", "low", context, context))
    return hits


def scan_credentials(strings: list[str]) -> list[CredentialHit]:
    """Credential-shaped matches ranked high to low; keyword-only noise is not included."""
    unique_strings = list(dict.fromkeys(strings))
    hits = _named_hits(unique_strings) + _assignment_hits(unique_strings)
    hits += _entropy_hits(unique_strings, {hit.value for hit in hits})
    unique = {(hit.shape, hit.value): hit for hit in hits}
    return sorted(unique.values(), key=lambda h: (_RANK[h.confidence], h.shape, h.value))


def keyword_matches(strings: list[str]) -> list[str]:
    """Strings merely mentioning a credential word — retained for review, not a detection."""
    return sorted({s.strip() for s in strings if _KEYWORD_RE.search(s)})
