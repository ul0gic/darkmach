"""Credential detection over binary strings — named formats ranked above keyword noise."""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from typing import NamedTuple

from darkmach.secretshapes import HIGH_SHAPES, MEDIUM_SHAPES

_RANK = {"high": 0, "medium": 1, "low": 2}
_DEMOTED = {"high": "medium", "medium": "low", "low": "low"}


class CredentialHit(NamedTuple):
    """`value` is the credential itself; `context` is the whole scanned string it sits in."""

    shape: str
    confidence: str
    value: str
    context: str
    source: str = ""


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

_PLACEHOLDER_RE = re.compile(
    r"(?i)example|placeholder|redacted|your[_-]?|xxxx|null|none|dummy|changeme"
    r"|username|password|<[a-z_-]+>"
)

_HOSTNAME_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")

_PEM_BEGIN_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
)
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_PEM_HEADER_RE = re.compile(r"(?i)^(?:Proc-Type|DEK-Info|Comment|Version):")
_PEM_LOOKAHEAD = 4

# Six-plus same-case letters in a row is a dictionary word, not entropy.
_MAX_SAME_CASE_RUN = 5
_MIN_ENTROPY_BITS = 4.0
_MAX_CHAR_SHARE = 0.25
_MAX_TEMPLATE_CHAR_SHARE = 0.5


def _build_scanner(shapes: tuple[tuple[str, str], ...]) -> tuple[re.Pattern[str], dict[str, str]]:
    parts = []
    names = {}
    for index, (shape, pattern) in enumerate(shapes):
        group = f"g{index}"
        names[group] = shape
        parts.append(f"(?P<{group}>{pattern})")
    return re.compile("|".join(parts)), names


_HIGH_SCANNER, _HIGH_NAMES = _build_scanner(HIGH_SHAPES)
_MEDIUM_SCANNER, _MEDIUM_NAMES = _build_scanner(MEDIUM_SHAPES)


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


def _jwt_header_decodes(value: str) -> bool:
    header = value.split(".", 1)[0]
    try:
        claims = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return isinstance(claims, dict) and "alg" in claims


def _is_template(value: str) -> bool:
    """A documentation placeholder or filler-character constant, not an issued credential."""
    if _PLACEHOLDER_RE.search(value):
        return True
    return max(Counter(value).values()) / len(value) > _MAX_TEMPLATE_CHAR_SHARE


def _grade(shape: str, value: str, confidence: str) -> str:
    unverified = shape == "jwt" and not _jwt_header_decodes(value)
    return _DEMOTED[confidence] if unverified or _is_template(value) else confidence


def _overlaps(value: str, claimed: set[str]) -> bool:
    return any(value in known or known in value for known in claimed)


def _scan(
    strings: list[str],
    scanner: re.Pattern[str],
    names: dict[str, str],
    confidence: str,
    source: str,
) -> list[CredentialHit]:
    hits = []
    for line in strings:
        context = line.strip()
        for match in scanner.finditer(context):
            value = match.group(0)
            shape = _refine(names[match.lastgroup], value)
            hits.append(
                CredentialHit(shape, _grade(shape, value, confidence), value, context, source)
            )
    return hits


def _named_hits(strings: list[str], source: str) -> list[CredentialHit]:
    high = _scan(strings, _HIGH_SCANNER, _HIGH_NAMES, "high", source)
    claimed = {hit.value for hit in high}
    medium = [
        hit
        for hit in _scan(strings, _MEDIUM_SCANNER, _MEDIUM_NAMES, "medium", source)
        if not any(hit.value in known for known in claimed)
    ]
    return high + medium


def _pem_evidence(strings: list[str], index: int, offset: int) -> str | None:
    """The string carrying the key body — `strings` splits an embedded PEM across lines."""
    if _PEM_BODY_RE.search(strings[index][offset:]):
        return strings[index].strip()
    for line in strings[index + 1 : index + 1 + _PEM_LOOKAHEAD]:
        candidate = line.strip()
        if _PEM_BODY_RE.fullmatch(candidate):
            return candidate
        if not _PEM_HEADER_RE.match(candidate):
            return None
    return None


def _pem_hits(strings: list[str], source: str) -> list[CredentialHit]:
    hits = []
    for index, line in enumerate(strings):
        match = _PEM_BEGIN_RE.search(line)
        if not match:
            continue
        evidence = _pem_evidence(strings, index, match.end())
        if evidence:
            hits.append(CredentialHit("private-key-pem", "high", match.group(0), evidence, source))
        else:
            hits.append(
                CredentialHit(
                    "pem-marker-no-key-material", "low", match.group(0), line.strip(), source
                )
            )
    return hits


def _assignment_hits(strings: list[str], claimed: set[str], source: str) -> list[CredentialHit]:
    hits = []
    for line in strings:
        context = line.strip()
        for match in _ASSIGNMENT_RE.finditer(context):
            value = match.group(1)
            if _looks_random(value) and not _overlaps(value, claimed):
                hits.append(
                    CredentialHit("keyword-anchored-value", "medium", value, context, source)
                )
    return hits


def _entropy_hits(strings: list[str], claimed: set[str], source: str) -> list[CredentialHit]:
    hits = []
    for line in strings:
        context = line.strip()
        if not _STANDALONE_RE.match(context) or not _looks_random(context):
            continue
        if _overlaps(context, claimed):
            continue
        hits.append(CredentialHit("high-entropy-string", "low", context, context, source))
    return hits


def rank_credentials(hits: list[CredentialHit]) -> list[CredentialHit]:
    """Deduplicated high-to-low ordering, safe to apply across scans of several sources."""
    unique = {(hit.shape, hit.value, hit.source): hit for hit in hits}
    return sorted(unique.values(), key=lambda h: (_RANK[h.confidence], h.shape, h.value, h.source))


def scan_credentials(strings: list[str], source: str = "") -> list[CredentialHit]:
    """Credential-shaped matches ranked high to low; keyword-only noise is not included."""
    unique_strings = list(dict.fromkeys(strings))
    hits = _named_hits(unique_strings, source) + _pem_hits(unique_strings, source)
    claimed = {hit.value for hit in hits} | {hit.context for hit in hits}
    hits += _assignment_hits(unique_strings, claimed, source)
    hits += _entropy_hits(unique_strings, claimed | {h.value for h in hits}, source)
    return rank_credentials(hits)


def keyword_matches(strings: list[str]) -> list[str]:
    """Strings merely mentioning a credential word — retained for review, not a detection."""
    return sorted({s.strip() for s in strings if _KEYWORD_RE.search(s)})
