from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class EntitlementResult:
    status: Literal["preserved", "absent", "none-compatible", "stripped"]
    kept_keys: tuple[str, ...]
    dropped_keys: tuple[str, ...]
    format: Literal["xml", "binary"] | None


@dataclass(frozen=True)
class CryptDump:
    path: Path
    cache_status: Literal["hit", "miss"]
    cache_key: str
    dump_sha256: str


@dataclass(frozen=True)
class PatchResult:
    strategy: str
    input_sha256: str
    cryptoff: int
    cryptsize: int
    cache_status: Literal["hit", "miss", "not-needed"]
    cache_key: str | None
    dump_sha256: str | None
    entitlements: EntitlementResult


def hash_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as target:
        temporary = Path(target.name)
        try:
            json.dump(value, target, indent=2, sort_keys=True)
            target.write("\n")
            target.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
