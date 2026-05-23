from __future__ import annotations
from pathlib import Path

import yaml

from ..config import ConfigError
from ..models import Mode
from .base import ScannerSpec

_TRUE_LIST_FIELDS = {"argv", "outputs", "extra_invocations"}


def load_registry(path: str | Path) -> dict[str, ScannerSpec]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"scanner registry not found: {path}")
    doc = yaml.safe_load(path.read_text()) or {}
    defaults = dict(doc.get("defaults") or {})
    raw = doc.get("scanners") or {}
    if not raw:
        raise ConfigError(f"{path}: no scanners defined")
    out: dict[str, ScannerSpec] = {}
    for name, spec in raw.items():
        merged = {**defaults, **(spec or {})}
        try:
            mode = Mode(merged.pop("mode"))
        except (KeyError, ValueError) as e:
            raise ConfigError(f"scanner '{name}': bad/missing mode ({e})")
        if "image" not in merged:
            raise ConfigError(f"scanner '{name}': missing image")
        needs = tuple(merged.pop("needs", ()) or ())
        ok = tuple(merged.pop("ok_exit_codes", (0,)) or (0,))
        known = {f.name for f in ScannerSpec.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        unknown = set(merged) - known - {"image"}
        if unknown:
            raise ConfigError(f"scanner '{name}': unknown keys {sorted(unknown)}")
        out[name] = ScannerSpec(name=name, mode=mode, needs=needs, ok_exit_codes=ok,
                                **{k: v for k, v in merged.items() if k in known})
    return out


def select(registry: dict[str, ScannerSpec], *, only: list[str], skip: list[str],
           static: bool, dynamic: bool) -> list[ScannerSpec]:
    chosen = list(only) if only else [n for n, s in registry.items() if s.enabled]
    skip_set = set(skip)
    specs: list[ScannerSpec] = []
    for n in chosen:
        if n in skip_set:
            continue
        if n not in registry:
            raise ConfigError(f"scanner '{n}' is not in the registry")
        s = registry[n]
        if s.mode is Mode.STATIC and not static:
            continue
        if s.mode is Mode.DYNAMIC and not dynamic:
            continue
        specs.append(s)
    return specs
