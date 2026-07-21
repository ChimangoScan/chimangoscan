from __future__ import annotations
import json
from collections.abc import Iterator

from ..models import Target
from .base import Source


class JsonlSource(Source):
    """One JSON object per line. Understands the ChimangoScan ranking schema
    (repository_namespace / repository_name / tag_name / weights) and a plain
    {"image": ..., "weight": ..., "ip": ...} schema."""

    def _iter(self) -> Iterator[Target]:
        for n, line in enumerate(self.path.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{self.path}:{n}: {e}") from e
            if "image" in d:
                image = d["image"]
            else:
                ns = (d.get("repository_namespace") or "").strip()
                repo = (d.get("repository_name") or "").strip()
                tag = (d.get("tag_name") or "latest").strip()
                if not repo:
                    continue
                image = f"{repo}:{tag}" if ns in ("", "library") else f"{ns}/{repo}:{tag}"
            w = d.get("weight", d.get("weights", 0.0))
            try:
                w = float(w)
            except (TypeError, ValueError):
                w = 0.0
            yield Target(image=image, name=d.get("name", ""), ip=d.get("ip"),
                         weight=w, meta={k: v for k, v in d.items()
                                         if k not in ("image", "name", "ip", "weight", "weights")})
