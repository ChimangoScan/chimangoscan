from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import Iterator

from ..config import Config
from ..models import Target


class Source(ABC):
    """Yields the targets to scan. Implementations read a catalog file."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.path = cfg.path(cfg.source.path)

    @abstractmethod
    def _iter(self) -> Iterator[Target]: ...

    def iter_deduped(self) -> Iterator[Target]:
        """Targets in file order, image-deduped, honoring source.limit. A
        generator — holds only the seen-set, not every Target — so seeding
        scales to millions of rows. The catalog files are pre-ranked, and the
        queue claims by weight at claim time, so file order is fine here."""
        seen: set[str] = set()
        limit = self.cfg.source.limit
        n = 0
        for t in self._iter():
            if t.image in seen:
                continue
            seen.add(t.image)
            yield t
            n += 1
            if limit and limit > 0 and n >= limit:
                return

    def targets(self) -> list[Target]:
        return sorted(self.iter_deduped(), key=lambda t: t.weight, reverse=True)
