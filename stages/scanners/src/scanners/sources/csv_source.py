from __future__ import annotations
import csv
from collections.abc import Iterator

from ..models import Target
from .base import Source


class CsvSource(Source):
    """Catalog as CSV. Needs an image column; IP/name/meta columns are optional.

    Matches the lab's inventory.csv (Category,Container,Image,Port,IP,Type) but
    works with any header by configuring source.{image,ip,name,meta}_column.
    """

    def _iter(self) -> Iterator[Target]:
        sc = self.cfg.source
        with self.path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or sc.image_column not in reader.fieldnames:
                raise ValueError(
                    f"{self.path}: missing image column '{sc.image_column}'; "
                    f"have {reader.fieldnames}")
            for row in reader:
                image = (row.get(sc.image_column) or "").strip()
                if not image or image.startswith("#"):
                    continue
                ip = (row.get(sc.ip_column) or "").strip() or None
                name = (row.get(sc.name_column) or "").strip()
                meta = {c: (row.get(c) or "").strip() for c in sc.meta_columns if c in row}
                w = 0.0
                if "weights" in row:
                    try:
                        w = float(row["weights"])
                    except ValueError:
                        pass
                yield Target(image=image, name=name, ip=ip, weight=w, meta=meta)
