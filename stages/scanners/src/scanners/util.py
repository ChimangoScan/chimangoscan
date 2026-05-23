from __future__ import annotations
import re, socket, time

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def slugify(ref: str) -> str:
    """`library/nginx:1.12` -> `library_nginx_1.12` (filesystem- and url-safe)."""
    s = _SLUG_RE.sub("_", ref.strip()).strip("_")
    return s or "image"


def normalize_image(ref: str) -> str:
    """Ensure an explicit tag (`nginx` -> `nginx:latest`); leave digests alone."""
    ref = ref.strip()
    if "@" in ref:
        return ref
    tail = ref.rsplit("/", 1)[-1]
    return ref if ":" in tail else f"{ref}:latest"


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def host_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
