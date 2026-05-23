from __future__ import annotations
import logging, socket, time, uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.error import URLError
from urllib.request import urlopen

from ..config import Config
from ..models import Target
from . import client as d

log = logging.getLogger("scanners.lifecycle")


class TargetUnscannable(Exception):
    """Permanent: don't retry this target (e.g. image too large, exits on startup)."""


@dataclass
class Running:
    name: str
    ip: str
    open_ports: list[int] = field(default_factory=list)
    http_endpoints: list[str] = field(default_factory=list)


class ContainerManager:
    """Pulls a target image and (for the dynamic phase) runs it hardened on an
    isolated network, probes its ports, and tears it down. Counts completions so
    it can prune images periodically."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.r = cfg.runtime
        self._done = 0
        self._net_ready = False

    # ── pulling (needed by every phase) ─────────────────────────────────────
    def ensure_pulled(self, image: str) -> float | None:
        d.pull(image, retries=self.r.pull_retries, backoff=self.r.pull_backoff)
        size = d.image_size_mb(image)
        if size is not None and self.r.max_image_mb and size > self.r.max_image_mb:
            raise TargetUnscannable(f"image {image} is {size:.0f} MB > limit {self.r.max_image_mb} MB")
        return size

    def maybe_prune(self) -> None:
        self._done += 1
        if self.r.prune_every and self._done % self.r.prune_every == 0:
            d.prune_images()

    def release_image(self, image: str) -> None:
        if self.r.remove_image_after:
            d.rm_image(image)

    def export_rootfs(self, image: str, into: Path) -> Path:
        """Flatten `image` to `into/rootfs`; reused if already extracted."""
        root = into / "rootfs"
        if root.is_dir() and any(root.iterdir()):
            return root
        d.export_rootfs(image, root)
        return root

    # ── running (dynamic phase only) ────────────────────────────────────────
    def _ensure_net(self) -> None:
        if not self._net_ready:
            d.ensure_network(self.r.network, self.r.subnet)
            self._net_ready = True

    @contextmanager
    def run(self, target: Target):
        """Yield a `Running` (or None if the container can't be brought up)."""
        self._ensure_net()
        name = f"scan-{target.name[:40]}-{uuid.uuid4().hex[:8]}"
        ro = self.r.hardened
        try:
            self._start(target.image, name, read_only=ro)
            if not self._wait_alive(name):
                if ro:                                    # some images need a writable rootfs
                    log.info("%s exited on startup with read-only rootfs; retrying writable", target.image)
                    d.rm(name)
                    self._start(target.image, name, read_only=False)
                    if not self._wait_alive(name):
                        ec = d.container_exit_code(name)
                        d.rm(name)
                        raise TargetUnscannable(f"container exits on startup (exit {ec})")
                else:
                    ec = d.container_exit_code(name)
                    d.rm(name)
                    raise TargetUnscannable(f"container exits on startup (exit {ec})")
            ip = d.container_ip(name, self.r.network)
            if not ip:
                d.rm(name)
                raise TargetUnscannable("no IP on the scan network")
            time.sleep(self.r.startup_wait)
            ports = self._probe(ip)
            https = [f"http://{ip}:{p}" for p in ports if p in self.r.http_ports]
            # an https-only service on 443 is still an http endpoint for the DAST tools
            https += [f"https://{ip}:{p}" for p in ports if p in (443, 8443)]
            log.info("%s up at %s ports=%s", target.image, ip, ports or "none")
            yield Running(name=name, ip=ip, open_ports=ports, http_endpoints=_dedup(https))
        finally:
            d.rm(name)
            self.maybe_prune()

    def _start(self, image: str, name: str, *, read_only: bool) -> None:
        d.run_detached(image, name=name, network=self.r.network, read_only=read_only,
                       mem_limit=self.r.mem_limit, pids_limit=self.r.pids_limit,
                       cpu_quota=self.r.cpu_quota, cap_drop_all=self.r.hardened,
                       no_new_privileges=self.r.hardened)

    @staticmethod
    def _wait_alive(name: str, settle: float = 1.5) -> bool:
        time.sleep(settle)
        return d.container_running(name)

    def _probe(self, ip: str) -> list[int]:
        deadline = time.time() + self.r.health_timeout
        open_ports: list[int] = []
        while time.time() < deadline:
            for port in self.r.probe_ports:
                if port in open_ports:
                    continue
                try:
                    with socket.create_connection((ip, port), timeout=1.0):
                        open_ports.append(port)
                except OSError:
                    pass
            if open_ports:
                # give a slow web server a moment to actually start serving
                for ep in (f"http://{ip}:{p}" for p in open_ports if p in self.r.http_ports):
                    _http_ready(ep)
                return sorted(open_ports)
            time.sleep(2)
        return sorted(open_ports)


def _http_ready(url: str, tries: int = 5) -> bool:
    for _ in range(tries):
        try:
            with urlopen(url, timeout=2):
                return True
        except URLError:
            pass
        except Exception:
            return True            # any HTTP response (incl. 4xx/5xx) means it's serving
        time.sleep(1)
    return False


def _dedup(xs: list[str]) -> list[str]:
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out
