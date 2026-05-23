from __future__ import annotations
import json, logging, shutil, threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from ..adapters.base import ScannerSpec
from ..config import Config
from ..dockerctl import client as d
from ..dockerctl.lifecycle import ContainerManager, Running, TargetUnscannable
from ..models import Finding, Mode, ScanInvocation, Target, TargetReport
from ..util import now_iso
from ..findings.store import TargetStore

log = logging.getLogger("scanners.worker")

# In-container mount points the scanner registry's argv templates refer to.
MNT_OUT, MNT_TAR, MNT_ROOTFS = "/out", "/work/image.tar", "/scan"


class ScanWorker:
    """Runs the full battery against one target and returns its TargetReport.
    The scanners for a target run concurrently (runtime.scan_parallelism); the
    image tar / flattened rootfs they share are produced once, up front."""

    def __init__(self, cfg: Config, specs: list[ScannerSpec]):
        self.cfg = cfg
        self.specs = specs
        self.cm = ContainerManager(cfg)
        self._pulled: set[str] = set()
        self._pull_lock = threading.Lock()
        self.cache_dir = cfg.cache_dir
        self._k = max(1, cfg.runtime.scan_parallelism)

    # ── public ──────────────────────────────────────────────────────────────
    def run(self, target: Target) -> TargetReport:
        rep = TargetReport(target=target, started_at=now_iso())
        store = TargetStore(self.cfg.out_dir, target)
        self._rootfs = None
        try:
            self.cm.ensure_pulled(target.image)
        except TargetUnscannable:
            raise
        except d.DockerError as e:
            raise TargetUnscannable(f"pull failed: {e}") from e
        try:                                   # record what :latest actually resolved to
            rep.scanned_image_digest = d.image_repo_digest(target.image)
        except Exception as e:                 # never let digest bookkeeping abort a scan
            log.debug("repo-digest lookup failed for %s: %s", target.image, e)

        static = [s for s in self.specs if s.mode is Mode.STATIC]
        dynamic = [s for s in self.specs if s.mode is Mode.DYNAMIC]
        try:
            # build the shared inputs once, before any scanner runs (avoids races)
            pending = [s for s in self.specs if not self._cached(s, target, store)]
            if any(s.needs_tarball for s in pending):
                tar = self._tarball_path(target); tar.parent.mkdir(parents=True, exist_ok=True)
                if not tar.exists():
                    d.save(target.image, tar)
            if any(s.needs_rootfs for s in pending):
                try:
                    self._rootfs = self.cm.export_rootfs(target.image, self._target_work(target))
                except d.DockerError as e:
                    log.warning("rootfs export failed for %s: %s", target.image, e)

            invs, fnds = self._run_phase(static, target, store, running=None)
            rep.invocations += invs; rep.findings += fnds

            if dynamic and self.cfg.scanners.dynamic:
                if all(self._cached(s, target, store) for s in dynamic):   # nothing left to run live
                    invs, fnds = self._run_phase(dynamic, target, store, running=None)
                    rep.invocations += invs; rep.findings += fnds
                else:
                    try:
                        with self.cm.run(target) as running:
                            rep.container_ip = running.ip
                            rep.open_ports = running.open_ports
                            rep.http_endpoints = running.http_endpoints
                            for f in rep.findings:           # correlate static findings with the container IP
                                if not f.target_ip:
                                    f.target_ip = running.ip
                            invs, fnds = self._run_phase(dynamic, replace(target, ip=running.ip), store, running)
                            rep.invocations += invs; rep.findings += fnds
                    except TargetUnscannable as e:
                        rep.skipped_reason = f"dynamic phase skipped: {e}"
                        for spec in dynamic:
                            rep.invocations.append(ScanInvocation(
                                scanner=spec.name, target_name=target.name, target_image=target.image,
                                target_ip=target.ip, mode=spec.mode.value, status="skipped", error=str(e)))

            rep.finished_at = now_iso()
            self._merge_prior_passes(store, rep, {s.name for s in self.specs})
            store.write_report(rep)
        finally:
            self._cleanup(target)
            self.cm.release_image(target.image)
            self.cm.maybe_prune()
        return rep

    def _run_phase(self, specs: list[ScannerSpec], target: Target, store: TargetStore,
                   running: Running | None) -> tuple[list[ScanInvocation], list[Finding]]:
        if not specs:
            return [], []
        invs: list[ScanInvocation] = [None] * len(specs)   # type: ignore[list-item]
        fnds: list[Finding] = []
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=min(self._k, len(specs)), thread_name_prefix="scan") as ex:
            futs = {ex.submit(self._invoke, s, target, store, running): i for i, s in enumerate(specs)}
            for fut in futs:
                i = futs[fut]
                inv, found = fut.result()
                invs[i] = inv
                with lock:
                    fnds.extend(found)
        return invs, fnds

    # ── one scanner invocation ──────────────────────────────────────────────
    def _invoke(self, spec: ScannerSpec, target: Target, store: TargetStore,
                running: Running | None) -> tuple[ScanInvocation, list[Finding]]:
        out_dir = store.scanner_dir(spec.name)
        rendered = spec.render(self._context(spec, target, running))
        inv = ScanInvocation(scanner=spec.name, target_name=target.name, target_image=target.image,
                             target_ip=target.ip, mode=spec.mode.value, image_ref=spec.image,
                             started_at=now_iso())

        # resume: a non-empty prior output is reused, not re-run
        if self.cfg.output.skip_done and self._has_output(rendered, out_dir):
            inv.status = "ok-cached"
            return inv, self._parse(spec, out_dir, target, inv)

        # gate dynamic scanners on target capabilities
        if "http" in spec.needs and not (running and running.http_endpoints):
            inv.status = "skipped"; inv.error = "no http endpoint"
            return inv, []
        if spec.needs_rootfs and not self._rootfs:
            inv.status = "error"; inv.error = "image rootfs export failed"
            return inv, []
        if spec.needs_tarball and not self._tarball_path(target).exists():
            inv.status = "error"; inv.error = "image tar not available"
            return inv, []

        try:
            self._ensure_scanner_image(spec)
        except d.DockerError as e:
            inv.status = "error"; inv.error = f"image pull: {e}"
            return inv, []

        mounts, workdir = self._mounts(spec, target, out_dir)
        timeout = spec.timeout or self.cfg.workers.scan_timeout
        net = self.cfg.runtime.network if spec.mode is Mode.DYNAMIC else None

        cmd_argv = ["docker", "run", "--rm", spec.image, *rendered.argv]
        try:
            r = d.run_monitored(spec.image, rendered.argv, name=self._cname(spec, target),
                                network=net, user=spec.user, entrypoint=spec.entrypoint,
                                workdir=workdir, mounts=mounts, env=spec.env, timeout=timeout)
        except Exception as e:                                   # never let one scanner kill the target
            log.exception("%s on %s crashed", spec.name, target.name)
            inv.status = "error"; inv.error = str(e)
            store.write_artifacts(spec.name, stderr=str(e).encode(), cmd=cmd_argv, failed=True)
            return inv, []

        inv.wall_seconds = round(r.wall_seconds, 2)
        inv.exit_code = r.exit_code
        inv.peak_cpu_pct = round(r.peak_cpu_pct, 1)
        inv.peak_mem_mb = round(r.peak_mem_mb, 1)
        inv.stderr_bytes = len(r.stderr)
        if rendered.capture_stdout:
            (out_dir / rendered.capture_stdout).write_bytes(r.stdout)
        else:
            inv.stdout_bytes = len(r.stdout)

        for extra in rendered.extra:
            try:
                d.run_monitored(spec.image, extra, name=self._cname(spec, target, suffix="x"),
                                network=net, user=spec.user, entrypoint=spec.entrypoint,
                                workdir=workdir, mounts=mounts, env=spec.env, timeout=timeout)
            except Exception:
                log.warning("%s extra invocation on %s failed", spec.name, target.name)

        if r.timed_out:
            inv.status = "timeout"
        elif r.exit_code in spec.ok_exit_codes or self._has_output(rendered, out_dir):
            inv.status = "ok" if r.exit_code in spec.ok_exit_codes else "nonzero-ok"
        else:
            inv.status = "error"
            inv.error = (r.stderr[-1500:] or r.stdout[-500:]).decode("utf-8", "replace").strip()
        store.write_artifacts(
            spec.name,
            stdout=b"" if rendered.capture_stdout else r.stdout,
            stderr=r.stderr, cmd=cmd_argv, exit_code=r.exit_code,
            failed=inv.status in ("error", "timeout"),
        )
        return inv, self._parse(spec, out_dir, target, inv)

    def _parse(self, spec: ScannerSpec, out_dir: Path, target: Target,
               inv: ScanInvocation) -> list[Finding]:
        files = [p for p in out_dir.iterdir() if p.is_file()]
        inv.artifacts = sorted(p.name for p in files)
        inv.output_bytes = sum(p.stat().st_size for p in files)
        findings: list[Finding] = []
        if inv.status in ("ok", "nonzero-ok", "ok-cached"):
            try:
                findings = spec.load_parser()(out_dir, target)
            except Exception as e:
                log.exception("parse %s for %s failed", spec.name, target.name)
                inv.error = f"parse: {e}"
        inv.findings = len(findings)
        inv.findings_by_severity = dict(Counter(f.severity.value for f in findings))
        return findings

    # ── helpers ─────────────────────────────────────────────────────────────
    def _cached(self, spec: ScannerSpec, target: Target, store: TargetStore) -> bool:
        if not self.cfg.output.skip_done:
            return False
        d_ = store.root / spec.name
        if not d_.exists():
            return False
        rendered = spec.render(self._context(spec, target, None))
        return self._has_output(rendered, d_)

    def _merge_prior_passes(self, store: TargetStore, rep: TargetReport, ran: set[str]) -> None:
        """Fold in invocations/findings from an earlier pass over this target whose
        scanners weren't run this time (so a `--only X` pass adds to, not replaces, the report)."""
        f = store.root / "report.json"
        if not f.is_file():
            return
        try:
            old = json.loads(f.read_text())
        except (OSError, ValueError):
            return
        for inv in old.get("invocations") or []:
            if inv.get("scanner") not in ran:
                rep.invocations.insert(0, ScanInvocation(**{k: v for k, v in inv.items()
                                                           if k in ScanInvocation.__dataclass_fields__}))
        for fd in old.get("findings") or []:
            if fd.get("scanner") not in ran:
                rep.findings.insert(0, Finding.from_json(fd))
        if not rep.container_ip and old.get("container_ip"):
            rep.container_ip = old["container_ip"]
        if not rep.open_ports and old.get("open_ports"):
            rep.open_ports = old["open_ports"]
        if not rep.http_endpoints and old.get("http_endpoints"):
            rep.http_endpoints = old["http_endpoints"]

    def _target_work(self, target: Target) -> Path:
        return self.cache_dir / "work" / target.name

    def _tarball_path(self, target: Target) -> Path:
        return self.cache_dir / "tars" / f"{target.name}.tar"

    def _cleanup(self, target: Target) -> None:
        if self.cfg.output.keep_image_tarball:
            return
        try:
            self._tarball_path(target).unlink(missing_ok=True)
        except OSError:
            pass
        wd = self._target_work(target)
        if wd.exists():
            shutil.rmtree(wd, ignore_errors=True)
        self._rootfs = None

    def _ensure_scanner_image(self, spec: ScannerSpec) -> None:
        if not spec.pull:
            return
        with self._pull_lock:
            if spec.image in self._pulled:
                return
            d.pull(spec.image, retries=self.cfg.runtime.pull_retries, backoff=self.cfg.runtime.pull_backoff)
            self._pulled.add(spec.image)

    def _context(self, spec: ScannerSpec, target: Target, running: Running | None) -> dict:
        url = (running.http_endpoints[0] if running and running.http_endpoints else "")
        host, port = "", ""
        if url:
            rest = url.split("://", 1)[-1]
            host = rest.split(":")[0].split("/")[0]
            port = rest.split(":")[1].split("/")[0] if ":" in rest else ("443" if url.startswith("https") else "80")
        elif running and running.open_ports:
            host, port = running.ip, str(running.open_ports[0])
        return {"image": target.image, "name": target.name, "out": MNT_OUT,
                "tarball": MNT_TAR if spec.needs_tarball else "", "rootfs": MNT_ROOTFS if spec.needs_rootfs else "",
                "url": url, "host": host or (running.ip if running else ""), "port": port,
                "cache": spec.cache_mount}

    def _mounts(self, spec: ScannerSpec, target: Target,
                out_dir: Path) -> tuple[list[tuple[str, str, bool]], str | None]:
        if spec.out_as_workdir and spec.workdir:
            mounts = [(str(out_dir), spec.workdir, False)]
        else:
            mounts = [(str(out_dir), MNT_OUT, False)]
        if spec.needs_tarball:
            mounts.append((str(self._tarball_path(target)), MNT_TAR, True))
        if spec.needs_rootfs and self._rootfs:
            mounts.append((str(self._rootfs), MNT_ROOTFS, True))
        if spec.needs_cache:
            cdir = self.cache_dir / spec.needs_cache
            cdir.mkdir(parents=True, exist_ok=True)
            mounts.append((str(cdir), spec.cache_mount, False))
        return mounts, (spec.workdir if not spec.out_as_workdir else None)

    @staticmethod
    def _has_output(rendered, out_dir: Path) -> bool:
        names = list(rendered.outputs) + ([rendered.capture_stdout] if rendered.capture_stdout else [])
        return any(name and (out_dir / name).exists() and (out_dir / name).stat().st_size > 0 for name in names)

    @staticmethod
    def _cname(spec: ScannerSpec, target: Target, suffix: str = "") -> str:
        import uuid
        return f"sc-{spec.name}-{target.name[:24]}-{uuid.uuid4().hex[:6]}{suffix}"
