from __future__ import annotations
import json, logging, shutil, subprocess, threading, time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("scanners.docker")

_RATE_LIMIT_HINTS = ("toomanyrequests", "rate limit", "429 too many requests")

# Pull errors that retrying will never fix — the tag is gone, the repo is
# private/absent, the manifest doesn't exist. Fail fast instead of grinding
# through `pull_retries` backoffs (~3.5 min) on a target we can't scan anyway.
_FATAL_PULL_HINTS = (
    "manifest unknown", "no such manifest", "manifest for ", " not found",
    "repository does not exist", "name unknown", "repository name not known",
    "pull access denied", "access to the resource is denied",
    "unauthorized: authentication required", "requested access to the resource is denied",
    "insufficient_scope", "image not found",
)

_account_pool = None  # set via set_account_pool(); rotated on a pull rate-limit


def set_account_pool(pool) -> None:
    global _account_pool
    _account_pool = pool


class DockerError(RuntimeError):
    pass


def _docker() -> str:
    exe = shutil.which("docker")
    if not exe:
        raise DockerError("docker CLI not found on PATH")
    return exe


def _run(argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run([_docker(), *argv], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise DockerError(f"docker {' '.join(argv[:2])}: {p.stderr.strip() or p.stdout.strip()}")
    return p


def daemon_ok() -> bool:
    try:
        return _run(["info", "--format", "{{.ServerVersion}}"], timeout=20).returncode == 0
    except (DockerError, subprocess.TimeoutExpired):
        return False


def ensure_network(name: str, subnet: str) -> None:
    if _run(["network", "inspect", name], timeout=15).returncode == 0:
        return
    p = _run(["network", "create", "--subnet", subnet, name], timeout=20)
    if p.returncode != 0 and "already exists" not in p.stderr.lower():
        # fall back to a default-subnet network rather than failing the whole run
        _run(["network", "create", name], timeout=20)


def pull(image: str, *, retries: int = 4, backoff: float = 30.0) -> None:
    # `retries` is per account; with a pool, a rate-limit triggers an immediate
    # rotation rather than a backoff, so the effective retry budget is larger.
    for attempt in range(retries):
        p = _run(["pull", "--quiet", image], timeout=180)
        if p.returncode == 0:
            return
        msg = (p.stderr + p.stdout).lower()
        rate_limited = any(h in msg for h in _RATE_LIMIT_HINTS)
        if not rate_limited and any(h in msg for h in _FATAL_PULL_HINTS):
            raise DockerError(f"pull {image}: {p.stderr.strip() or p.stdout.strip()}")
        if attempt == retries - 1:
            raise DockerError(f"pull {image} failed: {p.stderr.strip() or p.stdout.strip()}")
        if rate_limited and _account_pool is not None and len(_account_pool) > 1:
            who = _account_pool.rotate()
            log.warning("pull %s rate-limited; rotated to %s, retrying", image, who or "?")
            continue
        wait = backoff * (2 ** attempt) if rate_limited else min(15.0 * (attempt + 1), 60.0)
        log.warning("pull %s failed (try %d/%d), retrying in %.0fs", image, attempt + 1, retries, wait)
        time.sleep(wait)


def image_size_mb(image: str) -> float | None:
    p = _run(["image", "inspect", "-f", "{{.Size}}", image], timeout=20)
    if p.returncode != 0:
        return None
    try:
        return int(p.stdout.strip()) / (1024 * 1024)
    except ValueError:
        return None


def image_repo_digest(image: str) -> str:
    """The registry digest (`repo@sha256:...`) of the locally-pulled `image`.

    A moving tag like `:latest` resolves to a different image over time, so we
    record what we actually scanned. Returns "" if it can't be determined
    (e.g. the image was built locally and never pulled by digest)."""
    p = _run(["image", "inspect", "-f", "{{json .RepoDigests}}", image], timeout=20)
    if p.returncode != 0:
        return ""
    try:
        digests = json.loads(p.stdout.strip() or "[]") or []
    except (ValueError, TypeError):
        return ""
    if not digests:
        return ""
    repo = image.split("@", 1)[0].rsplit(":", 1)[0]
    for d in digests:
        if isinstance(d, str) and d.split("@", 1)[0] == repo:
            return d
    return digests[0] if isinstance(digests[0], str) else ""


def save(image: str, dest: str | Path) -> None:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    p = _run(["save", "-o", str(dest), image], timeout=3600)
    if p.returncode != 0:
        raise DockerError(f"save {image}: {p.stderr.strip()}")


def export_rootfs(image: str, dest_dir: str | Path) -> None:
    """Flatten an image to a directory: `docker create` + `docker export` piped
    into `tar -x`. Permission/device-node warnings on extraction are non-fatal."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    cp = _run(["create", image], timeout=120)
    if cp.returncode != 0:
        raise DockerError(f"create {image}: {cp.stderr.strip()}")
    cid = cp.stdout.strip()
    try:
        exp = subprocess.Popen([_docker(), "export", cid], stdout=subprocess.PIPE)
        tar = subprocess.Popen(
            ["tar", "-x", "-C", str(dest), "--no-same-owner", "--no-same-permissions",
             "--delay-directory-restore", "--warning=no-unknown-keyword"],
            stdin=exp.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        exp.stdout.close()
        tar.communicate(timeout=3600)
        exp.wait(timeout=10)
        if not any(dest.iterdir()):
            raise DockerError(f"export {image}: empty rootfs")
    finally:
        _run(["rm", "-f", cid], timeout=30)


def rm(name: str) -> None:
    _run(["rm", "-f", name], timeout=30)


def rm_image(image: str) -> None:
    _run(["image", "rm", "-f", image], timeout=120)


def login(user: str, token: str) -> bool:
    p = subprocess.run([_docker(), "login", "-u", user, "--password-stdin"],
                       input=token, capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        log.warning("docker login failed: %s", p.stderr.strip())
    return p.returncode == 0


def container_ip(name: str, network: str) -> str | None:
    p = _run(["inspect", "-f", "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}", name],
             timeout=15)
    ip = p.stdout.strip()
    return ip or None


def container_running(name: str) -> bool:
    p = _run(["inspect", "-f", "{{.State.Running}}", name], timeout=15)
    return p.stdout.strip() == "true"


def container_exit_code(name: str) -> int | None:
    p = _run(["inspect", "-f", "{{.State.ExitCode}}", name], timeout=15)
    try:
        return int(p.stdout.strip())
    except ValueError:
        return None


def logs_tail(name: str, lines: int = 40) -> str:
    return _run(["logs", "--tail", str(lines), name], timeout=15).stdout[-4000:]


def prune_images() -> None:
    _run(["image", "prune", "-f"], timeout=120)


@dataclass
class RunResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    wall_seconds: float
    peak_cpu_pct: float
    peak_mem_mb: float
    timed_out: bool = False


def run_monitored(image: str, argv: list[str], *, name: str, network: str | None = None,
                  user: str | None = None, entrypoint: str | None = None, workdir: str | None = None,
                  mounts: list[tuple[str, str, bool]] | None = None, env: dict[str, str] | None = None,
                  read_only: bool = False, mem_limit: str | None = None, pids_limit: int | None = None,
                  cpu_quota: int = 0, cap_drop_all: bool = False, no_new_privileges: bool = False,
                  detach: bool = False, timeout: float | None = None) -> RunResult:
    """`docker run --rm`, sampling CPU/RAM peaks while it runs. For one-shot
    scanner containers (detach=False)."""
    cmd = ["run", "--rm", "--name", name]
    if network:
        cmd += ["--network", network]
    if user:
        cmd += ["--user", user]
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    if workdir:
        cmd += ["--workdir", workdir]
    if read_only:
        cmd += ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"]
    if cap_drop_all:
        cmd += ["--cap-drop", "ALL"]
    if no_new_privileges:
        cmd += ["--security-opt", "no-new-privileges"]
    if mem_limit:
        cmd += ["--memory", mem_limit]
    if pids_limit:
        cmd += ["--pids-limit", str(pids_limit)]
    if cpu_quota and cpu_quota > 0:
        cmd += ["--cpu-quota", str(cpu_quota)]
    for src, dst, ro in (mounts or []):
        cmd += ["-v", f"{src}:{dst}{':ro' if ro else ''}"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [image, *argv]

    stop = threading.Event()
    peaks = {"cpu": 0.0, "mem": 0.0}

    def _sample():
        while not stop.wait(2.0):
            try:
                p = _run(["stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", name], timeout=20)
            except (subprocess.TimeoutExpired, OSError):
                continue                      # daemon busy — skip this tick, never crash the monitor
            if p.returncode != 0 or "|" not in p.stdout:
                continue
            cpu_s, mem_s = p.stdout.strip().split("|", 1)
            try:
                peaks["cpu"] = max(peaks["cpu"], float(cpu_s.strip().rstrip("%")))
            except ValueError:
                pass
            peaks["mem"] = max(peaks["mem"], _parse_mem(mem_s))

    mon = threading.Thread(target=_sample, daemon=True)
    t0 = time.time()
    mon.start()
    timed_out = False
    try:
        p = subprocess.run([_docker(), *cmd], capture_output=True, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc, out, err = 124, e.stdout or b"", (e.stderr or b"") + b"\n[timeout]"
        rm(name)
    finally:
        stop.set()
        mon.join(timeout=2)
    return RunResult(rc, out, err, time.time() - t0, peaks["cpu"], peaks["mem"], timed_out)


def run_detached(image: str, *, name: str, network: str, ip: str | None = None,
                 read_only: bool = False, mem_limit: str | None = None, pids_limit: int | None = None,
                 cpu_quota: int = 0, cap_drop_all: bool = False, no_new_privileges: bool = False) -> None:
    cmd = ["run", "-d", "--rm", "--name", name, "--network", network]
    if ip:
        cmd += ["--ip", ip]
    if read_only:
        cmd += ["--read-only", "--tmpfs", "/run:rw,noexec,nosuid", "--tmpfs", "/tmp:rw,noexec,nosuid",
                "--tmpfs", "/var/run:rw,noexec,nosuid"]
    if cap_drop_all:
        cmd += ["--cap-drop", "ALL"]
    if no_new_privileges:
        cmd += ["--security-opt", "no-new-privileges"]
    if mem_limit:
        cmd += ["--memory", mem_limit]
    if pids_limit:
        cmd += ["--pids-limit", str(pids_limit)]
    if cpu_quota and cpu_quota > 0:
        cmd += ["--cpu-quota", str(cpu_quota)]
    cmd += [image]
    p = _run(cmd, timeout=120)
    if p.returncode != 0:
        raise DockerError(f"run {image}: {p.stderr.strip() or p.stdout.strip()}")


def _parse_mem(s: str) -> float:
    """'12.5MiB / 1GiB' -> 12.5 (the used side, in MiB)."""
    used = s.split("/", 1)[0].strip().lower()
    units = {"b": 1 / (1024 * 1024), "kib": 1 / 1024, "kb": 1 / 1024, "mib": 1.0, "mb": 1.0,
             "gib": 1024.0, "gb": 1024.0, "tib": 1024 * 1024.0}
    for u, mul in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if used.endswith(u):
            try:
                return float(used[: -len(u)].strip()) * mul
            except ValueError:
                return 0.0
    return 0.0
