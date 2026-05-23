from __future__ import annotations
import argparse, json, logging, shutil, subprocess, sys, time
from pathlib import Path

from .adapters.registry import load_registry, select
from .config import Config, ConfigError
from .findings.openvas_import import import_openvas
from .findings.store import CorpusStore
from .jobqueue import get_queue
from .models import Finding
from .report import render as render_html
from .findings.analysis import analyze as _analyze
from .sources import get_source

log = logging.getLogger("scanners")
_DEFAULT_CONFIG = "config/config.yaml"
_EXTRA_FINDINGS = "_corpus/openvas_extra.jsonl"


# ── shared setup ────────────────────────────────────────────────────────────

def _load_config(args) -> Config:
    path = args.config
    if path is None and Path(_DEFAULT_CONFIG).is_file():
        path = _DEFAULT_CONFIG
    cfg = Config.load(path)
    # CLI overrides (handy on remote workers that have no config file)
    if getattr(args, "queue_url", None):
        cfg.queue.backend = "http"; cfg.queue.url = args.queue_url
    if getattr(args, "queue_token", None):
        cfg.queue.token = args.queue_token
    if getattr(args, "workers", None):
        cfg.workers.count = args.workers
    if getattr(args, "out_dir", None):
        cfg.output.dir = args.out_dir
    if getattr(args, "cache_dir", None):
        cfg.output.cache_dir = args.cache_dir
    if getattr(args, "registry", None):
        cfg.scanners.registry = args.registry
    if getattr(args, "dockerhub_accounts", None):
        cfg.runtime.dockerhub_accounts = args.dockerhub_accounts
    if getattr(args, "scan_parallelism", None):
        cfg.runtime.scan_parallelism = args.scan_parallelism
    return cfg


def _registry(cfg: Config):
    return load_registry(cfg.path(cfg.scanners.registry))


def _setup_dockerhub_auth(cfg: Config, d) -> None:
    """Authenticated pulls dodge the anonymous rate limit. Prefer an account
    pool (rotated on rate-limit); fall back to a single user/token."""
    if cfg.runtime.dockerhub_accounts:
        from .dockerctl.auth import AccountPool
        try:
            pool = AccountPool(cfg.path(cfg.runtime.dockerhub_accounts))
        except (OSError, ValueError) as e:
            log.warning("dockerhub_accounts unusable (%s); pulling anonymously", e)
        else:
            pool.login_current()
            d.set_account_pool(pool)
            log.info("docker hub: %d-account pool, starting as %s", len(pool), pool.current)
            return
    if cfg.runtime.dockerhub_user and cfg.runtime.dockerhub_token:
        d.login(cfg.runtime.dockerhub_user, cfg.runtime.dockerhub_token)


def _selected_specs(cfg: Config):
    return select(_registry(cfg), only=cfg.scanners.only, skip=cfg.scanners.skip,
                  static=cfg.scanners.static, dynamic=cfg.scanners.dynamic)


# ── commands ────────────────────────────────────────────────────────────────

def cmd_seed(cfg: Config, args) -> int:
    if args.limit:
        cfg.source.limit = args.limit
    q = get_queue(cfg)
    batch, added, n_src = [], 0, 0
    BATCH = 5000  # small POSTs / inserts — seeding millions of rows must not buffer it all
    for t in get_source(cfg).iter_deduped():
        batch.append(t)
        n_src += 1
        if len(batch) >= BATCH:
            added += q.seed(batch)
            batch.clear()
            if n_src % 50_000 == 0:
                log.info("seeding… %d targets read, %d new so far", n_src, added)
    if batch:
        added += q.seed(batch)
    print(f"seeded {added} new target(s); {n_src} in source")
    return 0


def cmd_run(cfg: Config, args) -> int:
    from .dockerctl import client as d
    if not d.daemon_ok():
        print("error: docker daemon not reachable", file=sys.stderr)
        return 2
    _setup_dockerhub_auth(cfg, d)
    if args.only:
        cfg.scanners.only = [s.strip() for s in args.only.split(",") if s.strip()]
    if args.skip:
        cfg.scanners.skip = [s.strip() for s in args.skip.split(",") if s.strip()]
    if args.static_only:
        cfg.scanners.dynamic = False
    if args.dynamic_only:
        cfg.scanners.static = False
    specs = _selected_specs(cfg)
    if not specs:
        print("error: no scanners selected", file=sys.stderr)
        return 2
    log.info("scanners: %s  (parallelism=%d)", ", ".join(f"{s.name}({s.mode.value})" for s in specs), cfg.runtime.scan_parallelism)
    for s in specs:                                  # warm scanner images once, single-threaded
        if s.pull:
            try:
                d.pull(s.image, retries=cfg.runtime.pull_retries, backoff=cfg.runtime.pull_backoff)
            except d.DockerError as e:
                log.warning("could not pre-pull %s (%s); workers will retry", s.image, e)
    from .pipeline import run_workers
    run_workers(cfg, get_queue(cfg), specs, n_workers=cfg.workers.count, watch=args.watch)
    return 0


def cmd_coordinator(cfg: Config, args) -> int:
    from .jobqueue.server import serve
    bind = args.bind or cfg.queue.bind
    host, _, port = bind.partition(":")
    serve(str(cfg.queue_db), host or "0.0.0.0", int(port or 8900), cfg.queue.token)
    return 0


def cmd_status(cfg: Config, args) -> int:
    st = get_queue(cfg).stats()
    total = st.get("total", 0) or 1
    done = st.get("done", 0) + st.get("failed", 0) + st.get("skipped", 0)
    if args.json:
        print(json.dumps(st))
    else:
        print(f"{done}/{st.get('total', 0)} processed ({done / total * 100:.1f}%)  "
              f"pending={st.get('pending', 0)} running={st.get('running', 0)} done={st.get('done', 0)} "
              f"failed={st.get('failed', 0)} skipped={st.get('skipped', 0)}  "
              f"findings={st.get('findings', 0)}")
    return 0


def cmd_reset(cfg: Config, args) -> int:
    q = get_queue(cfg)
    n = 0
    if args.stale:
        n += q.reset_stale(cfg.workers.stale_minutes)
    if args.failed or args.skipped or args.done:
        n += q.reset(failed=args.failed, skipped=args.skipped, done=args.done)
    print(f"requeued {n} job(s)")
    return 0


def cmd_import_openvas(cfg: Config, args) -> int:
    src_path = args.path or cfg.imports.openvas
    if not src_path:
        print("error: nothing to import (pass --from PATH or set imports.openvas)", file=sys.stderr)
        return 2
    ip_map = {}
    try:
        for t in get_source(cfg).targets():
            if t.ip:
                ip_map[t.ip] = t
    except (ConfigError, OSError):
        pass
    findings = import_openvas(src_path, ip_map)
    out = cfg.out_dir / _EXTRA_FINDINGS
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(f.to_json()) + "\n" for f in findings))
    print(f"imported {len(findings)} OpenVAS finding(s) -> {out}")
    return 0


def _extra_findings(cfg: Config) -> list[Finding]:
    p = cfg.out_dir / _EXTRA_FINDINGS
    if not p.is_file():
        return []
    return [Finding.from_json(json.loads(l)) for l in p.read_text().splitlines() if l.strip()]


def cmd_prepare(cfg: Config, args) -> int:
    """Warm any one-time caches the selected scanners need (CVE DBs, rule sets).
    Run once per machine that will host workers."""
    import subprocess, shutil as _sh
    from .dockerctl import client as d
    if args.only:
        cfg.scanners.only = [s.strip() for s in args.only.split(",") if s.strip()]
    specs = [s for s in _selected_specs(cfg) if s.prepare or s.prepare_host]
    if not specs:
        print("nothing to prepare for the selected scanners"); return 0
    if not d.daemon_ok():
        print("error: docker daemon not reachable", file=sys.stderr); return 2
    _setup_dockerhub_auth(cfg, d)
    cache_root = cfg.cache_dir
    for s in specs:
        log.info("preparing %s", s.name)
        for raw in s.prepare_host:
            cmd = raw.replace("{cache}", str(cache_root))
            r = subprocess.run(cmd, shell=True)
            if r.returncode != 0:
                log.warning("%s prepare_host step failed: %s", s.name, cmd)
        if s.prepare:
            cdir = cache_root / (s.needs_cache or s.name)
            cdir.mkdir(parents=True, exist_ok=True)
            argv = [a.replace("{cache}", s.cache_mount) for a in s.prepare]
            cmd = ["docker", "run", "--rm", "-v", f"{cdir}:{s.cache_mount}"]
            if s.user:
                cmd += ["--user", s.user]
            if s.entrypoint:
                cmd += ["--entrypoint", s.entrypoint]
            if s.name == "dependency-check" and cfg.runtime.nvd_api_key:
                cmd += ["-e", f"NVD_API_KEY={cfg.runtime.nvd_api_key}"]
            cmd += [s.image, *argv]
            d.pull(s.image, retries=cfg.runtime.pull_retries, backoff=cfg.runtime.pull_backoff)
            r = subprocess.run(cmd)
            if r.returncode != 0:
                log.warning("%s prepare failed (exit %d)", s.name, r.returncode)
    print(f"prepared: {', '.join(s.name for s in specs)}")
    return 0


def cmd_report(cfg: Config, args) -> int:
    corpus = CorpusStore(cfg.out_dir).rebuild(_all_reports(cfg), _extra_findings(cfg))
    out_path = Path(args.out) if args.out else (cfg.out_dir / "report.html")
    render_html(corpus, out_path)
    s = corpus["summary"]
    print(f"{s['findings_merged']} merged findings, {s['targets']} targets -> {out_path}")
    return 0


def _all_reports(cfg: Config):
    """Yield per-target reports for the corpus rebuild — one at a time, so a
    GB-scale run doesn't load everything at once. Reads the SQLite queue file
    directly if it's on this machine (the HTTP /reports stream doesn't scale);
    else over HTTP; else the per-target report.json files on disk."""
    db = cfg.queue_db
    if db.is_file():
        from .jobqueue.sqlite_queue import SqliteQueue
        yield from SqliteQueue(db).iter_reports()
        return
    got = False
    try:
        for r in get_queue(cfg).iter_reports():
            got = True
            yield r
    except Exception:
        got = False
    if not got:
        for p in cfg.out_dir.glob("*/report.json"):
            try:
                yield json.loads(p.read_text())
            except (OSError, ValueError):
                pass


def cmd_analyze(cfg: Config, args) -> int:
    corpus = CorpusStore(cfg.out_dir).rebuild(_all_reports(cfg), _extra_findings(cfg))
    md = _analyze(corpus, top=args.top)
    out = Path(args.out) if args.out else (cfg.out_dir / "_corpus" / "analysis.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    tp = (corpus["summary"].get("throughput") or {})
    print(f"analysis -> {out}  ({corpus['summary'].get('findings_merged', 0)} findings, "
          f"{tp.get('targets_per_hour', '?')} containers/h)")
    return 0


def cmd_collect(cfg: Config, args) -> int:
    hosts = args.hosts or cfg.cluster.hosts
    if not hosts:
        print("error: no hosts (pass --hosts or set cluster.hosts)", file=sys.stderr)
        return 2
    rsync = shutil.which("rsync")
    if not rsync:
        print("error: rsync not found", file=sys.stderr); return 2
    local_out = cfg.out_dir
    local_out.mkdir(parents=True, exist_ok=True)
    for h in hosts:
        src = f"{h}:{cfg.cluster.remote_dir.rstrip('/')}/{cfg.output.dir}/"
        log.info("collecting %s", src)
        subprocess.run([rsync, "-az", "--ignore-existing", src, str(local_out) + "/"], check=False)
    return 0


def cmd_cluster(cfg: Config, args) -> int:
    hosts = cfg.cluster.hosts
    if not hosts:
        print("error: cluster.hosts is empty in the config", file=sys.stderr)
        return 2
    port = int(cfg.queue.bind.partition(":")[2] or 8900)
    sel = ""
    if args.only:
        sel += f" --only {args.only}"
    if args.skip:
        sel += f" --skip {args.skip}"
    if args.static_only:
        sel += " --static-only"
    if args.dynamic_only:
        sel += " --dynamic-only"
    if args.action == "up":
        acc_flag = ""
        if cfg.runtime.dockerhub_accounts:
            src = cfg.path(cfg.runtime.dockerhub_accounts)
            for h in hosts:
                subprocess.run(["scp", "-q", str(src), f"{h}:{cfg.cluster.remote_dir}/accounts.json"], check=False)
            acc_flag = " --dockerhub-accounts accounts.json"
        _cluster_dispatch(cfg, hosts, port,
                          f"run --workers {cfg.cluster.workers_per_host} "
                          f"--queue-url http://localhost:{port}{_token(cfg)}{acc_flag}{sel}", tunnel=True)
    elif args.action == "prepare":
        _cluster_dispatch(cfg, hosts, port, f"prepare{sel}", tunnel=False, foreground=True)
    elif args.action == "down":
        for h in hosts:
            subprocess.run(["ssh", h, "pkill -f 'scanners run' || true"], check=False)
            print(f"{h}: workers stopped")
        subprocess.run(["pkill", "-f", f"-R {port}:localhost:{port}"], check=False)
    elif args.action == "status":
        for h in hosts:
            r = subprocess.run(["ssh", h, "pgrep -af 'scanners (run|prepare)' || true"],
                               capture_output=True, text=True)
            print(f"{h}: {r.stdout.strip() or '(idle)'}")
    return 0


def _token(cfg: Config) -> str:
    return f" --queue-token {cfg.queue.token}" if cfg.queue.token else ""


def _cluster_dispatch(cfg: Config, hosts: list[str], port: int, sub_cmd: str, *,
                      tunnel: bool, foreground: bool = False) -> None:
    if tunnel:
        import urllib.request
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3).read()
        except Exception:
            print(f"warning: no coordinator on 127.0.0.1:{port} — start `scanners coordinator` first")
    rsync = shutil.which("rsync") or "rsync"
    runner = "uv run scanners" if cfg.cluster.use_uv else "python -m scanners"
    setup = ('command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh; '
             'export PATH="$HOME/.local/bin:$PATH"; uv sync --quiet') if cfg.cluster.use_uv else 'true'
    rd = cfg.cluster.remote_dir
    for h in hosts:
        print(f"{h}: syncing repo -> {rd}")
        subprocess.run([rsync, "-az", "--delete", "--exclude", ".git", "--exclude", cfg.output.dir + "/",
                        "--exclude", "work/", "--exclude", "cache/", "--exclude", "*.db",
                        "--exclude", "config/config.yaml", f"{cfg.root}/", f"{h}:{rd}/"], check=True)
        if tunnel and cfg.cluster.reverse_tunnel:
            subprocess.run(["ssh", "-fNT", "-R", f"{port}:localhost:{port}", h], check=False)
        if foreground:
            inner = f"cd {rd} && {setup} && {runner} {sub_cmd} -v"
            subprocess.run(["ssh", h, "bash", "-lc", inner])
        else:
            inner = (f"cd {rd} && {setup} && nohup {runner} {sub_cmd} -v "
                     f"> scanners-{sub_cmd.split()[0]}.log 2>&1 < /dev/null & echo started pid $!")
            r = subprocess.run(["ssh", h, "bash", "-lc", inner], capture_output=True, text=True)
            print(f"{h}: {r.stdout.strip() or r.stderr.strip()}")


# ── argparse ────────────────────────────────────────────────────────────────

def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", help=f"path to run config (default: {_DEFAULT_CONFIG} if present)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--queue-url", help="override queue backend to this HTTP coordinator")
    p.add_argument("--queue-token", help="bearer token for the coordinator")
    p.add_argument("--out-dir", help="override output directory")
    p.add_argument("--cache-dir", help="override cache directory")
    p.add_argument("--registry", help="override scanner registry path")
    p.add_argument("--dockerhub-accounts", help="path to a JSON account pool for authenticated pulls")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="scanners", description="distributed container scanning pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("seed", help="load targets from the configured source into the queue")
    _common(p); p.add_argument("--limit", type=int, default=0); p.set_defaults(fn=cmd_seed)

    p = sub.add_parser("run", help="drain the queue with a pool of workers on this machine")
    _common(p)
    p.add_argument("--workers", type=int)
    p.add_argument("--watch", action="store_true", help="keep waiting for new work instead of exiting on empty queue")
    p.add_argument("--only", help="comma-separated scanner names to run (overrides config)")
    p.add_argument("--skip", help="comma-separated scanner names to exclude")
    p.add_argument("--static-only", action="store_true", help="skip the dynamic phase")
    p.add_argument("--dynamic-only", action="store_true", help="skip the static phase")
    p.add_argument("--scan-parallelism", type=int, help="scanners run concurrently per target")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("prepare", help="warm one-time caches (CVE DBs, rule sets) for the selected scanners")
    _common(p); p.add_argument("--only", help="comma-separated scanner names"); p.set_defaults(fn=cmd_prepare)

    p = sub.add_parser("coordinator", help="serve the work queue over HTTP for many workers")
    _common(p); p.add_argument("--bind", help="host:port (default: queue.bind)"); p.set_defaults(fn=cmd_coordinator)

    p = sub.add_parser("status", help="show queue progress"); _common(p)
    p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_status)

    p = sub.add_parser("reset", help="requeue failed / skipped / stale jobs"); _common(p)
    p.add_argument("--failed", action="store_true"); p.add_argument("--skipped", action="store_true")
    p.add_argument("--done", action="store_true", help="requeue completed targets (e.g. to re-run a newly-added scanner)")
    p.add_argument("--stale", action="store_true"); p.set_defaults(fn=cmd_reset)

    p = sub.add_parser("import-openvas", help="fold an existing OpenVAS run into the merged view")
    _common(p); p.add_argument("--from", dest="path", help="dir of reports or a *_completo.csv")
    p.set_defaults(fn=cmd_import_openvas)

    p = sub.add_parser("report", help="rebuild the corpus aggregates and render the HTML report")
    _common(p); p.add_argument("-o", "--out", dest="out", help="HTML output path"); p.set_defaults(fn=cmd_report)

    p = sub.add_parser("analyze", help="cross-scanner statistics (overlap, exclusivity, cost) -> analysis.md")
    _common(p); p.add_argument("-o", "--out", dest="out"); p.add_argument("--top", type=int, default=20)
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("collect", help="rsync raw artifacts from cluster hosts to the local output dir")
    _common(p); p.add_argument("--hosts", nargs="*"); p.set_defaults(fn=cmd_collect)

    p = sub.add_parser("cluster", help="rsync + run workers / prepare on the configured remote hosts")
    _common(p)
    p.add_argument("action", choices=["up", "prepare", "down", "status"])
    p.add_argument("--only"); p.add_argument("--skip")
    p.add_argument("--static-only", action="store_true"); p.add_argument("--dynamic-only", action="store_true")
    p.set_defaults(fn=cmd_cluster)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose >= 2 else logging.INFO if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S")
    if not args.verbose:
        logging.getLogger("scanners.docker").setLevel(logging.WARNING)
    try:
        cfg = _load_config(args)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    try:
        return args.fn(cfg, args)
    except KeyboardInterrupt:
        return 130
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
