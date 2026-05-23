from __future__ import annotations
import importlib, json, re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..models import Category, Finding, Mode, Severity, Target

# A parser turns a scanner's output directory into normalized findings.
ParseFn = Callable[[Path, Target], list[Finding]]

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    image: str
    mode: Mode
    argv: list[str] = field(default_factory=list)
    entrypoint: str | None = None
    user: str | None = None
    workdir: str | None = None
    outputs: list[str] = field(default_factory=list)       # filename templates under {out}
    capture_stdout: str | None = None                      # filename template for stdout
    extra_invocations: list[dict] = field(default_factory=list)
    needs: tuple[str, ...] = ()                            # capabilities the target must expose
    needs_tarball: bool = False                            # mount the `docker save` tar (at {tarball})
    needs_rootfs: bool = False                             # mount the flattened image filesystem (at {rootfs})
    needs_cache: str | None = None                         # persistent cache subdir; mounted at `cache_mount`
    cache_mount: str = "/cache"
    env: dict[str, str] = field(default_factory=dict)      # extra env vars passed into the scanner container
    ok_exit_codes: tuple[int, ...] = (0,)
    out_as_workdir: bool = False                           # mount {out} as the workdir, not /out
    timeout: int | None = None
    pull: bool = True
    enabled: bool = True
    parser: str = ""                                       # adapter module name (defaults to `name`)
    prepare: list[str] = field(default_factory=list)       # one-time docker argv to warm a cache (DBs, feeds)
    prepare_host: list[str] = field(default_factory=list)  # one-time host shell commands ({cache} expanded)

    def render(self, ctx: dict[str, Any]) -> "RenderedSpec":
        return RenderedSpec(
            spec=self,
            argv=[_fmt(a, ctx) for a in self.argv],
            extra=[[_fmt(a, ctx) for a in inv["argv"]] for inv in self.extra_invocations],
            outputs=[_fmt(o, ctx) for o in self.outputs],
            capture_stdout=_fmt(self.capture_stdout, ctx) if self.capture_stdout else None,
        )

    def load_parser(self) -> ParseFn:
        mod = importlib.import_module(f"scanners.adapters.{self.parser or self.name}")
        fn = getattr(mod, "parse", None)
        if not callable(fn):
            raise TypeError(f"adapter '{self.parser or self.name}' has no parse()")
        return fn


@dataclass
class RenderedSpec:
    spec: ScannerSpec
    argv: list[str]
    extra: list[list[str]]
    outputs: list[str]
    capture_stdout: str | None


def _fmt(s: str, ctx: dict[str, Any]) -> str:
    return _PLACEHOLDER.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), s)


# ── helpers shared by adapter parsers ───────────────────────────────────────

def read_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def read_jsonl(p: Path):
    try:
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def endpoint_of(url_or_host: str) -> str:
    m = re.match(r"^\w+://([^/]+)", url_or_host or "")
    return m.group(1) if m else (url_or_host or "")


def cves_in(s: Any) -> list[str]:
    return re.findall(r"CVE-\d{4}-\d{4,7}", str(s or ""), re.I)


def f(scanner: str, target: Target, **kw) -> Finding:
    """Construct a Finding pre-filled with target provenance (incl. IP)."""
    cat = kw.pop("category", Category.OTHER)
    sev = kw.pop("severity", Severity.UNKNOWN)
    return Finding(scanner=scanner, category=cat, severity=sev,
                   target_image=target.image, target_name=target.name, target_ip=target.ip, **kw)
