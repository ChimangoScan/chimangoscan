# Scanner registry

Every scanner is one pinned Docker image plus a recipe for how to invoke it and
where it writes. The registry lives in `config/scanners.yaml`; the run config
(`scanners.only` / `scanners.skip` / `--only` / `--skip`) decides which entries
actually run.

A scanner reads one of three things:

- **the saved image tar** (`{tarball}`) — the worker runs `docker save` once per
  target and mounts the tar read-only at `/work/image.tar`. The scanner never
  pulls from a registry, so it can't hit a rate limit and doesn't need a Docker
  daemon of its own. Set with `needs_tarball: true`.
- **the flattened image rootfs** (`{rootfs}`) — the worker runs `docker create`
  + `docker export | tar -x` once per target and mounts the directory read-only
  at `/scan`, then removes it after. Set with `needs_rootfs: true`.
- **a running container over HTTP** — only `mode: dynamic` scanners; the worker
  brings the target up hardened on an isolated bridge network and passes the
  scanner its URL / host / port. Gated by `needs: [http]` (at least one probed
  port speaks HTTP).

## What's in the registry

`enabled` is the registry default; `scanners.only` / `--only` overrides it
(and `scanners.skip` / `--skip` subtracts). `prepare` means the scanner needs
`scanners prepare` run once per host before it works (see below).

| scanner | image | mode | reads | keeps | enabled | prepare |
|---|---|---|---|---|---|---|
| `syft` | `anchore/syft` | static | `{tarball}` | `.syft.json` + `.cdx.json` (CycloneDX) + `.spdx.json` | yes | — |
| `trivy` | `aquasec/trivy` | static | `{tarball}` | `.trivy.json` (parsed) + `.trivy.cdx.json` (CycloneDX) + `.trivy.sarif` | yes | — |
| `grype` | `anchore/grype` | static | `{tarball}` | `.grype.json` (parsed) + `.grype.sarif` + `.grype.cdx.json` | yes | — |
| `osv` | `ghcr.io/google/osv-scanner` | static | `{tarball}` | `.osv.json` | yes | — |
| `dockle` | `goodwithtech/dockle` | static | `{tarball}` | `.dockle.json` | yes | — |
| `trufflehog` | `trufflesecurity/trufflehog` | static | `{tarball}` (via `file://`) | `.trufflehog.jsonl` (captured stdout) | yes | — |
| `clair` | `quay.io/projectquay/clair-action` | static | `{tarball}` | `.clair.json` (captured stdout) | no | yes — builds `matcher.db` (~1 GB) |
| `dependency-check` | `owasp/dependency-check` | static | `{rootfs}` | `dependency-check-report.json` + SARIF | no | yes — downloads the NVD feed (set `runtime.nvd_api_key` or NVD throttles hard) |
| `semgrep` | `semgrep/semgrep` | static | `{rootfs}` | `.semgrep.json` + `.semgrep.sarif` | no | — |
| `yara` | `blacktop/yara` | static | `{rootfs}` | `.yara.txt` (captured stdout) | no | yes — clones the rule set (`prepare_host`, see below) |
| `clamav` | `clamav/clamav` | static | `{rootfs}` | `.clamav.txt` (captured stdout) | no | — (ships its own signature DB) |
| `nuclei` | `projectdiscovery/nuclei` | dynamic, `needs: [http]` | running container | `.nuclei.jsonl` | yes | — |
| `nikto` | `ghcr.io/sullo/nikto` | dynamic, `needs: [http]` | running container | `.nikto.json` | yes | — |
| `zap` | `zaproxy/zap-stable` | dynamic, `needs: [http]` | running container | `.zap.json` | yes | — |
| `sqlmap` | `googlesky/sqlmap` | dynamic, `needs: [http]` | running container | session tree under `{out}` | no | — (targeted only; enable per run when an injection point is known) |

The default battery is the six enabled static scanners (`syft`, `trivy`,
`grype`, `osv`, `dockle`, `trufflehog`) plus the three enabled dynamic ones
(`nuclei`, `nikto`, `zap`). The dynamic phase as a whole is also gated by
`scanners.dynamic` (off with `--static-only`); the static phase by
`scanners.static` (off with `--dynamic-only`).

A few notes the registry comments call out:

- `osv` exits 1 when it finds vulnerabilities — `ok_exit_codes: [0, 1]` so a
  non-zero exit with output present still counts as success. Same for `semgrep`
  and `clamav` (`1` = infected file found).
- `trufflehog` fetches the image itself from `file://{tarball}`. If that proves
  unreliable on some images, switch its argv to `["docker", "--image",
  "{image}", "--json", "--no-update"]` and drop `needs_tarball`.
- `dependency-check` runs with `--noupdate` at scan time; the data has to be
  warmed first by `scanners prepare` (which runs it with `--updateonly`).

### `scanners prepare`

Run it once on every machine that will host workers. It warms the one-time
caches for the selected scanners and does nothing for the rest:

```bash
uv run scanners prepare                 # all enabled scanners that have a prepare step
uv run scanners prepare --only clair    # just one
```

Each prepared cache lives under `output.cache_dir/<needs_cache>` (default
`cache/<name>`) on the host and is mounted into the scanner container at
`cache_mount` (default `/cache`) every run. `clair`'s matcher DB and
`dependency-check`'s NVD data are built by running the scanner image with its
`prepare:` argv; `yara`'s rule set is cloned on the host by its `prepare_host:`
shell steps. `dependency-check` picks up `runtime.nvd_api_key` (passed in as
`NVD_API_KEY`) during prepare.

## Adding a scanner

Two parts: a registry entry and an adapter module.

### 1. The `config/scanners.yaml` entry

The key is the scanner name (also the default adapter module name and the
default cache subdir). `defaults:` at the top of the file is merged under every
entry (currently `user: "0:0"`, `pull: true`).

| field | meaning |
|---|---|
| `image` | the Docker image reference (pin a tag) — required |
| `mode` | `static` (runs against the image) or `dynamic` (runs against the running container) — required |
| `argv` | the command argv passed to the container, with `{...}` placeholders expanded at runtime |
| `extra_invocations` | a list of `{argv: [...]}` — additional runs of the same image/mounts (e.g. a second output format); their failures are logged, not fatal |
| `outputs` | filename templates, relative to `{out}`, that the adapter parses; their presence (non-empty) is also what "this scanner already ran" checks for |
| `capture_stdout` | filename template — the scanner writes to stdout instead of a file; the worker captures it to `{out}/<that name>` |
| `entrypoint` | `docker run --entrypoint` value (when you need to override the image's entrypoint) |
| `workdir` | `docker run --workdir` value |
| `out_as_workdir` | mount `{out}` at `workdir` instead of at `/out` (some tools only write into their cwd, e.g. ZAP's `/zap/wrk`) |
| `user` | `docker run --user` value (`0:0` lets a non-root image write the bind mount) |
| `needs_tarball` | mount the `docker save` tar at `{tarball}` (`/work/image.tar`) |
| `needs_rootfs` | mount the flattened image filesystem at `{rootfs}` (`/scan`) |
| `needs_cache` | name of a persistent cache subdir under `output.cache_dir`; mounted at `cache_mount` |
| `cache_mount` | where `needs_cache` is mounted inside the container (default `/cache`) |
| `env` | extra environment variables passed into the container |
| `ok_exit_codes` | exit codes treated as success (default `[0]`); other exits still count as `nonzero-ok` if the expected output exists |
| `timeout` | per-invocation seconds (overrides `workers.scan_timeout`) |
| `pull` | pre-pull this image before running (default `true`) |
| `enabled` | default on/off; `scanners.only/skip` still applies |
| `parser` | adapter module name under `scanners.adapters` (defaults to the entry key) |
| `prepare` | docker argv run once by `scanners prepare` to warm a cache (`{cache}` → `cache_mount`) |
| `prepare_host` | host shell commands run once by `scanners prepare` (`{cache}` → the host cache root) |
| `needs` | for `mode: dynamic`: capabilities the target must expose; `http` = at least one probed port speaks HTTP |

#### `{...}` placeholders

Expanded just before the container runs:

| placeholder | value |
|---|---|
| `{image}` | the target image reference (`repo:tag`) |
| `{tarball}` | path to the saved image tar inside the scanner container (`/work/image.tar`) — empty if the scanner didn't ask for it |
| `{rootfs}` | path to the flattened image rootfs inside the scanner container (`/scan`) — empty if not requested |
| `{url}` | `http(s)://host:port` of the running target (dynamic scanners) |
| `{host}` | bare host/IP of the running target |
| `{port}` | primary TCP port of the running target |
| `{out}` | the output directory inside the container (`/out`, or `workdir` if `out_as_workdir`) |
| `{name}` | the target slug (filesystem-safe, e.g. `library_nginx_1.12`) |
| `{cache}` | inside `argv`/`prepare`: the in-container `cache_mount`; inside `prepare_host`: the host cache root |

An unknown `{foo}` is left as-is.

### 2. The adapter

A module `src/scanners/adapters/<name>.py` exposing one function:

```python
def parse(out_dir: Path, target: Target) -> list[Finding]:
    ...
```

`out_dir` is `out/<slug>/<scanner>/` (where the scanner wrote its files);
`target` carries `.image`, `.name`, `.ip`, `.meta`. Helpers in
`adapters/base.py`:

- `read_json(path)` — parse a JSON file, returns `None` on missing/bad JSON.
- `read_jsonl(path)` — yield parsed objects from a JSON Lines file, skipping bad
  lines.
- `f(scanner, target, **kw)` — build a `Finding` with the target provenance
  (`target_image`, `target_name`, `target_ip`) already filled in; `kw` are the
  remaining `Finding` fields, with `category` and `severity` defaulting to
  `Category.OTHER` / `Severity.UNKNOWN`.
- `cves_in(s)` — pull `CVE-YYYY-NNNN` ids out of any string.
- `endpoint_of(url_or_host)` — `https://1.2.3.4:8443/x` → `1.2.3.4:8443`.

`Finding` (in `models.py`) is the normalized record. The fields you'll set most:
`category` (a `Category`), `severity` (a `Severity`), `id` (CVE / rule id / NVT
OID — the cross-scanner join key), `title`, `description`, `cvss`, `package`,
`version`, `fixed_version`, `ecosystem`, `location` (file path / layer / URL
path), `cves`, `references`, `endpoint` (host:port, for dynamic findings), and
`raw` — **the original record, untouched**, which survives into the merged
output. The provenance fields (`target_image`, `target_name`, `target_ip`,
`endpoint`) are what ties a finding back to its container.

`Category` values: `pkg-vuln` (CVE in an installed package), `secret`,
`image-config` (hardening / CIS / Dockerfile smell), `web-vuln` (a DAST finding
over HTTP), `network-vuln` (a network scanner NVT, e.g. OpenVAS),
`malware` (AV / YARA hit), `sbom-component` (an inventory entry, not a
finding), `other`.

`Severity` values (worst → least): `critical`, `high`, `medium`, `low`, `info`,
`unknown`. `Severity.parse(x)` maps loose vendor strings ("important",
"moderate", "warning", "negligible", …) onto these; `Severity.from_cvss(score)`
maps a 0–10 score onto them.

#### Worked example: `adapters/trivy.py`

```python
def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.trivy.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("Results") or []:
        loc = r.get("Target") or r.get("Class") or ""
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            res.append(f("trivy", t, category=Category.PKG_VULN,
                         severity=Severity.parse(v.get("Severity")),
                         id=vid, title=v.get("Title") or vid,
                         description=(v.get("Description") or "")[:1000],
                         cvss=_cvss(v), package=v.get("PkgName", ""),
                         version=v.get("InstalledVersion", ""),
                         fixed_version=v.get("FixedVersion", ""),
                         ecosystem=r.get("Type", ""),
                         location=v.get("PkgPath") or loc,
                         cves=cves_in(vid) or cves_in(v.get("References")),
                         references=list(v.get("References") or [])[:10], raw=v))
        # ...also r["Secrets"] -> Category.SECRET and r["Misconfigurations"] -> Category.IMAGE_CONFIG
    return res
```

It reads the one parsed output (`{name}.trivy.json` — the other two outputs are
kept for tooling but not parsed), walks Trivy's `Results`, and turns each
vulnerability / secret / misconfiguration into a `Finding` with `id` set to the
CVE so the merge step lines it up with `grype`, `osv`, `clair`, etc. Look at
`adapters/grype.py`, `adapters/osv.py`, and `adapters/clair.py` for the same
shape against other JSON layouts, and `adapters/nuclei.py` / `adapters/zap.py`
for dynamic findings that set `endpoint`.

The parser only runs when the invocation's status is `ok` / `nonzero-ok` /
`ok-cached`; a parser exception is logged and recorded on the invocation, it
doesn't kill the target.
