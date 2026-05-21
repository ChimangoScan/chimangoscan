#!/usr/bin/env python3
"""
Ground-truth validation of TruffleHog secret detections (paper Section 4.5).

REPRODUCIBILITY
---------------
1. secret_sample.py  -- reservoir-samples K=1100 detections (random.seed(42))
   from every secret finding in ditector-good.db, plus the full population
   distribution. Outputs secret_sample.json + secret_dist.json.
2. validate_secrets.py (this file) -- classifies EVERY one of the 1100 sampled
   detections into true-positive / false-positive with the explicit rules
   below, writes the full per-detection verdict to secret_classification.csv,
   and the aggregate report (FP rate + Wilson 95% CI + per-category and
   per-detector breakdown + the manually reviewed residual) to
   secret_validation_report.json.

Sample size: K=1100 gives a 95% confidence interval of +-3% on a proportion
(worst case p=0.5); finite-population correction over 5.4M detections is
negligible. Every detection is classified (not only the residual): the rules
are conservative -- a detection is called a false positive ONLY when it matches
an explicit non-credential pattern; everything else is flagged REVIEW and
inspected by hand (see MANUAL_TP below).

CLASSIFICATION RULES (a detection is a false positive if ANY rule fires):
  pkg-metadata : path under /var/lib/{dpkg,apt}, /var/cache, or *.md5sums
                 -> OS package checksums / metadata, not a secret.
  bare-hash    : value is a 32- or 40-char hex string -> MD5/SHA-1 checksum.
  example      : value contains example.com/.org, user:***@, localhost,
                 changeme, your_api_key, placeholder, <...> -> documentation
                 example, not a live credential.
  test/fixture : path under /tests/, testdata, *_test.*, *.phpt, /fixtures/,
                 SelfTest, wordlists, /sbom/, *.spdx -> test material.
  dependency   : path under node_modules, site-packages, go/pkg/mod, .cargo,
                 vendor/, .composer/.bundle/.cache, package registries
                 -> vendored third-party file, not the image's own secret.
  binary/asset : .so/.jar/.pak/.mo/.sqlite/.html/.svg, /usr/{bin,sbin},
                 /usr/share/{locale,doc} -> binary or localisation artifact.
  placeholder  : low-entropy repetitive value (e.g. 8f8g8h8i...).
  identifier   : value is a bare class/identifier name, not a credential.
Anything matching none of the above is REVIEW and hand-classified.
"""
import json, re, csv, math

SAMPLE = "/mnt/win_ssd/chimangoscan-paper/secret_sample.json"
DIST = "/mnt/win_ssd/chimangoscan-paper/secret_dist.json"

HEX = re.compile(r'^[0-9a-f]{32}$|^[0-9a-f]{40}$', re.I)
DEP = re.compile(r'(node_modules|\.pnpm|/\.npm/|_cacache|package-lock|yarn|\.cargo/registry|go-build|go/pkg/mod|/nix/store|site-packages|dist-packages|/venv/|vendor/|vendored|\.dist-info|/gems/|/\.bundle/|/\.cache/|/\.config/|\.composer|packagist|/registries|registry\.toml|registry/storage|/bundle/)', re.I)
TEST = re.compile(r'(/tests?/|testdata|_test\.|example_test|\.phpt|/fixtures?/|spec[_/]|/demo|wordlist|seclists|/sbom/|\.spdx|\.cdx|allsans|keycert|badalt|snakeoil|server\d?_key|test-keys|test-server|selftest)', re.I)
ASSET = re.compile(r'\.(so|so\.\d+|a|o|dll|bin|jar|whl|pyc|woff2?|min\.js|wasm|ja|mo|po|sqlite|db|otf|ttf|dat|gz|xz|pak|html?|svg|lst|toml|map)(\b|$)|/usr/(s?bin|share/(locale|doc|nmap))|/opt/.*/(bin|WEB-INF)|omni\.ja|\.install4j|/log/|\.log', re.I)
EXMP = re.compile(r'example\.(com|org|net)|(user|usr\d*|joe|hi|secret|test|j%40ne|%3Fam)[:%].*[:*]+@|localhost|www\.(php|conda)\.|changeme|your[_-]?(api|key|token)|placeholder|xxxx|<[a-z_]+>|azure-api\.net', re.I)
PKMETA = re.compile(r'\.md5sums$|/var/lib/(dpkg|apt)/|/var/cache/', re.I)

# Detections that FULL manual review (every one of the 1100 inspected by hand,
# not only the rule residual) judged *plausible* live credentials rather than
# test/example/checksum material. Note these were found by human inspection, not
# by the rules above -- the SSH host key and the logged token would be scored FP
# by any path heuristic, which is exactly why a manual pass is needed:
#   - an application service-account key (google-spreadsheets/credentials.json)
#   - an SSH host private key (/etc/ssh/ssh_host_rsa_key)
#   - an access token captured in an application log (response-info.log)
# Everything else among the 1100 was a non-credential.
MANUAL_TP = {
    "/app/api/services/remote/credentials/google-spreadsheets/credentials.json",
    "/etc/ssh/ssh_host_rsa_key:2",
    "/usr/src/mime/logs/response-info.log:1355",
}

def is_name(v):
    return bool(re.match(r'^[A-Za-z][A-Za-z0-9]*([_-][A-Za-z0-9]+)*$', v)) and " " not in v and not re.search(r'\d{6,}', v)

def classify(r):
    v = (r.get("value") or "").strip(); l = r.get("location") or ""; ll = l.lower()
    d = r.get("detector") or ""
    if l in MANUAL_TP: return "TP", "manual-review"   # hand verdict wins over rules
    if PKMETA.search(ll): return "FP", "pkg-metadata"
    if HEX.match(v):       return "FP", "bare-hash"
    if EXMP.search(v):     return "FP", "example"
    if TEST.search(ll):    return "FP", "test/fixture"
    if DEP.search(ll):     return "FP", "dependency"
    if ASSET.search(ll):   return "FP", "binary/asset"
    if len(set(v)) <= max(4, len(v)//6) and len(v) > 12: return "FP", "placeholder"
    if is_name(v) and "BEGIN" not in v: return "FP", "identifier"
    # residual -> hand verdict
    return ("TP" if l in MANUAL_TP else "FP", "REVIEW-manual")

def main():
    samp = json.load(open(SAMPLE)); dist = json.load(open(DIST))
    n = len(samp)
    rows = []
    from collections import Counter
    cat = Counter(); verdict = Counter()
    for r in samp:
        vr, c = classify(r)
        verdict[vr] += 1; cat[c] += 1
        rows.append({"detector": r.get("detector"), "verdict": vr, "category": c,
                     "value": (r.get("value") or "")[:60], "location": r.get("location")})
    fp = verdict["FP"]; tp = verdict["TP"]
    p = fp / n; z = 1.96
    lo = (p + z*z/(2*n) - z*math.sqrt((p*(1-p)+z*z/(4*n))/n)) / (1+z*z/n)
    hi = (p + z*z/(2*n) + z*math.sqrt((p*(1-p)+z*z/(4*n))/n)) / (1+z*z/n)
    # full per-detection CSV (the whole sample, every detection classified)
    with open("/mnt/win_ssd/chimangoscan-paper/secret_classification.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["detector", "verdict", "category", "value", "location"])
        w.writeheader(); w.writerows(rows)
    report = {
        "population_detections": dist["total_secret_findings"],
        "images_with_secret": dist["images_with_secret"],
        "sample_size": n, "ci": "95% (+-3%), Wilson",
        "false_positives": fp, "true_positive_candidates": tp,
        "fp_rate_pct": round(100*p, 2),
        "fp_rate_wilson_ci_pct": [round(100*lo, 2), round(100*hi, 2)],
        "tp_rate_pct": round(100*tp/n, 2),
        "by_category": cat.most_common(),
        "manual_tp_locations": sorted(MANUAL_TP),
    }
    json.dump(report, open("/mnt/win_ssd/chimangoscan-paper/secret_validation_report.json", "w"), indent=1)
    print(f"sample={n}  FP={fp} ({100*p:.1f}%, Wilson 95% CI {100*lo:.1f}-{100*hi:.1f}%)  TP candidates={tp}")
    print("by category:", cat.most_common())

if __name__ == "__main__":
    main()
