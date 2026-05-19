#!/usr/bin/env python3
"""
Fill the placeholder tokens in main.tex with the per-repository numbers
recomputed by recount_repo.py. Reads the regenerated JSONs and substitutes
every TOKEN -> value. Idempotent only on a fresh main.tex with tokens present.
"""
import json, os, re, sys

OUT = "/mnt/win_ssd/chimangoscan-paper"
TEX = os.path.join(OUT, "main.tex")


def J(name):
    return json.load(open(os.path.join(OUT, name)))


def gp(n):                       # grouped int, LaTeX thin space
    return "{:,}".format(int(round(n))).replace(",", "{,}")


def mil(n, d=1):                 # millions, d decimals
    return f"{n/1e6:.{d}f}"


dedup = J("dedup_analysis.json")
plan = J("plan_analysis.json")
paper = J("paper_analysis.json")
rich = J("rich_analysis.json")
extra = J("extra_analysis.json")
repro = J("repro_analysis.json")
oc = J("fig_official_vs_community_stats.json")
step3 = J("step3_recompute.json")
stats = J("analyze_db.stats.json")

prev = dedup["prevalence"]
vpi = dedup["vulns_per_image"]
sevf = dedup["sev_global_pkgvuln"]      # pkg-vuln findings by severity
sevi = dedup["sev_images"]
ft = dedup["findings_total"]
psf = dedup["per_scanner_findings"]
pss = dedup["per_scanner_severity"]
sbs = dedup["status_by_scanner"]

N = dedup["n_distinct_images"]          # = 50453, the unit count
# distinct digests = rows - duplicate rows; recount prints it
DIST_DIGESTS = None
for line in open(os.path.join(OUT, "recount_repo.log")):
    m = re.search(r"distinct digests\s*:\s*(\d+)", line)
    if m:
        DIST_DIGESTS = int(m.group(1))
if DIST_DIGESTS is None:
    sys.exit("could not find distinct-digest count in recount_repo.log")

pkgf_total = ft["pkg_vuln"]
merged_total = ft["all_merged"]

# ---- run-success rates per scanner ----
def runok(sc):
    st = sbs.get(sc, {})
    tot = sum(st.values())
    ok = st.get("ok", 0) + st.get("ok-cached", 0) + st.get("nonzero-ok", 0)
    return 100.0 * ok / tot if tot else 0.0


# ---- n1 marginal ----
n1 = plan["n1"]
single = n1["single_scanner_union"]
uniq = n1["unique_contribution"]
pairu = n1["pair_union"]
marg = n1["marginal_avg_pct"]
tg = n1["total_distinct_groups"]

# ---- venn ----
v = extra["venn"]
venn_single = v["trivy_only"] + v["grype_only"] + v["osv_only"]
venn_two = v["trivy_grype"] + v["trivy_osv"] + v["grype_osv"]
venn_three = v["all3"]

# ---- all-vs-distinct (afig2) ----
a2 = plan["afig2_ctab4"]
sall = a2["sev_all_findings"]
sdist = a2["sev_distinct_groups"]
SEVO = ["critical", "high", "medium", "low", "info", "unknown"]

# ---- n5 (where scanners disagree) ----
n5s = plan["n5"]["by_severity"]
n5e = plan["n5"]["by_ecosystem_class"]

# ---- n7 (severity disagreement) ----
n7 = plan["n7"]
conf = n7["confusion"]


def pair(a, b):
    return conf.get(f"{a}|{b}", 0) + conf.get(f"{b}|{a}", 0)


# ---- exposure deciles ----
dec = plan["afig1_n4"]["exposure_deciles"]
dec_meds = sorted(d["median_vuln"] for d in dec)
corpus_med = dec_meds[len(dec_meds) // 2]
top_dec_med = dec[-1]["median_vuln"]

# ---- reach / propagation ----
reach = plan["n3"]["top_cve_by_exposure"]
prop = plan["n2"]["top_cve_propagation"]

# ---- top packages ----
pkgtab = rich["pkg_table"]

# ---- repro ----
liu = repro["liu"]
wist = repro["wist"]
dahl = repro["dahl"]
wist_eco = wist["sev_findings_by_eco_class"]
wist_tot = sum(wist_eco.values())
wist_lang = dict(wist["sev_findings_top_lang_eco"])

# CVE by year (recent share)
cy = paper["cve_distinct_by_year"]
cy_tot = sum(cy.values())
cy_recent = sum(c for y, c in cy.items() if int(y) >= 2020)

# temporal
young = old = covp = None
temporal = J("temporal_analysis.json")
pairs = temporal["pairs"]
yv = sorted(nv for ad, nv in pairs if ad < 365)
ov = sorted(nv for ad, nv in pairs if ad >= 365)
young = yv[len(yv) // 2]
old = ov[len(ov) // 2]
covp = temporal["coverage_pct"]

# Shu worst-severity panel (most_severe)
ms = paper["most_severe"]
ms_tot = sum(ms.values())


def sevname(s):
    return {"critical": "Crit.", "high": "High", "medium": "Med.",
            "low": "Low", "info": "Info", "unknown": "Unrated"}[s]


# severity table package-vuln (Table tab:severity) uses pkg-vuln findings
def sev_row(s):
    f = sevf.get(s, 0)
    n = sevi.get(s, 0)
    return f, 100.0 * f / pkgf_total, n, 100.0 * n / N


# ===== build the replacement map =====
R = {}

# --- abstract / intro ---
R["ABMERGEDM"] = mil(merged_total)
R["ABVULN"] = f"{prev['with_vuln_pct']:.1f}"
R["ABCRIT"] = f"{prev['with_critical_pct']:.1f}"
R["ABMISC"] = f"{prev['with_misconfig_pct']:.1f}"
R["ABSINGLE"] = f"{100.0*venn_single/tg:.1f}"
R["ABALL3"] = f"{100.0*venn_three/tg:.1f}"

# --- dataset table ---
R["DTDISTINCT"] = gp(DIST_DIGESTS)
R["DTCVES"] = gp(dedup["n_distinct_cves"])
R["DTMERGEDTOT"] = gp(merged_total)
R["DTPKGF"] = gp(ft["pkg_vuln"])
R["DTPKGS"] = f"{100.0*ft['pkg_vuln']/merged_total:.1f}\\%"
R["DTPKGI"] = f"{prev['with_vuln_pct']:.1f}\\%"
R["DTSBOMF"] = gp(ft["sbom_component"])
R["DTSBOMS"] = f"{100.0*ft['sbom_component']/merged_total:.1f}\\%"
# software-inventory image coverage: images with >=1 component
cpi = stats.get("components_per_image", [])
n_with_comp = sum(1 for c in cpi if c > 0)
R["DTSBOMI"] = f"{100.0*n_with_comp/N:.1f}\\%"
R["DTSECF"] = gp(ft["secret"])
R["DTSECS"] = f"{100.0*ft['secret']/merged_total:.1f}\\%"
R["DTSECI"] = f"{prev['with_secret_pct']:.1f}\\%"
R["DTMISCF"] = gp(ft["misconfig"])
R["DTMISCS"] = f"{100.0*ft['misconfig']/merged_total:.1f}\\%"
R["DTMISCI"] = f"{prev['with_misconfig_pct']:.1f}\\%"

# --- unit-of-measurement paragraph ---
R["FALSEDDIST"] = gp(DIST_DIGESTS)
R["AVTMERGEDTOT"] = gp(merged_total)
R["AVTPKGM"] = mil(ft["pkg_vuln"])
R["AVTSBOMM"] = mil(ft["sbom_component"])
R["AVTSECM"] = mil(ft["secret"])
R["AVTMISCM"] = mil(ft["misconfig"], 2)

# --- prevalence section ---
R["PVVULN"] = f"{prev['with_vuln_pct']:.1f}"
R["PVCLEAN"] = f"{100.0-prev['with_vuln_pct']:.1f}"
R["PVCRIT"] = f"{prev['with_critical_pct']:.1f}"
R["PVHIGH"] = f"{prev['with_high_pct']:.1f}"
R["PVMED"] = gp(vpi["median"])
R["PVMEAN"] = gp(vpi["mean"])
R["PVP90"] = gp(vpi["p90"])
R["PVP99"] = gp(vpi["p99"])
R["PVMAX"] = gp(vpi["max"])
R["PVPKGM"] = mil(pkgf_total)
crit_f, crit_fp, crit_n, crit_np = sev_row("critical")
high_f, high_fp, high_n, high_np = sev_row("high")
R["PVCRITPCT"] = f"{crit_fp:.1f}"
R["PVHIGHPCT"] = f"{high_fp:.1f}"
R["PVCHM"] = mil(crit_f + high_f)
R["PVCRITN"] = gp(crit_n)
R["PVHIGHN"] = gp(high_n)

# --- severity table ---
for s, pre in [("critical", "SVC"), ("high", "SVH"), ("medium", "SVM"),
               ("low", "SVL"), ("info", "SVI"), ("unknown", "SVU")]:
    f, fp, n, np_ = sev_row(s)
    R[pre + "F"] = gp(f)
    R[pre + "FP"] = f"{fp:.1f}\\%"
    R[pre + "N"] = gp(n)
    R[pre + "NP"] = f"{np_:.1f}\\%"
R["SVTOTF"] = gp(pkgf_total)
R["SVTOTN"] = gp(prev["n_with_vuln"])
R["SVTOTNP"] = f"{prev['with_vuln_pct']:.1f}\\%"

# --- per-scanner ---
R["PSGRPM"] = mil(psf["grype"])
R["PSTRVM"] = mil(psf["trivy"])
R["PSOSVM"] = mil(psf["osv"])
R["PSSYFM"] = mil(psf["syft"])
R["PSTRFM"] = mil(psf["trufflehog"])
R["PSDCKM"] = mil(psf["dockle"], 2)
for sc, pre in [("syft", "PSSYF"), ("trivy", "PSTRV"), ("grype", "PSGRP"),
                ("osv", "PSOSV"), ("dockle", "PSDCK"),
                ("trufflehog", "PSTRF")]:
    R[pre + "F"] = gp(psf[sc])
    sv = pss.get(sc, {})
    R[pre + "C"] = gp(sv.get("critical", 0)) if sv.get("critical") else "0"
    R[pre + "H"] = gp(sv.get("high", 0)) if sv.get("high") else "0"
    R[pre + "MED"] = gp(sv.get("medium", 0)) if sv.get("medium") else "0"
    R[pre + "L"] = gp(sv.get("low", 0)) if sv.get("low") else "0"
for sc, pre in [("syft", "PSRELSYF"), ("trivy", "PSRELTRV"),
                ("grype", "PSRELGRP"), ("osv", "PSRELOSV"),
                ("dockle", "PSRELDCK"), ("trufflehog", "PSRELTRF")]:
    R[pre] = f"{runok(sc):.1f}"
R["PSERRTRV"] = gp(sbs["trivy"].get("error", 0))

# --- inventory ---
cpi_s = sorted(cpi)
R["CICMED"] = gp(cpi_s[len(cpi_s) // 2])
R["CICMEAN"] = gp(sum(cpi_s) / len(cpi_s))
R["CICMAX"] = gp(cpi_s[-1])
eco = stats.get("ecosystem_count", {})
eco_tot = sum(eco.values())
R["CIECONPM"] = f"{100.0*eco.get('npm',0)/eco_tot:.1f}"
R["CIECODEB"] = f"{100.0*eco.get('deb',0)/eco_tot:.1f}"

# --- divergence ---
R["DGTOTAL"] = mil(tg)
R["DGSINGLE"] = f"{100.0*venn_single/tg:.1f}"
R["DGTWO"] = f"{100.0*venn_two/tg:.1f}"
R["DGTHREE"] = f"{100.0*venn_three/tg:.1f}"
R["DGGT"] = mil(v["trivy_grype"])
R["DGGO"] = mil(v["grype_osv"])
R["DGOT"] = mil(v["trivy_osv"])
spread = max(psf["grype"], psf["trivy"], psf["osv"]) / \
    min(psf["grype"], psf["trivy"], psf["osv"])
R["DGSPREAD"] = f"{spread:.2f}"

# --- marginal table ---
R["MGBEST1"] = f"{n1['best1_pct']:.1f}"
R["MGBEST2"] = f"{n1['best2_pct']:.1f}"
R["MGM1"] = f"{marg[0]:.1f}"
R["MGM2"] = f"{marg[1]:.1f}"
R["MGM3"] = f"{marg[2]:.1f}"
R["MGUG"] = mil(uniq["grype"])
R["MGUT"] = mil(uniq["trivy"])
R["MGUO"] = mil(uniq["osv"])
R["MGTOTNUM"] = gp(tg)
for sc, pre in [("grype", "MGGRP"), ("trivy", "MGTRV"), ("osv", "MGOSV")]:
    R[pre + "N"] = gp(single[sc])
    R[pre + "P"] = f"{100.0*single[sc]/tg:.1f}\\%"
    R[pre + "U"] = gp(uniq[sc])
R["MGGTN"] = gp(pairu["trivy+grype"])
R["MGGTP"] = f"{100.0*pairu['trivy+grype']/tg:.1f}\\%"
R["MGGON"] = gp(pairu["grype+osv"])
R["MGGOP"] = f"{100.0*pairu['grype+osv']/tg:.1f}\\%"
R["MGTON"] = gp(pairu["trivy+osv"])
R["MGTOP"] = f"{100.0*pairu['trivy+osv']/tg:.1f}\\%"
R["MGALL3U"] = gp(n1["setcount_by_mask"].get("7", 0))

# --- all-vs-distinct (Wist) ---
R["AVTALLF"] = mil(pkgf_total)
R["AVTREDALL"] = f"{pkgf_total/tg:.2f}"
red = {}
for s, pre in [("critical", "AVTC"), ("high", "AVTH"), ("medium", "AVTM"),
               ("low", "AVTL"), ("info", "AVTI"), ("unknown", "AVTU")]:
    af = sall.get(s, 0)
    df = sdist.get(s, 0)
    r = af / df if df else 0.0
    red[s] = r
    R[pre + "F"] = gp(af)
    R[pre + "D"] = gp(df)
    R[pre + "R"] = f"{r:.2f}"
R["AVTREDC"] = f"{red['critical']:.2f}"
R["AVTREDH"] = f"{red['high']:.2f}"
R["AVTREDI"] = f"{red['info']:.2f}"
R["AVTTOTF"] = gp(pkgf_total)
R["AVTTOTD"] = gp(tg)

# --- where scanners disagree (n5) ---
R["WSCRITP"] = f"{n5s['critical']['single_pct']:.1f}"
R["WSINFOP"] = f"{n5s['info']['single_pct']:.1f}"
R["WSOSP"] = f"{n5e['os']['single_pct']:.1f}"
R["WSLANGP"] = f"{n5e['lang']['single_pct']:.1f}"
R["WSLANG3P"] = f"{n5e['lang']['three_pct']:.1f}"

# --- severity disagreement (n7) ---
R["DSCODETM"] = mil(n7["total_codetections"])
R["DSMISMP"] = f"{n7['mismatch_pct']:.1f}"
R["DSMHM"] = mil(pair("medium", "high"), 2)
R["DSLIM"] = mil(pair("low", "info"), 2)
R["DSLHM"] = mil(pair("low", "high"), 2)
R["DSCHM"] = mil(pair("critical", "high"), 2)

# --- official vs community ---
o = oc["OFFICIAL"]
c = oc["COMMUNITY"]
R["OCNTOTAL"] = gp(N)
R["OCNOFF"] = gp(o["n_images"])
R["OCNCOM"] = gp(c["n_images"])
R["OCMEDOFF"] = gp(o["median"])
R["OCMEDCOM"] = gp(c["median"])
R["OCMEANOFF"] = gp(o["mean"])
R["OCMEANCOM"] = gp(c["mean"])
ratio = c["median"] / o["median"] if o["median"] else 0
R["OCRATIO"] = (f"{ratio:.1f} times" if abs(ratio - round(ratio)) > 0.15
                else ("twice" if round(ratio) == 2
                      else f"{int(round(ratio))} times"))
R["OCSECOFF"] = f"{100.0*o['secret_frac']:.1f}"
R["OCSECCOM"] = f"{100.0*c['secret_frac']:.1f}"
# above corpus median
ocd = extra["offcomm"]
allv = ocd["official_vulns"] + ocd["community_vulns"]
allv_s = sorted(allv)
cmed = allv_s[len(allv_s) // 2]
above_off = 100.0 * sum(1 for x in ocd["official_vulns"]
                        if x > cmed) / len(ocd["official_vulns"])
above_com = 100.0 * sum(1 for x in ocd["community_vulns"]
                        if x > cmed) / len(ocd["community_vulns"])
R["OCABOVEOFF"] = f"{above_off:.1f}"
R["OCABOVECOM"] = f"{above_com:.1f}"

# --- secrets / misconfig ---
R["SCMISCP"] = f"{prev['with_misconfig_pct']:.1f}"
R["SCMISCN"] = gp(prev["n_with_misconfig"])
R["SCSECP"] = f"{prev['with_secret_pct']:.1f}"
R["SCSECN"] = gp(prev["n_with_secret"])
R["SCSECM"] = mil(ft["secret"])
# Dockle FATAL = critical findings
R["SCFATALN"] = gp(pss.get("dockle", {}).get("critical", 0))
# misconfig table by check
mt = stats.get("misconfig_title", {})


def misc_count(substr):
    tot = 0
    for k, vv in mt.items():
        if substr.lower() in k.lower():
            tot += vv
    return tot


# secrets per image distribution
secscatter = J("plan_scatter.json")
sec_off = sorted(secscatter["sec_off"])
sec_com = sorted(secscatter["sec_com"])
sec_all2 = sorted(secscatter["sec_off"] + secscatter["sec_com"])
R["SCSECMED"] = gp(sec_all2[len(sec_all2) // 2])
R["SCSECP99"] = gp(sec_all2[min(len(sec_all2) - 1,
                                99 * len(sec_all2) // 100)])
R["SCSECMAX"] = gp(sec_all2[-1])
R["SCOFFMAX"] = gp(sec_off[-1] if sec_off else 0)

# CIS-DI credential check count
R["SCCREDN"] = gp(misc_count("CIS-DI-0010"))

# --- misconfig table ---
mc_checks = [("MC0005", "CIS-DI-0005"), ("MC0006", "CIS-DI-0006"),
             ("MC0001", "CIS-DI-0001"), ("MC0008", "CIS-DI-0008"),
             ("MC0004", "CIS-DI-0004"), ("MC0010", "CIS-DI-0010"),
             ("MC0009", "CIS-DI-0009")]
for pre, code in mc_checks:
    n = misc_count(code)
    R[pre + "N"] = gp(n)
    R[pre + "P"] = f"{100.0*n/N:.1f}\\%"

# --- exposure deciles ---
R["EXRHOPULL"] = f"{plan['afig1_n4']['rho_pull_vs_vuln']:+.2f}"
R["EXRHOEXP"] = f"{plan['afig1_n4']['rho_exposure_vs_vuln']:+.2f}"
R["EXRHOEXPC"] = f"{plan['afig1_n4']['rho_exposure_vs_critical']:+.2f}"
R["EXMEDCORPUS"] = gp(corpus_med)
R["EXMEDTOP"] = gp(top_dec_med)

# --- reach table ---
SEVLBL = {"critical": "Crit.", "high": "High", "medium": "Med.",
          "low": "Low", "info": "Info", "unknown": "Unr."}
for i, row in enumerate(reach[:8], start=1):
    R[f"RCH{i}"] = (f"{row['cve']} & \\texttt{{{row['package']}}} & "
                    f"{SEVLBL.get(row['severity'],'Unr.')} & "
                    f"{gp(row['affected_images'])} & "
                    f"{row['pct_total_exposure']:.1f}\\%")
R["RCHTOPEXP"] = f"{reach[0]['pct_total_exposure']:.1f}"
R["RCHTOPIMG"] = f"{reach[0]['pct_corpus']:.1f}"

# --- propagation table ---
for i, row in enumerate(prop[:8], start=1):
    R[f"PROP{i}"] = (f"{row['cve']} & \\texttt{{{row['package']}}} & "
                     f"{gp(row['direct_images'])} & "
                     f"{gp(row['downstream_images'])} & "
                     f"{int(round(row['propagation_factor']))}")
prop_factors = [row["propagation_factor"] for row in prop[:8]]
R["PROPMIN"] = str(int(min(prop_factors) // 50 * 50))
R["PROPMAX"] = str(int(round(max(prop_factors))))

# --- top-package table ---
for i, row in enumerate(pkgtab[:10], start=1):
    R[f"TPK{i}"] = (f"\\texttt{{{row['package']}}} & "
                    f"{gp(row['images'])} & "
                    f"{100.0*row['images']/N:.1f}\\% & "
                    f"{gp(row['findings'])} & "
                    f"{row['distinct_cves']} & "
                    f"{gp(row['critical_images'])}")

# --- repro section ---
R["RPCRITP"] = f"{100.0*ms.get('critical',0)/ms_tot:.1f}"
R["RPHIGHP"] = f"{100.0*ms.get('high',0)/ms_tot:.1f}"
R["RPRECENTP"] = f"{100.0*cy_recent/cy_tot:.1f}"
# top packages by image count: zlib, openssl
pkg_by_img = {row["package"]: row["images"] for row in pkgtab}
R["RPZLIBN"] = gp(pkg_by_img.get("zlib", 0))
R["RPOSSLN"] = gp(pkg_by_img.get("openssl", 0))
R["RPLIUCOMP"] = f"{liu['community_hc_pct']:.1f}"
R["RPLIUOFFP"] = f"{liu['official_hc_pct']:.1f}"
R["RPWISTOSP"] = f"{100.0*wist_eco.get('os',0)/wist_tot:.1f}"
R["RPWISTLANGP"] = f"{100.0*wist_eco.get('lang',0)/wist_tot:.1f}"
go = wist_lang.get("go", 0) + wist_lang.get("go-module", 0) + \
    wist_lang.get("gobinary", 0) + wist_lang.get("golang", 0)
npm = wist_lang.get("npm", 0) + wist_lang.get("node-pkg", 0)
py = wist_lang.get("pypi", 0) + wist_lang.get("python", 0) + \
    wist_lang.get("python-pkg", 0)
R["RPWISTGO"] = mil(go)
R["RPWISTNPM"] = mil(npm)
R["RPWISTPY"] = mil(py)
R["RPMILLSYOUNG"] = gp(young)
R["RPMILLSOLD"] = gp(old)
R["RPMILLSCOVP"] = f"{covp:.1f}"
R["RPDAHLPKP"] = f"{dahl['img_with_private_key_pct']:.1f}"
R["RPDAHLPKN"] = gp(dahl["img_with_private_key"])

# ===== apply =====
tex = open(TEX).read()
# longest tokens first to avoid prefix collisions
missing = []
for tok in sorted(R, key=len, reverse=True):
    val = R[tok]
    if val is None:
        missing.append(tok)
        continue
    pat = r"\b" + re.escape(tok) + r"\b"
    if not re.search(pat, tex):
        sys.stderr.write(f"warn: token {tok} not found in tex\n")
    tex = re.sub(pat, lambda m, v=str(val): v, tex)

if missing:
    sys.exit("missing values for: " + ", ".join(missing))

# check no leftover tokens
leftover = re.findall(
    r"\b(?:AB|PV|SV|PS|DG|MG|AVT|CIC|CIECO|SC[A-Z]|MC0|OC[A-Z]|WS|DS|EX[A-Z]"
    r"|RCH|PROP|DT[A-Z]|RP[A-Z]|TPK)[A-Z0-9]*\b", tex)
leftover = [x for x in leftover if x not in ("SCADA",)]
if leftover:
    sys.stderr.write("LEFTOVER TOKENS: " + ", ".join(sorted(set(leftover)))
                     + "\n")

open(TEX, "w").write(tex)
print("applied %d substitutions; %d leftover" % (len(R), len(set(leftover))))
