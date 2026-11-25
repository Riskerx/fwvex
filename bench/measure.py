"""Compare CVE matching: Zephyr's own `west spdx` output vs fwvex, on real builds.

Usage: python3 -I bench/measure.py <build_dir> [<build_dir> ...]
For each build: (a) every CPE in west spdx's SPDX files, queried in NVD exactly as written
(what a CPE-based scanner does); (b) `fwvex check` on the same build.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fwvex import nvd  # noqa: E402


def spdx_cpes(build: Path) -> dict[str, str]:
    """CPE -> package name, across all SPDX files of the build (and of sysbuild domains)."""
    out = {}
    files = list(build.glob("spdx/*.spdx")) + list(build.glob("*/spdx/*.spdx"))
    for f in files:
        pkg = None
        for line in f.read_text(errors="ignore").splitlines():
            if line.startswith("PackageName:"):
                pkg = line.split(":", 1)[1].strip()
            elif line.startswith("ExternalRef:") and "cpe23Type" in line:
                out[line.split()[3]] = pkg
    return out


def main():
    rows = []
    for b in map(Path, sys.argv[1:]):
        raw = {}
        for c, pkg in spdx_cpes(b).items():
            ids = {x["id"] for x in nvd.cves_for_cpe(c)}
            raw[f"{pkg} {c}"] = len(ids)
        raw_total = len({i for c in spdx_cpes(b) for i in (x["id"] for x in nvd.cves_for_cpe(c))})
        subprocess.run([sys.executable, "-m", "fwvex", "check", "-d", str(b), "--product", b.name],
                       cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True)
        sb = json.loads((b / "fwvex" / "sbom.cdx.json").read_text())
        v = sb.get("vulnerabilities", [])
        ids = {x["id"] for x in v}
        na_code = {x["id"] for x in v if x["analysis"].get("justification") == "code_not_present"}
        na_cfg = {x["id"] for x in v if x["analysis"].get("justification") == "requires_configuration"}
        review = ids - na_code - na_cfg
        rows.append(dict(build=b.name, west_spdx_cpes=raw, west_spdx_cves=raw_total, fwvex_cves=len(ids),
                         not_affected_code=len(na_code), not_affected_config=len(na_cfg), need_review=len(review)))
    print(json.dumps(rows, indent=1))


main()
