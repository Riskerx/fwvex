"""Small NVD API 2.0 client: CVEs for a CPE at a given version, cached on disk.

Without an API key NVD allows 5 requests per 30 seconds; set NVD_API_KEY to raise that.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = Path(os.environ.get("FWVEX_CACHE", Path.home() / ".cache" / "fwvex")) / "nvd"
MAX_AGE_S = 24 * 3600
_last_call = 0.0


def _get(params: dict) -> dict:
    global _last_call
    url = API + "?" + urllib.parse.urlencode(params)
    CACHE.mkdir(parents=True, exist_ok=True)
    f = CACHE / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")
    if f.exists() and time.time() - f.stat().st_mtime < MAX_AGE_S:
        return json.loads(f.read_text())
    key = os.environ.get("NVD_API_KEY")
    wait = (0.7 if key else 6.5) - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    req = urllib.request.Request(url, headers={"User-Agent": "fwvex (open-source SBOM tool)",
                                               **({"apiKey": key} if key else {})})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            break
        except Exception:
            if attempt == 3:
                raise
            time.sleep(10 * (attempt + 1))
    _last_call = time.time()
    f.write_text(json.dumps(data))
    return data


def cves_for_cpe(cpe: str) -> list[dict]:
    """All CVEs whose configurations match this CPE (version included in the CPE)."""
    out, start = [], 0
    while True:
        d = _get({"virtualMatchString": cpe, "resultsPerPage": 2000, "startIndex": start})
        out += [v["cve"] for v in d.get("vulnerabilities", [])]
        start += d.get("resultsPerPage", 0)
        if start >= d.get("totalResults", 0) or not d.get("resultsPerPage"):
            return out


def summary(cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, severity = None, None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        m = cve.get("metrics", {}).get(k)
        if m:
            score = m[0]["cvssData"].get("baseScore")
            severity = m[0]["cvssData"].get("baseSeverity")
            break
    return {"id": cve["id"], "description": desc, "published": cve.get("published", "")[:10],
            "score": score, "severity": severity}
