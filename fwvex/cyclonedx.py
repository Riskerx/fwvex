"""Write a CycloneDX 1.6 SBOM (and optional VEX entries) for scanned Zephyr images."""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import uuid
from pathlib import Path

from . import __version__
from .build import Image, Module
from .identify import cpe, normalize_cpe, purl_from_remote, read_version, upstream_purl

# Zephyr subsystems reported as sub-components, by source-path prefix (longest match wins).
SUBSYSTEMS = [
    "subsys/bluetooth/host", "subsys/bluetooth/controller", "subsys/bluetooth/mesh", "subsys/bluetooth/audio",
    "subsys/bluetooth/services", "subsys/bluetooth/common", "subsys/bluetooth/crypto", "subsys/bluetooth",
    "subsys/net/ip", "subsys/net/l2", "subsys/net/lib/sockets", "subsys/net/lib/lwm2m", "subsys/net/lib/mqtt",
    "subsys/net/lib/coap", "subsys/net/lib/dns", "subsys/net/lib/http", "subsys/net/lib/dhcpv4",
    "subsys/net/lib", "subsys/net", "subsys/usb", "subsys/mgmt/mcumgr", "subsys/mgmt", "subsys/fs",
    "subsys/shell", "subsys/settings", "subsys/storage", "subsys/dfu", "subsys/logging", "subsys/random",
    "subsys/canbus", "subsys/modem", "subsys/ipc", "subsys/pm", "subsys/tracing", "subsys/debug", "subsys/console",
    "subsys/secure_storage", "subsys/jwt", "subsys",
    "kernel", "arch", "soc", "boards", "drivers", "lib/libc", "lib/os", "lib/posix", "lib/crc", "lib/heap", "lib",
]


def _subsystem(rel: str) -> str:
    for s in SUBSYSTEMS:
        if rel == s or rel.startswith(s + "/"):
            if s in ("drivers", "subsys/net/lib", "subsys", "lib"):  # one level deeper is more useful
                parts = rel.split("/")
                depth = s.count("/") + 2
                return "/".join(parts[:depth]) if len(parts) > depth else s
            return s
    return rel.split("/", 1)[0]


def _sha256(p: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _tag(rev: str | None) -> str | None:
    """A release-like revision (v3.4.2, ncs-v3.4.2, TF-Mv2.3.1), not a bare commit hash."""
    if not rev or re.fullmatch(r"[0-9a-f]{7,40}(-dirty)?", rev):
        return None
    return rev


def module_component(img: Image, m: Module) -> dict:
    version = m.version or read_version(m.name, m.path)
    ref = f"{img.name}:{m.name}"
    yml_cpe = next((r for r in m.ext_refs if r.startswith("cpe:")), None)
    yml_purl = next((r for r in m.ext_refs if r.startswith("pkg:")), None)
    if not version and yml_cpe:
        v = yml_cpe.split(":")[5]
        version = v if v not in ("*", "-", "") else None
    comp = {"type": "operating-system" if m.kind in ("zephyr", "esp-idf") else "library", "bom-ref": ref, "name": m.name,
            "version": version or _tag(m.west_revision) or _tag(m.git_describe) or m.git_rev or "unknown"}
    c = (m.cpes[0] if m.cpes else None) or yml_cpe or cpe(m.name, version)
    if c:
        comp["cpe"] = normalize_cpe(c)
    p = purl_from_remote(m.git_url, m.git_rev)  # the exact repository and commit built
    up = m.purl or yml_purl or upstream_purl(m.name, version)  # the upstream release it corresponds to
    if up and version:
        comp["purl"] = up
    elif p:
        comp["purl"] = p
    ext = []
    if m.git_url:
        ext.append({"type": "vcs", "url": m.git_url})
    if ext:
        comp["externalReferences"] = ext
    props = [{"name": "fwvex:compiled_files", "value": str(len(m.files))}]
    if m.not_linked:
        props.append({"name": "fwvex:compiled_not_linked", "value": str(m.not_linked)})
    if m.git_rev:
        props.append({"name": "fwvex:git_commit", "value": m.git_rev})
    if m.west_revision:
        props.append({"name": "fwvex:west_revision", "value": m.west_revision})
    if p and comp.get("purl") != p:
        props.append({"name": "fwvex:source_purl", "value": p})
    for alt in m.cpes[1:]:
        props.append({"name": "fwvex:alt_cpe", "value": normalize_cpe(alt)})
    for cve, why in sorted(m.cve_excludes.items()):
        props.append({"name": "fwvex:vendor_fixed_cve", "value": f"{cve}: {why}".strip(": ")})
    comp["properties"] = props
    # Sub-components: Zephyr subsystems / ESP-IDF components that were compiled in.
    groups: dict[str, int] = {}
    for f in m.files:
        if m.kind == "zephyr":
            g = _subsystem(f)
        elif m.kind == "esp-idf":
            parts = f.split("/")
            g = "/".join(parts[:2]) if parts[0] == "components" and len(parts) > 2 else parts[0]
        else:
            g = f.split("/", 1)[0]
        groups[g] = groups.get(g, 0) + 1
    if m.kind in ("zephyr", "esp-idf"):
        comp["components"] = [{"type": "library", "bom-ref": f"{ref}:{g}", "name": f"{m.name}/{g}",
                               "version": comp["version"],
                               "properties": [{"name": "fwvex:compiled_files", "value": str(n)}]}
                              for g, n in sorted(groups.items())]
    return comp


def _rel_blob(img: Image, b) -> str:
    """Blob path relative to the module that provides it, so SBOMs do not leak local directories."""
    m = img.modules.get(b.owner)
    if m is not None:
        try:
            return f"{b.owner}/" + b.path.resolve().relative_to(m.path.resolve()).as_posix()
        except ValueError:
            pass
    return b.path.name


def image_components(img: Image) -> list[dict]:
    comps = [module_component(img, m) for m in sorted(img.modules.values(), key=lambda m: (m.name != "zephyr", m.name))]
    owner_version = {c["name"]: c["version"] for c in comps}
    for b in img.blobs:
        h = _sha256(b.path)
        comps.append({"type": "library", "bom-ref": f"{img.name}:blob:{b.path.name}", "name": b.path.name,
                      "version": b.version or (f"{b.owner} {owner_version[b.owner]}" if b.owner in owner_version
                                                else "unknown"), "hashes": [{"alg": "SHA-256", "content": h}] if h else [],
                      "description": "Prebuilt binary library linked into the firmware (no source in the build).",
                      "properties": [{"name": "fwvex:prebuilt", "value": "true"},
                                     {"name": "fwvex:blob_path", "value": _rel_blob(img, b)},
                                     {"name": "fwvex:provided_by_module", "value": b.owner}]})
    return comps


def bom(images: list[Image], product: str | None, product_version: str | None,
        vulnerabilities: list[dict] | None = None) -> dict:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    main = images[0]
    top = {"type": "firmware", "bom-ref": "product", "name": product or main.name,
           "version": product_version or "unversioned"}
    props = []
    for img in images:
        props.append({"name": f"fwvex:image:{img.name}:board", "value": img.board or "unknown"})
        if img.elf:
            h = _sha256(img.elf)
            if h:
                props.append({"name": f"fwvex:image:{img.name}:elf_sha256", "value": h})
    top["properties"] = props
    components, deps = [], []
    for img in images:
        ic = image_components(img)
        img_ref = f"image:{img.name}"
        components.append({"type": "firmware", "bom-ref": img_ref, "name": img.name, "version": top["version"],
                           "components": ic})
        deps.append({"ref": img_ref, "dependsOn": [c["bom-ref"] for c in ic]})
    deps.insert(0, {"ref": "product", "dependsOn": [f"image:{i.name}" for i in images]})
    out = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": now, "tools": {"components": [{"type": "application", "name": "fwvex",
                                                                    "version": __version__}]},
                        "component": top},
           "components": components, "dependencies": deps}
    if vulnerabilities:
        out["vulnerabilities"] = vulnerabilities
    return out


def iter_components(b: dict):
    stack = list(b.get("components", []))
    while stack:
        c = stack.pop()
        yield c
        stack.extend(c.get("components", []))
