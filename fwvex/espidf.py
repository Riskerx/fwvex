"""Read an ESP-IDF build directory (idf.py build) and work out what went into the firmware.

Evidence used:
- build/project_description.json: IDF path, target, project, and the components linked in
- build/compile_commands.json (and build/bootloader/...): every compiled source file
- build/build.ninja: the final link line, for prebuilt libraries (Wi-Fi, PHY, BT controller blobs)
- sdkconfig: the resolved Kconfig
- ESP-IDF's own SBOM metadata: `sbom*.yml` manifests and `sbom-*` entries in .gitmodules,
  which give upstream versions, CPEs and Espressif's list of CVEs it has already fixed
- managed_components/*/idf_component.yml for components from the component registry
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .build import Image, Module, _collect, _git, _git_url

ROOT_FILE = "project_description.json"


def _project_description(build: Path) -> Path | None:
    for p in (build / ROOT_FILE, build / "build" / ROOT_FILE):
        if p.is_file():
            return p
    return None


def is_espidf_build(build: Path) -> bool:
    p = _project_description(Path(build))
    if not p:
        return False
    try:
        return "idf_path" in json.loads(p.read_text())
    except (OSError, ValueError):
        return False


def _mini_yaml(text: str) -> dict:
    """Enough YAML for ESP-IDF sbom manifests: scalars, lists of scalars, and lists of small maps."""
    out: dict = {}
    key = None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and not raw.startswith((" ", "\t")):
            key, val = m.group(1), m.group(2).strip().strip("'\"")
            out[key] = val if val else []
            continue
        m = re.match(r"^\s+-\s+([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and key is not None:
            out.setdefault(key, [])
            if isinstance(out[key], list):
                out[key].append({m.group(1): m.group(2).strip().strip("'\"")})
            continue
        m = re.match(r"^\s+([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and key is not None and isinstance(out.get(key), list) and out[key] and isinstance(out[key][-1], dict):
            out[key][-1][m.group(1)] = m.group(2).strip().strip("'\"")
            continue
        m = re.match(r"^\s+-\s+(.*)$", line)
        if m and key is not None:
            if not isinstance(out.get(key), list):
                out[key] = []
            out[key].append(m.group(1).strip().strip("'\""))
    return out


def _as_list(v) -> list:
    return v if isinstance(v, list) else ([v] if v else [])


def _fmt_cpes(cpes, version: str | None) -> list[str]:
    out = []
    for c in _as_list(cpes):
        if isinstance(c, str) and c.startswith("cpe:"):
            out.append(c.replace("{}", version or "*"))
    return out


def _excludes(v) -> dict[str, str]:
    out = {}
    for e in _as_list(v):
        if isinstance(e, dict) and e.get("cve"):
            out[e["cve"]] = e.get("reason", "")
    return out


def _manifest_packages(idf: Path, kconfig: dict[str, str]) -> list[Module]:
    """Third-party packages that ESP-IDF itself describes (sbom*.yml and .gitmodules sbom-* entries)."""
    pkgs: list[Module] = []
    for f in sorted((idf / "components").rglob("sbom*.yml")):
        if f.name != "sbom.yml":
            continue  # sbom_<x>.yml files are virtual packages, pulled in via `virtpackages`
        y = _mini_yaml(f.read_text(errors="ignore"))
        entries = [y]
        if y.get("virtpackages"):  # e.g. newlib: newlibc or picolibc, chosen by Kconfig
            picolibc = kconfig.get("CONFIG_LIBC_PICOLIBC") == "y"
            entries = []
            for v in _as_list(y["virtpackages"]):
                if ("picolibc" in v) == picolibc and (f.parent / v).is_file():
                    entries.append(_mini_yaml((f.parent / v).read_text(errors="ignore")))
        for e in entries:
            version = e.get("version") or None
            name = e.get("name") or f.parent.name
            cpes = _fmt_cpes(e.get("cpe"), version)
            if not (version or cpes):
                continue
            pkgs.append(Module(name, f.parent.resolve(), version=version, cpes=cpes,
                               cve_excludes=_excludes(e.get("cve-exclude-list"))))
    gm = idf / ".gitmodules"
    if gm.exists():
        for sect in re.split(r"(?m)^\[submodule ", gm.read_text(errors="ignore"))[1:]:
            path = re.search(r"^\s*path\s*=\s*(\S+)", sect, re.M)
            ver = re.search(r"^\s*sbom-version\s*=\s*(\S+)", sect, re.M)
            if not path or not ver:
                continue
            p = (idf / path.group(1)).resolve()
            if any(m.path == p for m in pkgs):
                continue
            version = ver.group(1)
            cpes = [c.replace("{}", version) for c in re.findall(r"^\s*sbom-cpe\s*=\s*(\S+)", sect, re.M)]
            url = re.search(r"^\s*sbom-url\s*=\s*(\S+)", sect, re.M)
            pkgs.append(Module(p.name, p, version=version, cpes=cpes, git_url=url.group(1) if url else None))
    return pkgs


def _managed_components(project: Path) -> list[Module]:
    out = []
    mc = project / "managed_components"
    if mc.is_dir():
        for d in sorted(p for p in mc.iterdir() if p.is_dir()):
            y = _mini_yaml((d / "idf_component.yml").read_text(errors="ignore")) if (d / "idf_component.yml").exists() else {}
            ns_name = d.name.replace("__", "/")
            version = y.get("version") or None
            out.append(Module(ns_name, d.resolve(), version=version,
                              purl=f"pkg:generic/{ns_name}" + (f"@{version}" if version else "") +
                                   "?repository_url=https://components.espressif.com"))
    return out


def _kconfig(path: Path) -> dict[str, str]:
    out = {}
    if path.is_file():
        for line in path.read_text(errors="ignore").splitlines():
            m = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", line)
            if m:
                out[m.group(1)] = m.group(2).strip('"')
    return out


def _idf_version(idf: Path) -> str | None:
    f = idf / "tools" / "cmake" / "version.cmake"
    if not f.exists():
        return None
    t = f.read_text(errors="ignore")
    parts = [re.search(rf"IDF_VERSION_{k}\s+(\d+)", t) for k in ("MAJOR", "MINOR", "PATCH")]
    return ".".join(p.group(1) for p in parts) if all(parts) else None


def _image(pd_path: Path, name: str, elf_name: str, kconfig: dict[str, str], extra: list[Module]) -> Image:
    pd = json.loads(pd_path.read_text())
    idf = Path(pd["idf_path"]).resolve()
    build = pd_path.parent.resolve()
    project = Path(pd.get("project_path", build.parent)).resolve()
    idf_ver = _idf_version(idf)
    mods: dict[str, Module] = {"esp-idf": Module("esp-idf", idf, kind="esp-idf", version=idf_ver,
                                                 cpes=[f"cpe:2.3:a:espressif:esp-idf:{idf_ver}:*:*:*:*:*:*:*"] if idf_ver else [],
                                                 purl=f"pkg:github/espressif/esp-idf@v{idf_ver}" if idf_ver else None)}
    for m in _manifest_packages(idf, kconfig) + extra:
        mods[m.name] = Module(**{k: getattr(m, k) for k in m.__dataclass_fields__ if k != "files"})
    roots = [(n, m.path) for n, m in mods.items()]
    if idf != project and idf not in project.parents:  # the bootloader's "project" lives inside ESP-IDF
        roots.append(("__app__", project))
    roots.sort(key=lambda x: -len(str(x[1])))  # deepest first: managed components before the project
    app_files, other, blobs = _collect(build, build, roots, mods, re.escape(elf_name),
                                       build / (Path(elf_name).stem + ".map"))
    used = {n: m for n, m in mods.items() if m.files or n == "esp-idf" or any(b.owner == n for b in blobs)}
    for m in used.values():
        m.git_rev = _git(m.path, "rev-parse", "HEAD")
        m.git_url = m.git_url or _git_url(m.path)
        m.git_describe = _git(m.path, "describe", "--tags", "--always", "--dirty")
        m.files.sort()
    elf = build / elf_name
    return Image(name, build, pd.get("target"), idf, project, kconfig, used, app_files, other, blobs,
                 elf if elf.exists() else None, framework="esp-idf",
                 components_built={c for c in pd.get("build_components", []) if c},
                 components_known=set(pd.get("all_component_info", {})) | {c for c in pd.get("build_components", []) if c})


def scan(build: Path) -> list[Image]:
    pd_path = _project_description(Path(build))
    pd = json.loads(pd_path.read_text())
    kconfig = _kconfig(Path(pd.get("config_file", "")))
    project = Path(pd.get("project_path", pd_path.parent.parent)).resolve()
    extra = _managed_components(project)
    images = [_image(pd_path, pd.get("project_name", "app"), Path(pd.get("app_elf", "app.elf")).name, kconfig, extra)]
    boot = pd_path.parent / "bootloader" / ROOT_FILE
    if boot.is_file():
        images.append(_image(boot, f"{images[0].name}/bootloader", "bootloader.elf", kconfig, []))
    return images
