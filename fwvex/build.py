"""Read a Zephyr build directory and work out what actually went into the firmware.

Evidence used (all produced by a normal `west build`):
- CMakeCache.txt: ZEPHYR_BASE, BOARD, application source dir
- zephyr_modules.txt: name and path of every Zephyr module in the workspace
- compile_commands.json: every source file compiled into this image
- build.ninja: the final link line, to find prebuilt libraries (binary blobs)
- zephyr/.config: the resolved Kconfig
Sysbuild builds (domains.yaml) are handled by scanning each domain's build directory.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Module:
    name: str
    path: Path
    files: list[str] = field(default_factory=list)  # compiled files, relative to module path
    git_url: str | None = None
    git_rev: str | None = None
    git_describe: str | None = None
    ext_refs: list[str] = field(default_factory=list)  # CPE/PURL from the module's zephyr/module.yml
    west_revision: str | None = None  # revision in the west manifest (often a release tag)
    kind: str = ""  # "zephyr" / "esp-idf": framework whose files are grouped into sub-components
    version: str | None = None  # known version (from a manifest), overrides other sources
    cpes: list[str] = field(default_factory=list)  # first is primary; the rest are other NVD names
    purl: str | None = None
    cve_excludes: dict[str, str] = field(default_factory=dict)  # CVE -> vendor's reason (fixed/patched)
    not_linked: int = 0  # files compiled for this module that the linker dropped (map file evidence)


@dataclass
class Blob:
    path: Path
    owner: str  # module name, or "unknown"
    sha256: str | None = None

    @property
    def version(self) -> str | None:
        m = re.search(r"_v?(\d+\.\d+(?:\.\d+)*)\.a$", self.path.name)  # e.g. liboberon_3.0.20.a
        return m.group(1) if m else None


@dataclass
class Image:
    name: str  # domain name ("app", "mcuboot", ...) or the app dir name
    build_dir: Path
    board: str | None
    zephyr_base: Path
    app_dir: Path | None
    kconfig: dict[str, str]
    modules: dict[str, Module]  # includes "zephyr" itself
    app_files: list[str]
    other_files: list[str]
    blobs: list[Blob]
    elf: Path | None
    framework: str = "zephyr"
    components_built: set[str] = field(default_factory=set)  # ESP-IDF: components linked into this image
    components_known: set[str] = field(default_factory=set)  # ESP-IDF: every component that exists


def _cmake_cache(build: Path) -> dict[str, str]:
    out = {}
    f = build / "CMakeCache.txt"
    if f.exists():
        for line in f.read_text(errors="ignore").splitlines():
            m = re.match(r"^([A-Za-z0-9_]+):[A-Z]+=(.*)$", line)
            if m:
                out[m.group(1)] = m.group(2)
    return out


def _kconfig(build: Path) -> dict[str, str]:
    out = {}
    f = build / "zephyr" / ".config"
    if f.exists():
        for line in f.read_text(errors="ignore").splitlines():
            m = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", line)
            if m:
                out[m.group(1)] = m.group(2).strip('"')
    return out


def _modules_txt(build: Path) -> dict[str, Path]:
    out = {}
    f = build / "zephyr_modules.txt"
    if f.exists():
        for line in f.read_text(errors="ignore").splitlines():
            parts = re.findall(r'"([^"]*)"', line)
            if len(parts) >= 2:
                out[parts[0]] = Path(parts[1]).resolve()
    return out


def _git(path: Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, timeout=20)
        return (r.stdout.strip() or None) if r.returncode == 0 else None
    except Exception:
        return None


def scrub_url(url: str | None) -> str | None:
    """Drop credentials (https://user:token@host/...) so they never reach an SBOM."""
    if not url:
        return url
    return re.sub(r"^([a-z][a-z0-9+.-]*://)[^/@]*@", r"\1", url)


def _git_url(path: Path) -> str | None:
    url = _git(path, "config", "--get", "remote.origin.url")
    if not url:
        remotes = _git(path, "config", "--get-regexp", r"^remote\..*\.url$")  # west names it "upstream"
        url = remotes.splitlines()[0].split(None, 1)[1] if remotes else None
    return scrub_url(url)


def _module_refs(path: Path) -> list[str]:
    """security: external-references from zephyr/module.yml (Zephyr 4.x), without a YAML dependency."""
    for f in (path / "zephyr" / "module.yml", path / "zephyr" / "module.yaml"):
        if f.exists():
            refs, inside = [], False
            for line in f.read_text(errors="ignore").splitlines():
                if re.match(r"^\s*external-references:\s*$", line):
                    inside = True
                    continue
                if inside:
                    m = re.match(r"^\s*-\s*['\"]?((?:cpe:2\.3:|pkg:)[^'\"\s]+)", line)
                    if m:
                        refs.append(m.group(1))
                    elif line.strip() and not line.strip().startswith("#"):
                        inside = False
            return refs
    return []


def _west_projects(cache: dict[str, str], zephyr_base: Path) -> dict[Path, tuple[str, str, str]]:
    """{project path: (name, manifest revision, url)} from `west list`, if west is available."""
    top = next((p for p in [zephyr_base, *zephyr_base.parents] if (p / ".west").is_dir()), None)
    if not top:
        return {}
    py = cache.get("WEST_PYTHON")
    cmds = ([[py, "-m", "west"]] if py and Path(py).exists() else []) + [["west"]]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd + ["list", "-f", "{abspath}|{name}|{revision}|{url}"], cwd=top,
                               capture_output=True, text=True, timeout=60)
        except Exception:
            continue
        if r.returncode == 0:
            out = {}
            for line in r.stdout.splitlines():
                parts = line.split("|")
                if len(parts) == 4:
                    out[Path(parts[0]).resolve()] = (parts[1], parts[2], parts[3])
            return out
    return {}


def _compile_entries(build: Path) -> list[tuple[Path, str | None]]:
    """(source file, object file name) for every compile command."""
    f = build / "compile_commands.json"
    if not f.exists():
        return []
    out = {}
    for e in json.loads(f.read_text()):
        p = Path(e["file"])
        if not p.is_absolute():
            p = Path(e.get("directory", build)) / p
        obj = e.get("output")
        if not obj:
            m = re.search(r"\s-o\s+(\S+)", e.get("command", ""))
            obj = m.group(1) if m else None
        out.setdefault(p.resolve(), Path(obj).name if obj else None)
    return sorted(out.items())


def _compiled_files(build: Path) -> list[Path]:
    return [p for p, _ in _compile_entries(build)]


def linked_from_map(map_file: Path | None) -> tuple[set[str], set[str]] | None:
    """(object file names, archive file names) that the linker kept, from a GNU ld map file.

    Only the "Linker script and memory map" part is read: it lists the input sections that went
    into the output. Archive members appear as lib.a(member.obj). Returns None without a map file.
    Matching is by file name, so two objects with the same name count as one; that errs towards
    "linked", never towards dropping code that is present.
    """
    if not map_file or not map_file.is_file():
        return None
    text = map_file.read_text(errors="ignore")
    i = text.find("Linker script and memory map")
    if i < 0:
        return None
    body = text[i:]
    objs, archives = set(), set()
    for a, mem in re.findall(r"(\S+?\.a)\(([^)\s]+)\)", body):
        archives.add(Path(a).name)
        objs.add(mem)
    for o in re.findall(r"\s(\S+\.(?:obj|o))\b", body):
        objs.add(Path(o).name)
    return objs, archives


ZEPHYR_ELF = r"zephyr/zephyr(?:_final)?\.elf"
TFM_ELF = r"bin/tfm_s\.elf"


def _link_libs(build: Path, elf_re: str = ZEPHYR_ELF) -> list[Path]:
    """Static libraries named on the final link line of `elf_re` that this build did not produce."""
    f = build / "build.ninja"
    if not f.exists():
        return []
    text = f.read_text(errors="ignore")
    libs = set()
    for m in re.finditer(r"^build (?:[^:\n]* )?" + elf_re + r"[ :|][^\n]*\n((?:  [^\n]*\n)+)", text, re.M):
        block = m.group(1)
        lm = re.search(r"^  LINK_LIBRARIES = (.*)$", block, re.M)
        if not lm:
            continue
        # Windows paths use backslashes, which shlex would read as escapes: use forward slashes.
        toks = shlex.split(lm.group(1).replace("\\", "/"))
        lp = re.search(r"^  LINK_PATH = (.*)$", block, re.M)
        toks_path = shlex.split(lp.group(1).replace("\\", "/")) if lp else []
        search = []  # -L directories outside the build (vendor library folders, not the toolchain)
        for i, tok in enumerate(toks_path + toks):
            d = tok[2:] if tok.startswith("-L") and len(tok) > 2 else None
            if d:
                dp = Path(d).resolve()
                if build.resolve() not in dp.parents and dp != build.resolve():
                    search.append(dp)
        for tok in toks:
            if tok.endswith(".a") and not tok.startswith("-"):
                p = Path(tok)
                p = (build / p).resolve() if not p.is_absolute() else p.resolve()
                if build.resolve() not in p.parents:
                    libs.add(p)
            elif tok.startswith("-l") and len(tok) > 2 and not tok.startswith("-l:"):
                for d in search:  # e.g. ESP-IDF's -lphy with -L components/esp_phy/lib/esp32
                    cand = d / f"lib{tok[2:]}.a"
                    if cand.is_file():
                        libs.add(cand.resolve())
                        break
    return sorted(libs)


def _owner(p: Path, roots: list[tuple[str, Path]]) -> tuple[str, str] | None:
    for name, root in roots:
        try:
            return name, p.relative_to(root).as_posix()
        except ValueError:
            continue
    return None


def _collect(build: Path, compile_db: Path, roots: list[tuple[str, Path]], mods: dict[str, Module],
             elf_re: str, map_file: Path | None = None) -> tuple[list[str], list[str], list[Blob]]:
    linked = linked_from_map(map_file)
    app_files, other = [], []
    for f, obj in _compile_entries(compile_db):
        if build in f.parents:
            continue  # generated files
        o = _owner(f, roots)
        if linked is not None and obj and obj not in linked[0]:
            if o and o[0] in mods:
                mods[o[0]].not_linked += 1
            continue  # compiled, but the linker dropped it: not in the firmware
        if not o:
            other.append(str(f))
        elif o[0] == "__app__":
            app_files.append(o[1])
        else:
            mods[o[0]].files.append(o[1])
    blobs = []
    for lib in _link_libs(compile_db, elf_re):
        if linked is not None and lib.name not in linked[1]:
            continue  # on the link line, but nothing was taken from it
        o = _owner(lib, [r for r in roots if r[0] != "__app__"])
        blobs.append(Blob(lib, o[0] if o else "unknown"))
    return sorted(app_files), sorted(other), blobs


def _finish(mods: dict[str, Module], blobs: list[Blob], west: dict, keep_zephyr: bool) -> dict[str, Module]:
    used = {n: m for n, m in mods.items()
            if m.files or (n == "zephyr" and keep_zephyr) or any(b.owner == n for b in blobs)}
    for m in used.values():
        m.git_rev = _git(m.path, "rev-parse", "HEAD")
        m.ext_refs = _module_refs(m.path)
        m.git_describe = _git(m.path, "describe", "--tags", "--always", "--dirty")
        w = west.get(m.path.resolve())
        m.git_url = _git_url(m.path) or scrub_url(w[2] if w and w[2] != "N/A" else None)
        if w and w[1] not in ("HEAD", "N/A"):
            m.west_revision = w[1]
        m.files.sort()
    return used


def scan_image(build: Path, name: str | None = None) -> list[Image]:
    """The Zephyr image in `build`, plus a TF-M secure image if the build contains one."""
    build = build.resolve()
    cache = _cmake_cache(build)
    zb = Path(cache.get("ZEPHYR_BASE", "")).resolve() if cache.get("ZEPHYR_BASE") else None
    if not zb or not zb.exists():
        raise SystemExit(f"{build}: not a Zephyr build directory (no ZEPHYR_BASE in CMakeCache.txt)")
    app = Path(cache["APPLICATION_SOURCE_DIR"]).resolve() if cache.get("APPLICATION_SOURCE_DIR") else None
    module_paths = {"zephyr": zb, **_modules_txt(build)}
    west = _west_projects(cache, zb)

    def fresh() -> tuple[dict[str, Module], list[tuple[str, Path]]]:
        mods = {n: Module(n, p, kind="zephyr" if n == "zephyr" else "") for n, p in module_paths.items()}
        # Longest path first, so a module nested inside another directory wins.
        roots = sorted([(n, m.path) for n, m in mods.items()], key=lambda x: -len(str(x[1])))
        return mods, roots

    mods, roots = fresh()
    if app:
        roots.insert(0, ("__app__", app))
    app_files, other, blobs = _collect(build, build, roots, mods, ZEPHYR_ELF, build / "zephyr" / "zephyr.map")
    used = _finish(mods, blobs, west, keep_zephyr=True)
    elf = build / "zephyr" / "zephyr.elf"
    img_name = name or (app.name if app else build.name)
    board = cache.get("BOARD") or cache.get("CACHED_BOARD")
    images = [Image(img_name, build, board, zb, app, _kconfig(build), used, app_files, other, blobs,
                    elf if elf.exists() else None)]
    tfm = build / "tfm"
    if (tfm / "compile_commands.json").exists():  # TF-M secure image, built as a sub-build
        mods, roots = fresh()
        _, other_t, blobs_t = _collect(tfm, tfm, roots, mods, TFM_ELF, tfm / "bin" / "tfm_s.map")
        used_t = _finish(mods, blobs_t, west, keep_zephyr=False)
        tfm_elf = tfm / "bin" / "tfm_s.elf"
        images.append(Image(f"{img_name}/tfm", tfm, board, zb, None, {}, used_t, [], other_t, blobs_t,
                            tfm_elf if tfm_elf.exists() else None))
    return images


def scan(build: Path) -> list[Image]:
    """One Image per firmware image; sysbuild builds give one per domain. ESP-IDF builds are detected too."""
    build = Path(build)
    from . import espidf
    if espidf.is_espidf_build(build):
        return espidf.scan(build)
    domains = build / "domains.yaml"
    if domains.exists():
        imgs = []
        for m in re.finditer(r"-\s*name:\s*(\S+)\s*\n\s*build_dir:\s*(\S+)", domains.read_text()):
            imgs += scan_image(Path(m.group(2)), m.group(1))
        if imgs:
            return imgs
    return scan_image(build)
