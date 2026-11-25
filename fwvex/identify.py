"""Identifiers (PURL, CPE) and upstream versions for Zephyr and common Zephyr modules.

Vulnerability databases match on identifiers, not on names. NVD matches on CPE; OSV and most
SBOM tools match on PURL. This module knows the NVD CPE names for the components that have
them and how to read the real upstream version out of a module's source tree (Zephyr's
module forks are pinned by commit, which says nothing about the upstream release).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Known:
    cpe_vendor_product: str | None  # e.g. "o:zephyrproject:zephyr"; NVD name used in the SBOM
    upstream_purl: str | None  # PURL of the upstream project, without version
    version_file: str | None  # path inside the module, relative
    version_regex: str | None  # one capture group, or several joined with "."


# Other names NVD files the same product under; `check` queries all of them.
CPE_ALIASES: dict[str, list[str]] = {
    "a:arm:mbed_tls": ["a:trustedfirmware:mbed_tls"],
    "a:trustedfirmware:mbed_tls": ["a:arm:mbed_tls"],
    "o:trustedfirmware:trusted_firmware-m": ["o:arm:trusted_firmware-m", "a:arm:trusted_firmware-m",
                                             "a:trustedfirmware:trusted_firmware-m", "a:linaro:trusted_firmware-m"],
    "o:arm:trusted_firmware-m": ["o:trustedfirmware:trusted_firmware-m", "a:arm:trusted_firmware-m"],
}


def normalize_cpe(c: str) -> str:
    """Use ANY ("*") instead of NA ("-") in the update field and pad to 13 fields.

    Zephyr's own SBOM writes e.g. cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:...; NVD's API matches
    that against 0 of the 26 CVEs it lists for zephyr 4.4.2 (checked 2026-11-24), because "-" means
    "this product has no update value" rather than "any update".
    """
    parts = c.split(":")
    parts += ["*"] * (13 - len(parts))
    if parts[6] == "-":
        parts[6] = "*"
    return ":".join(parts[:13])


def cpe_variants(c: str) -> list[str]:
    """The CPE plus the same product/version under its other NVD vendor names."""
    c = normalize_cpe(c)
    parts = c.split(":")
    if len(parts) < 6:
        return [c]
    key = ":".join(parts[2:5])
    out = [c]
    for alt in CPE_ALIASES.get(key, []):
        out.append(":".join(parts[:2] + alt.split(":") + parts[5:]))
    return out


# Keyed by Zephyr module name (the name in west.yml / zephyr_modules.txt).
# CPE names checked against the NVD CPE dictionary on 2026-11-24.
KNOWN: dict[str, Known] = {
    "zephyr": Known("o:zephyrproject:zephyr", "pkg:github/zephyrproject-rtos/zephyr", "VERSION",
                    r"VERSION_MAJOR\s*=\s*(\d+)\s+VERSION_MINOR\s*=\s*(\d+)\s+PATCHLEVEL\s*=\s*(\d+)"),
    "mbedtls": Known("a:trustedfirmware:mbed_tls", "pkg:github/Mbed-TLS/mbedtls", "include/mbedtls/build_info.h",
                     r'#define\s+MBEDTLS_VERSION_STRING\s+"([0-9.]+)"'),
    "trusted-firmware-m": Known("o:trustedfirmware:trusted_firmware-m", "pkg:github/TrustedFirmware-M/trusted-firmware-m",
                                "cmake/version.cmake", r'TFM_VERSION_MANUAL\s+"([0-9]+\.[0-9]+\.[0-9]+)'),
    "mcuboot": Known(None, "pkg:github/mcu-tools/mcuboot", "boot/bootutil/include/bootutil/bootutil_public.h", None),
    "littlefs": Known(None, "pkg:github/littlefs-project/littlefs", "lfs.h",
                      r"#define\s+LFS_VERSION\s+0x([0-9a-fA-F]+)"),
    "lvgl": Known(None, "pkg:github/lvgl/lvgl", "lv_version.h",
                  r"LVGL_VERSION_MAJOR\s+(\d+).*?LVGL_VERSION_MINOR\s+(\d+).*?LVGL_VERSION_PATCH\s+(\d+)"),
    "tinycrypt": Known(None, "pkg:github/intel/tinycrypt", None, None),
    "tf-psa-crypto": Known("a:trustedfirmware:tf-psa-crypto", "pkg:github/Mbed-TLS/TF-PSA-Crypto",
                           "include/tf-psa-crypto/build_info.h", r'TF_PSA_CRYPTO_VERSION_STRING\s+"([0-9.]+)"'),
    "fatfs": Known("a:elm-chan:fatfs", "pkg:generic/elm-chan/fatfs", "include/ff.h", r"#define\s+FF_DEFINED\s+(\d+)"),
    "picolibc": Known(None, "pkg:github/picolibc/picolibc", None, None),
    "segger": Known(None, "pkg:generic/segger/rtt", None, None),
    "cmsis_6": Known(None, "pkg:github/ARM-software/CMSIS_6", None, None),
    "cmsis": Known(None, "pkg:github/ARM-software/CMSIS_5", None, None),
    "hal_nordic": Known(None, "pkg:github/NordicSemiconductor/nrfx", None, None),
    "hal_stm32": Known(None, "pkg:github/STMicroelectronics/stm32cube", None, None),
    "lwip": Known("a:lwip_project:lwip", "pkg:generic/savannah/lwip", None, None),
    "openthread": Known(None, "pkg:github/openthread/openthread", None, None),
}


def read_version(module: str, path: Path) -> str | None:
    k = KNOWN.get(module)
    if not k or not k.version_file or not k.version_regex:
        return None
    f = path / k.version_file
    if not f.is_file():
        return None
    m = re.search(k.version_regex, f.read_text(errors="ignore"), re.S)
    if not m:
        return None
    if module == "littlefs":  # 0x00020009 -> 2.9
        v = int(m.group(1), 16)
        return f"{v >> 16}.{v & 0xFFFF}"
    return ".".join(g for g in m.groups())


def cpe(module: str, version: str | None) -> str | None:
    k = KNOWN.get(module)
    if not k or not k.cpe_vendor_product or not version:
        return None
    return f"cpe:2.3:{k.cpe_vendor_product}:{version}:*:*:*:*:*:*:*"


def purl_from_remote(url: str | None, rev: str | None) -> str | None:
    """PURL for the exact repository and commit the build used (the fork, if it is a fork)."""
    if not url:
        return None
    u = urlparse(url if "://" in url else "ssh://" + url.replace(":", "/", 1))
    parts = [p for p in u.path.strip("/").removesuffix(".git").split("/") if p]
    if len(parts) < 2:
        return None
    host = (u.hostname or "").lower()
    kind = {"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket"}.get(host, "generic")
    ns, name = parts[-2], parts[-1]
    base = f"pkg:{kind}/{ns}/{name}" if kind != "generic" else f"pkg:generic/{name}?vcs_url={url}"
    return base + (f"@{rev}" if rev and kind != "generic" else "")


def upstream_purl(module: str, version: str | None) -> str | None:
    k = KNOWN.get(module)
    if not k or not k.upstream_purl:
        return None
    if not version:
        return k.upstream_purl
    tag = f"v{version}" if k.upstream_purl.startswith("pkg:github/") and module != "fatfs" else version
    return f"{k.upstream_purl}@{tag}"
