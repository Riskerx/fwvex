# fwvex

[![test](https://github.com/Riskerx/fwvex/actions/workflows/test.yml/badge.svg)](https://github.com/Riskerx/fwvex/actions/workflows/test.yml)

**Vulnerability-matchable SBOMs and evidence-based VEX for Zephyr, nRF Connect SDK and ESP-IDF firmware.**

`fwvex` reads an ordinary build directory and writes a CycloneDX 1.6 SBOM of what is actually in the
firmware: code that was compiled **and kept by the linker**, plus the prebuilt vendor libraries that
were linked. `fwvex check` then looks up known CVEs and, for each one, says whether the vulnerable
code is in *this* build, with the evidence.

Measured on unmodified sample builds (details and caveats in [bench/RESULTS.md](bench/RESULTS.md)):

| Build | CVEs from the framework's own SBOM tool | CVEs fwvex matches | Ruled out with evidence | Left to review |
|---|---|---|---|---|
| Zephyr 4.4.2, BLE heart-rate sensor (nRF52840) | 0 (`west spdx`) | 26 | 21 | 5 |
| Zephyr 4.4.2, MQTT over Ethernet (STM32F429) | 0 (`west spdx`) | 26 | 20 | 6 |
| Zephyr 4.4.2, MCUboot + SMP server, 2 images | 0 (`west spdx`) | 26 | 21 | 5 |
| nRF Connect SDK 3.4.2, nRF9151 LTE + TF-M | 0 (`west spdx`) | 26 | 23 | 3 |
| ESP-IDF 5.5.4, ESP32-C3 NimBLE peripheral | 5 (`esp-idf-sbom`), all of which fwvex rules out | 22 | 5 (+2 vendor-fixed) | 15 |

- Zephyr's `west spdx` writes the Zephyr CPE as `...:zephyr:4.4.2:-:...`, which NVD's API does not
  match; in nRF Connect SDK Zephyr gets no CPE at all. On Zephyr 4.5 it lists every workspace module,
  so a Bluetooth sample with no FatFs code gets 5 FatFs CVEs. It lists none of Nordic's prebuilt libraries.
- Espressif's `esp-idf-sbom` is much better (correct CPEs, NVD check, Espressif's list of fixed CVEs),
  but it reports by version: e.g. ESP-TEE and HTTP-server CVEs on builds that contain neither component.
  It is cleaner than fwvex in one place: see RESULTS.md section 4.

## Why

From 11 September 2026 the EU Cyber Resilience Act requires manufacturers to report actively
exploited vulnerabilities, and from 11 December 2027 products need an SBOM and a vulnerability
handling process to carry a CE mark. For a firmware product that means: know exactly which components
and versions ship, notice new CVEs in them, and be able to say which ones affect you. A list of 26
CVEs where 21 cannot affect the product wastes the review time CRA deadlines leave you.

## Example

A real report for Zephyr's `samples/bluetooth/peripheral_hr` on Zephyr 4.4.2:
[examples/zephyr-4.4.2-bt_hr/vulnerability-report.md](examples/zephyr-4.4.2-bt_hr/vulnerability-report.md)
(SBOM next to it).

## Install

Python 3.10+, no dependencies.

```bash
pip install fwvex                                   # once released on PyPI
pip install git+https://github.com/Riskerx/fwvex    # latest from GitHub
```

## Use

After a normal `west build` or `idf.py build`:

```bash
fwvex sbom  -d build --product my-sensor --product-version 1.2.0     # Zephyr / nRF Connect SDK
fwvex check -d build --product my-sensor --product-version 1.2.0
fwvex check -d my_esp_project --product my-sensor                      # ESP-IDF: project or build dir
```

`check` writes `<dir>/fwvex/sbom.cdx.json` (SBOM with a `vulnerabilities` section) and
`<dir>/fwvex/vulnerability-report.md`. Multi-image builds (sysbuild, TF-M, ESP-IDF bootloader)
produce one SBOM with every image in it. Set `NVD_API_KEY` to query NVD faster; results are cached
for 24 hours in `~/.cache/fwvex`.

As a west extension: add this repository to your `west.yml` as a project with
`west-commands: west-commands.yml`, then run `west fwvex check -d build`.

## What is in the SBOM

- The product, and one firmware component per image (sysbuild domains, TF-M secure image,
  ESP-IDF bootloader).
- The framework itself (Zephyr or ESP-IDF) with CPE and PURL, and one sub-component per subsystem
  or component that is in the firmware (`zephyr/subsys/bluetooth/host`, `esp-idf/components/esp_wifi`, ...).
- Every module or bundled library that contributed linked code. Identifiers come from the
  framework's own metadata where it exists (Zephyr `module.yml` external references; ESP-IDF
  `sbom.yml` manifests and `.gitmodules` `sbom-*` entries, including Espressif's list of fixed CVEs),
  otherwise from fwvex's table (upstream version read from the source, e.g. `build_info.h`).
- Prebuilt static libraries the linker actually used (Nordic SoftDevice Controller, MPSL, `libmodem.a`;
  Espressif Wi-Fi, PHY and Bluetooth controller libraries), with SHA-256, providing module and version.
- Files that were compiled but discarded by the linker are counted (`fwvex:compiled_not_linked`) but
  not treated as present.
- Release tags from the west manifest where the source has no version file; exact commits as
  `fwvex:source_purl` / `fwvex:git_commit`.

## How the verdicts work

For every CVE matched by CPE (all known NVD vendor names are queried, e.g. Mbed TLS under both
`arm` and `trustedfirmware`):

0. **The vendor lists it as fixed in this version** (ESP-IDF `cve-exclude-list`): `resolved`, with
   the vendor's reason.
1. **The CVE names source files or directories** (63 of 69 Zephyr 4.4.0 CVEs do; many ESP-IDF ones).
   If none of them is in the firmware (compiled and linked): `not_affected`, `code_not_present`, with
   the file names as evidence. If any is: `in_triage`, naming it.
2. **ESP-IDF: the CVE names a component** (e.g. `esp_http_server`, `esp_tee`). If it is not part of
   the build: `not_affected`, `code_not_present`.
3. **The CVE names a subsystem or feature** (Bluetooth, MQTT, USB, IPv6, ESP-TEE, BluFi, ...). If every
   Kconfig option that enables it is off: `not_affected`, `requires_configuration`.
4. Otherwise `in_triage`. For bundled libraries the report shows which of their files are in the firmware.

Header files alone never count as proof of absence, and only distinctive component names count.
Verdicts are suggestions with evidence; a person should review them before they go into a VEX you publish.

## Limits (0.1)

- Tested on Zephyr 4.4.2 and 4.5.0, nRF Connect SDK 3.4.2 and ESP-IDF 5.5.4 builds made with GNU ld.
  STM32Cube is next.
- nRF Connect SDK uses Nordic's fork of Zephyr, which may already fix some upstream CVEs; Nordic's
  advisories are not consulted yet, so "review" can be conservative there.
- File-level evidence exists for Zephyr and ESP-IDF CVEs; CVEs of bundled libraries (Mbed TLS, lwIP,
  FreeRTOS, ...) are matched by CPE and left for review, with the library's linked files shown.
- Vulnerability source is NVD. OSV and the vendors' GitHub security advisories are not queried yet.
- Linker evidence matches object files by name; two objects with the same name count as one, which
  errs towards "present".
- A CVE that names a file only for context could be marked not affected wrongly; the evidence is
  in every verdict so a reviewer can catch it.

## Related tools

- `west spdx` (Zephyr) and `esp-idf-sbom` (Espressif) are the frameworks' own SBOM generators;
  fwvex is measured against both in [bench/RESULTS.md](bench/RESULTS.md).
- For bare-metal projects (STM32Cube, vendored FreeRTOS / Mbed TLS / lwIP without Zephyr or ESP-IDF),
  see [chen-embedded/fwsbom](https://github.com/chen-embedded/fwsbom), which detects vendored libraries
  from their sources and also uses the linker map.

## License

Apache-2.0 (same as Zephyr and ESP-IDF). See [LICENSE](LICENSE).
