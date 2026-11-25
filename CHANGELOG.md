# Changelog

## 0.1.0 (2026-11-25)

First public version.

- `fwvex sbom`: CycloneDX 1.6 SBOM from an existing build directory, no setup before building.
  - Zephyr and nRF Connect SDK (`west build`, including sysbuild and TF-M secure images).
  - ESP-IDF (`idf.py build`, app and bootloader images).
  - Only code that was compiled and kept by the linker (from the `.map` file) counts.
  - Prebuilt vendor libraries the linker used are listed with SHA-256.
  - Identifiers from the frameworks' own metadata (Zephyr `module.yml`, ESP-IDF `sbom.yml` / `.gitmodules`).
- `fwvex check`: NVD CVEs for every component with a CPE (all NVD vendor names), each with a CycloneDX
  `analysis` verdict and its evidence (files in the firmware, ESP-IDF components in the build, Kconfig),
  vendor-fixed CVEs as `resolved`, a Markdown report, and `--fail-on` for CI.
- Tested on Zephyr 4.4.2 / 4.5.0, nRF Connect SDK 3.4.2 and ESP-IDF 5.5.4 sample builds; see `bench/RESULTS.md`.
