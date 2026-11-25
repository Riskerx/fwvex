# Measured results (2026-11-24)

All numbers below come from unmodified sample/example builds, fwvex 0.1 with linker-map filtering,
and the NVD API queried on 2026-11-24. "In the firmware" means compiled **and** kept by the linker
(from the `.map` file); code that is compiled but discarded does not count.

Reproduce the Zephyr / nRF Connect rows with `python3 -I bench/measure.py <build dir> ...` (needs
`west spdx` output in the build). The ESP-IDF rows compare `fwvex check` with
`esp-idf-sbom 1.5.0 create` + `check`.

## 1. Zephyr 4.4.2 (upstream)

| Build | Board | CVEs a scanner finds from `west spdx` | CVEs fwvex matches | Ruled out: code not in firmware | Left for review |
|---|---|---|---|---|---|
| `bt_hr`: `samples/bluetooth/peripheral_hr` | nrf52840dk/nrf52840 | 0 | 26 | 21 | 5 |
| `mqtt_stm32`: `samples/net/mqtt_publisher` | nucleo_f429zi | 0 | 26 | 20 | 6 |
| `smp_mcuboot`: `smp_svr` + `bt.conf`, sysbuild with MCUboot (2 images) | nrf52840dk/nrf52840 | 0 | 26 | 21 | 5 |

- Why 0: `west spdx` writes the Zephyr CPE as `cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*`. NVD's
  API matches that `-` (NA) form to 0 of the 26 CVEs it lists for 4.4.2 (1 of 69 for 4.4.0); the `*` form
  matches all. Scanners that implement CPE matching themselves may behave differently.
- What is left for review is specific. `bt_hr`: CVE-2026-10685 and CVE-2026-2411 (`subsys/bluetooth/host/gatt.c`),
  CVE-2026-11368 (`att.c`), CVE-2026-10682 (`subsys/logging/log_mgmt.c`), CVE-2026-10670 (`kernel/thread.c`).
- Linker evidence matters: `kernel/pipe.c` is compiled into the kernel library of `bt_hr` but discarded by
  the linker (the app uses no pipes), so CVE-2026-10671 (score 7.1) is ruled out with that evidence.

## 2. Zephyr 4.5.0 (upstream): false positives from unused modules

| Build | CVEs from `west spdx` CPEs | CVEs fwvex matches |
|---|---|---|
| `bt_hr` | 5 (CVE-2026-6682, -6683, -6686, -6687, -6688: FatFs) | 0 |

`west spdx` lists every workspace module, with its CPE, whether or not any of its code is used. The BLE
sample contains no FatFs code, yet its SBOM carries the FatFs CPE.

## 3. nRF Connect SDK v3.4.2 (Zephyr 4.4.2 base, Nordic fork)

| Build | Board | CVEs from `west spdx` | CVEs fwvex matches | Ruled out | Review | Prebuilt binaries: `west spdx` / fwvex |
|---|---|---|---|---|---|---|
| `lbs_52840`: `nrf/samples/bluetooth/peripheral_lbs` | nrf52840dk/nrf52840 | 0 | 26 | 22 | 4 | 0 / 5 |
| `lbs_5340`: same, dual core (app + `ipc_radio`) | nrf5340dk/nrf5340/cpuapp | 0 | 26 | 22 | 4 | 0 / 5 |
| `at_client_9151`: `nrf/samples/cellular/at_client` + TF-M | nrf9151dk/nrf9151/ns | 0 | 26 | 23 | 3 | 0 / 1 + TF-M image |

- `west spdx` in nRF Connect SDK gives Zephyr no CPE (its version is a commit hash), and lists Mbed TLS,
  TF-PSA-Crypto and TF-M CPEs in every build, including ones that contain none of them.
- None of Nordic's prebuilt libraries appears in `west spdx`. fwvex lists the ones the linker actually
  used, e.g. for `lbs_52840`: `libsoftdevice_controller_peripheral.a`, `libmpsl.a`, `libmpsl_fem_common.a`,
  `liboberon_3.0.20.a`, `libnrf_cc310_platform_0.9.23.a` (6 more MPSL front-end libraries are on the link
  line but nothing is taken from them, so they are left out). For `at_client_9151`: `libmodem.a`, plus the
  TF-M 2.3.1 secure image as its own component.
- Caveat: Nordic's Zephyr fork may already contain fixes for some upstream 4.4.2 CVEs; matching is by
  upstream version and Nordic's advisories are not consulted yet, so "review" can be conservative here.

## 4. ESP-IDF v5.5.4, against Espressif's own esp-idf-sbom 1.5.0

Espressif already ships good SBOM metadata (versions and CPEs for each bundled library, its own list of
CVEs it has fixed) and `esp-idf-sbom` uses it well: the CPEs are right and it checks NVD. The difference
is per-build evidence.

| Build | Target | esp-idf-sbom: "vulnerable" | fwvex matches | Ruled out with evidence | Vendor-fixed | Left for review |
|---|---|---|---|---|---|---|
| `wifi_sta`: `examples/wifi/getting_started/station` | esp32 | 16 | 23 | 4 | 3 | 16 |
| `ble_prph_c3`: `examples/bluetooth/nimble/bleprph` | esp32c3 | 5 | 22 | 5 | 2 | 15 |
| `https_req`: `examples/protocols/https_request` | esp32 | 16 | 23 | 4 | 3 | 16 |

Where fwvex is better:
- Rules out CVEs esp-idf-sbom reports, with the evidence: CVE-2026-45328 and -45329 (ESP-TEE: component
  `esp_tee` not in the build, `CONFIG_SECURE_ENABLE_TEE` off), CVE-2026-45541 (`esp_http_server` not in the
  build), CVE-2026-45542 (`components/protocomm/src/security/security2.c` not in the firmware), and on the
  BLE build CVE-2026-45160 (`components/lwip/apps/dhcpserver/dhcpserver.c` compiled but discarded by the linker).
- Lists the prebuilt libraries actually linked, with SHA-256: Wi-Fi (`libnet80211.a`, `libpp.a`, `libcore.a`,
  ...), PHY (`libphy.a`, `librtc.a`), Bluetooth controller (`libbtdm_app.a`, `libbtbb.a`), coexistence.
  On the BLE build the Wi-Fi libraries are on the link line but unused, and are left out.
- Matches 4 recent FreeRTOS-Kernel CVEs (CVE-2026-77234 to -77237) that esp-idf-sbom did not report.
  They concern MPU and TrustZone ports and probably do not affect ESP32 ports; fwvex leaves them for review.

Where esp-idf-sbom is cleaner:
- On the BLE build it drops Mbed TLS entirely; fwvex keeps it because 2 Mbed TLS files are in the firmware
  (`library/platform.c`, `library/platform_util.c`) and leaves its 11 CVEs for review, showing those two files.
  A reviewer can dismiss them quickly, but fwvex does not do it automatically.
- It also reports licences and supports Espressif's VEX workflow; fwvex does not yet.

## Differences in one table

| | `west spdx` (Zephyr 4.4/4.5, NCS) | esp-idf-sbom 1.5.0 | fwvex 0.1 |
|---|---|---|---|
| Setup before building | `--init` (4.4) and `CONFIG_BUILD_OUTPUT_META=y` | none | none |
| Format | SPDX 2.3, 4 files per image | SPDX 2.2 | CycloneDX 1.6, one file per product, all images |
| Components listed | every workspace module | components in the build | only code compiled **and linked** |
| Prebuilt binaries | not listed | as submodule packages | each linked library, with SHA-256 |
| CVE check | none | NVD, vendor exclusions | NVD + vendor exclusions + per-build evidence (files, linker, components, Kconfig) |
