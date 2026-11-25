import json
import os
import tempfile
import unittest
from pathlib import Path

from fwvex.build import scan
from fwvex.cyclonedx import bom, iter_components


def make_build(root: Path) -> Path:
    zb, mod, app, b = root / "zephyr", root / "modules/crypto/mbedtls", root / "app", root / "build"
    for d in (zb / "kernel", zb / "subsys/bluetooth/host", mod / "library", mod / "include/mbedtls",
              mod / "zephyr", app / "src", b / "zephyr", root / "modules/hal/stm32"):
        d.mkdir(parents=True, exist_ok=True)
    (zb / "VERSION").write_text("VERSION_MAJOR = 4\nVERSION_MINOR = 4\nPATCHLEVEL = 2\n")
    (mod / "include/mbedtls/build_info.h").write_text('#define MBEDTLS_VERSION_STRING "4.1.0"\n')
    (mod / "zephyr/module.yml").write_text("security:\n  external-references:\n"
                                           "    - cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*\n"
                                           "    - pkg:github/Mbed-TLS/mbedtls@v4.1.0\n")
    (b / "CMakeCache.txt").write_text(f"ZEPHYR_BASE:PATH={zb}\nAPPLICATION_SOURCE_DIR:PATH={app}\nBOARD:STRING=nrf52840dk/nrf52840\n")
    (b / "zephyr_modules.txt").write_text(f'"mbedtls":"{mod}":"x"\n"hal_stm32":"{root / "modules/hal/stm32"}":"x"\n')
    (b / "zephyr/.config").write_text("CONFIG_BT=y\n# CONFIG_NET_TCP is not set\n")
    files = [zb / "kernel/sched.c", zb / "subsys/bluetooth/host/gatt.c", mod / "library/aes.c", app / "src/main.c",
             b / "zephyr/misc/generated/x.c"]
    (b / "compile_commands.json").write_text(json.dumps([{"directory": str(b), "file": str(f), "command": "cc"} for f in files]))
    blob = root / "modules/hal/stm32/lib/libblob.a"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(b"!<arch>\n")
    (b / "build.ninja").write_text("build zephyr/zephyr.elf: C_EXECUTABLE_LINKER__zephyr_final x.obj\n"
                                   f"  LINK_LIBRARIES = -Wl,--whole-archive {blob} libkernel.a\n")
    return b


class ScanTests(unittest.TestCase):
    def test_scan_and_bom(self):
        with tempfile.TemporaryDirectory() as t:
            b = make_build(Path(t))
            [img] = scan(b)
            self.assertEqual(img.board, "nrf52840dk/nrf52840")
            self.assertEqual(sorted(img.modules), ["hal_stm32", "mbedtls", "zephyr"])  # stm32 only via its blob
            self.assertEqual(img.modules["zephyr"].files, ["kernel/sched.c", "subsys/bluetooth/host/gatt.c"])
            self.assertEqual(img.app_files, ["src/main.c"])
            self.assertEqual([x.owner for x in img.blobs], ["hal_stm32"])
            self.assertEqual(img.kconfig.get("CONFIG_BT"), "y")
            out = bom([img], "demo", "1.0")
            comps = {c["name"]: c for c in iter_components(out)}
            self.assertEqual(comps["zephyr"]["cpe"], "cpe:2.3:o:zephyrproject:zephyr:4.4.2:*:*:*:*:*:*:*")
            self.assertEqual(comps["mbedtls"]["cpe"], "cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*")
            self.assertEqual(comps["mbedtls"]["purl"], "pkg:github/Mbed-TLS/mbedtls@v4.1.0")
            self.assertIn("zephyr/subsys/bluetooth/host", comps)
            self.assertIn("libblob.a", comps)
            self.assertEqual(out["specVersion"], "1.6")

    def test_not_a_build_dir(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(SystemExit):
                scan(Path(t))


class CpeVariantTests(unittest.TestCase):
    def test_mbedtls_aliases(self):
        from fwvex.identify import cpe_variants
        v = cpe_variants("cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*")
        self.assertIn("cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*", v)


if __name__ == "__main__":
    unittest.main()


class NormalizeTests(unittest.TestCase):
    def test_na_update_becomes_any(self):
        from fwvex.identify import normalize_cpe
        self.assertEqual(normalize_cpe("cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*"),
                         "cpe:2.3:o:zephyrproject:zephyr:4.4.2:*:*:*:*:*:*:*")
        self.assertEqual(normalize_cpe("cpe:2.3:a:x:y:1.0"), "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*")


class TfmAndBlobTests(unittest.TestCase):
    def test_tfm_subimage_and_blob_versions(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            b = make_build(root)
            tfm_src = root / "modules/tee/tf-m/trusted-firmware-m"
            (tfm_src / "secure_fw").mkdir(parents=True)
            (tfm_src / "cmake").mkdir()
            (tfm_src / "cmake/version.cmake").write_text('set(TFM_VERSION_MANUAL "2.3.1**")\n')
            with open(b / "zephyr_modules.txt", "a") as f:
                f.write(f'"trusted-firmware-m":"{tfm_src}":"x"\n')
            tfm = b / "tfm"
            (tfm / "bin").mkdir(parents=True)
            (tfm / "compile_commands.json").write_text(json.dumps(
                [{"directory": str(tfm), "file": str(tfm_src / "secure_fw/spm.c"), "command": "cc"}]))
            vlib = root / "nrfxlib/crypto/liboberon_3.0.20.a"
            vlib.parent.mkdir(parents=True)
            vlib.write_bytes(b"!<arch>\n")
            (tfm / "build.ninja").write_text("build bin/tfm_s.bin bin/tfm_s.elf bin/tfm_s.hex: C_EXECUTABLE_LINKER x.o\n"
                                             f"  LINK_LIBRARIES = {vlib} lib/libplatform_s.a\n")
            imgs = scan(b)
            self.assertEqual([i.name for i in imgs], ["app", "app/tfm"])
            tfm_img = imgs[1]
            self.assertNotIn("zephyr", tfm_img.modules)
            self.assertEqual(tfm_img.modules["trusted-firmware-m"].files, ["secure_fw/spm.c"])
            self.assertEqual([x.version for x in tfm_img.blobs], ["3.0.20"])
            out = bom(imgs, "demo", "1.0")
            comps = {c["bom-ref"]: c for c in iter_components(out)}
            self.assertEqual(comps["app/tfm:trusted-firmware-m"]["cpe"],
                             "cpe:2.3:o:trustedfirmware:trusted_firmware-m:2.3.1:*:*:*:*:*:*:*")
            self.assertEqual(comps["app:blob:libblob.a"]["version"].split()[0], "hal_stm32")  # owner's release
            self.assertEqual(comps["app:zephyr"]["purl"], "pkg:github/zephyrproject-rtos/zephyr@v4.4.2")


class PrivacyTests(unittest.TestCase):
    def test_scrub_url(self):
        from fwvex.build import scrub_url
        self.assertEqual(scrub_url("https://me:ghp_secret@github.com/a/b.git"), "https://github.com/a/b.git")
        self.assertEqual(scrub_url("https://github.com/a/b"), "https://github.com/a/b")
