import json
import tempfile
import unittest
from pathlib import Path

from fwvex.applicability import assess
from fwvex.build import scan
from fwvex.cyclonedx import bom, iter_components


def make_idf_build(root: Path) -> Path:
    idf, proj = root / "esp-idf", root / "proj"
    b = proj / "build"
    for d in (idf / "tools/cmake", idf / "components/lwip/lwip/src/core", idf / "components/lwip/apps/dhcpserver",
              idf / "components/esp_wifi/lib/esp32", idf / "components/esp_wifi/src", proj / "main", b):
        d.mkdir(parents=True, exist_ok=True)
    (idf / "tools/cmake/version.cmake").write_text("set(IDF_VERSION_MAJOR 5)\nset(IDF_VERSION_MINOR 5)\nset(IDF_VERSION_PATCH 4)\n")
    (idf / "components/lwip/lwip/sbom.yml").write_text(
        "name: 'lwip'\nversion: '2.2.0'\ncpe: cpe:2.3:a:lwip_project:lwip:{}:*:*:*:*:*:*:*\n"
        "cve-exclude-list:\n  - cve: CVE-2099-0001\n    reason: Fixed by Espressif\n")
    (idf / ".gitmodules").write_text('[submodule "components/json/cJSON"]\n\tpath = components/json/cJSON\n'
                                     '\tsbom-version = 1.7.19\n\tsbom-cpe = cpe:2.3:a:cjson_project:cjson:{}:*:*:*:*:*:*:*\n')
    (proj / "sdkconfig").write_text("CONFIG_ESP_WIFI_ENABLED=y\nCONFIG_LWIP_DHCPS=y\n")
    srcs = {"main": proj / "main/app.c", "core": idf / "components/lwip/lwip/src/core/tcp.c",
            "dhcp": idf / "components/lwip/apps/dhcpserver/dhcpserver.c", "wifi": idf / "components/esp_wifi/src/wifi.c"}
    (b / "compile_commands.json").write_text(json.dumps(
        [{"directory": str(b), "file": str(p), "command": "cc", "output": f"x/{p.name}.obj"} for p in srcs.values()]))
    blob = idf / "components/esp_wifi/lib/esp32/libnet80211.a"
    blob.write_bytes(b"!<arch>\n")
    (idf / "components/esp_wifi/lib/esp32/libunused.a").write_bytes(b"!<arch>\n")
    (b / "build.ninja").write_text(
        "build app.elf: CXX_EXECUTABLE_LINKER x.obj\n"
        f"  LINK_LIBRARIES = esp-idf/lwip/liblwip.a -lnet80211 -lunused -lc\n"
        f"  LINK_PATH = -L{idf}/components/esp_wifi/lib/esp32 -L{b}/esp-idf/esp_system/ld\n")
    # dhcpserver.c compiled but dropped by the linker; libunused.a on the link line but unused
    (b / "app.map").write_text("Archive member included\n\nLinker script and memory map\n"
                               " .text.a 0x1 0x10 esp-idf/main/libmain.a(app.c.obj)\n"
                               " .text.b 0x1 0x10 esp-idf/lwip/liblwip.a(tcp.c.obj)\n"
                               " .text.c 0x1 0x10 esp-idf/esp_wifi/libesp_wifi.a(wifi.c.obj)\n"
                               f" .text.d 0x1 0x10 {blob}(ieee80211.o)\n")
    (b / "project_description.json").write_text(json.dumps({
        "idf_path": str(idf), "project_path": str(proj), "build_dir": str(b), "project_name": "app",
        "app_elf": "app.elf", "target": "esp32", "config_file": str(proj / "sdkconfig"),
        "build_components": ["main", "lwip", "esp_wifi", ""],
        "all_component_info": {"main": {}, "lwip": {}, "esp_wifi": {}, "esp_tee": {}, "esp_http_server": {}}}))
    return proj


class EspIdfScanTests(unittest.TestCase):
    def test_scan(self):
        with tempfile.TemporaryDirectory() as t:
            proj = make_idf_build(Path(t))
            [img] = scan(proj)
            self.assertEqual(img.framework, "esp-idf")
            self.assertEqual(img.board, "esp32")
            self.assertEqual(img.app_files, ["main/app.c"])
            self.assertEqual(img.modules["lwip"].files, ["src/core/tcp.c"])
            self.assertEqual(img.modules["esp-idf"].files, ["components/esp_wifi/src/wifi.c"])  # dhcpserver dropped
            self.assertEqual(img.modules["esp-idf"].not_linked, 1)
            self.assertEqual([x.path.name for x in img.blobs], ["libnet80211.a"])  # -l resolved, unused dropped
            out = bom([img], "demo", "1.0")
            comps = {c["name"]: c for c in iter_components(out)}
            self.assertEqual(comps["esp-idf"]["cpe"], "cpe:2.3:a:espressif:esp-idf:5.5.4:*:*:*:*:*:*:*")
            self.assertEqual(comps["lwip"]["cpe"], "cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*")
            self.assertIn("esp-idf/components/esp_wifi", comps)
            props = {p["name"]: p["value"] for p in comps["lwip"]["properties"]}
            self.assertEqual(props["fwvex:vendor_fixed_cve"], "CVE-2099-0001: Fixed by Espressif")
            self.assertNotIn("cJSON", comps)  # in .gitmodules but nothing compiled from it


class EspIdfAssessTests(unittest.TestCase):
    known = {"main", "lwip", "esp_wifi", "esp_tee", "esp_http_server"}
    built = {"main", "lwip", "esp_wifi"}

    def test_component_not_built(self):
        v = assess("a NULL-pointer dereference in the WebSocket path of the esp_http_server component.",
                   set(), {}, "esp-idf", self.built, self.known)
        self.assertEqual((v.state, v.justification), ("not_affected", "code_not_present"))

    def test_path_dropped_by_linker(self):
        v = assess("parse_options() in components/lwip/apps/dhcpserver/dhcpserver.c reads past the end",
                   {"components/esp_wifi/src/wifi.c"}, {"CONFIG_LWIP_DHCPS": "y"}, "esp-idf", self.built, self.known)
        self.assertEqual(v.justification, "code_not_present")

    def test_kconfig_off(self):
        v = assess("several ESP-TEE secure-service wrappers validated only some pointers",
                   set(), {"CONFIG_ESP_WIFI_ENABLED": "y"}, "esp-idf", self.built, self.known)
        self.assertEqual(v.justification, "requires_configuration")

    def test_common_words_are_not_components(self):
        v = assess("A log message can overflow the heap.", set(), {}, "esp-idf", self.built, self.known | {"log", "heap"})
        self.assertEqual(v.state, "in_triage")


if __name__ == "__main__":
    unittest.main()
