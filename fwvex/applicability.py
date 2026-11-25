"""Decide whether a published Zephyr CVE can apply to one specific firmware build.

Two pieces of build evidence are used, in this order:
1. Source files. Many Zephyr CVE descriptions name the file they affect
   (e.g. "subsys/net/lib/lwm2m/lwm2m_message_handling.c"). If the description names files
   and none of them was compiled into this firmware, the vulnerable code is not present.
2. Kconfig. If no file is named, the description's subsystem keywords are mapped to the
   Kconfig options that enable that subsystem. If every mapped option is off in this build's
   .config, the vulnerable code needs a configuration this build does not have.

Anything else stays "in_triage" for a human. The tool never marks a CVE as not affecting the
product without one of these two pieces of evidence, and it records the evidence it used.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PATH_RE = re.compile(r"\b((?:subsys|drivers|kernel|lib|arch|soc|include|modules|boards|dts)/[A-Za-z0-9_./-]*[A-Za-z0-9_])")

# Subsystem keyword -> Kconfig options; any one enabled means the subsystem is in the build.
KEYWORD_KCONFIG: list[tuple[str, list[str]]] = [
    (r"\bBluetooth Mesh\b|\bBT Mesh\b", ["CONFIG_BT_MESH"]),
    (r"\bBluetooth\b|\bBLE\b|\bL2CAP\b|\bGATT\b|\bHCI\b", ["CONFIG_BT"]),
    (r"\bLwM2M\b|\blwm2m\b", ["CONFIG_LWM2M"]),
    (r"\bMQTT\b", ["CONFIG_MQTT_LIB"]),
    (r"\bCoAP\b", ["CONFIG_COAP"]),
    (r"\bMCUmgr\b|\bmcumgr\b", ["CONFIG_MCUMGR"]),
    (r"\bUSB\b", ["CONFIG_USB_DEVICE_STACK", "CONFIG_USB_DEVICE_STACK_NEXT", "CONFIG_USB_HOST_STACK", "CONFIG_UHC_DRIVER", "CONFIG_UDC_DRIVER"]),
    (r"\bIEEE 802\.15\.4\b|\b802\.15\.4\b|\bieee802154\b", ["CONFIG_IEEE802154", "CONFIG_NET_L2_IEEE802154"]),
    (r"\bWi-?Fi\b|\bwpa_supplicant\b", ["CONFIG_WIFI"]),
    (r"\bDNS\b|\bmDNS\b|\bLLMNR\b", ["CONFIG_DNS_RESOLVER", "CONFIG_MDNS_RESPONDER", "CONFIG_LLMNR_RESPONDER"]),
    (r"\bDHCP", ["CONFIG_NET_DHCPV4", "CONFIG_NET_DHCPV6", "CONFIG_NET_DHCPV4_SERVER"]),
    (r"\bHTTP\b|\bwebsocket\b", ["CONFIG_HTTP_CLIENT", "CONFIG_HTTP_SERVER", "CONFIG_HTTP_PARSER", "CONFIG_WEBSOCKET_CLIENT"]),
    (r"\bIPv6\b|\bICMPv6\b|\b6LoWPAN\b|\bRPL\b", ["CONFIG_NET_IPV6"]),
    (r"\bIPv4\b|\bICMPv4\b|\bIGMP\b|\bARP\b", ["CONFIG_NET_IPV4"]),
    (r"\bTCP\b", ["CONFIG_NET_TCP"]),
    (r"\bUDP\b", ["CONFIG_NET_UDP"]),
    (r"\b[Ss]ocket", ["CONFIG_NET_SOCKETS"]),
    (r"\bCAN\b|\bISO-TP\b", ["CONFIG_CAN"]),
    (r"\b[Ss]hell\b", ["CONFIG_SHELL"]),
    (r"\bFAT\b|\bFatFs\b", ["CONFIG_FAT_FILESYSTEM_ELM"]),
    (r"\blittlefs\b", ["CONFIG_FILE_SYSTEM_LITTLEFS"]),
    (r"\bext2\b", ["CONFIG_FILE_SYSTEM_EXT2"]),
    (r"\bLoRa", ["CONFIG_LORA", "CONFIG_LORAWAN"]),
    (r"\b[Uu]serspace\b|\bsyscall|\buser mode\b|CONFIG_USERSPACE", ["CONFIG_USERSPACE"]),
    (r"\b[Mm]odem\b", ["CONFIG_MODEM"]),
    (r"\bTLS\b|\bDTLS\b", ["CONFIG_NET_SOCKETS_SOCKOPT_TLS", "CONFIG_MBEDTLS"]),
]


# ESP-IDF: paths are relative to IDF_PATH; Kconfig comes from sdkconfig.
ESPIDF_PATH_RE = re.compile(r"\b(components/[A-Za-z0-9_./-]*[A-Za-z0-9_])")
ESPIDF_KEYWORD_KCONFIG: list[tuple[str, list[str]]] = [
    (r"\bESP-TEE\b|\bTEE\b|\besp_tee\b", ["CONFIG_SECURE_ENABLE_TEE"]),
    (r"\bBluFi\b|\bBLUFI\b", ["CONFIG_BT_BLE_BLUFI_ENABLE"]),
    (r"\bAVRCP\b|\bA2DP\b|\bHFP\b|\bSPP\b|\bHID Host\b|\bClassic Bluetooth\b|\bBR/EDR\b",
     ["CONFIG_BT_CLASSIC_ENABLED"]),
    (r"\bBluedroid\b", ["CONFIG_BT_BLUEDROID_ENABLED"]),
    (r"\bNimBLE\b", ["CONFIG_BT_NIMBLE_ENABLED"]),
    (r"\bBLE Mesh\b|\bBluetooth Mesh\b", ["CONFIG_BLE_MESH"]),
    (r"\bBluetooth\b|\bBLE\b", ["CONFIG_BT_ENABLED"]),
    (r"\bDHCP server\b|\bdhcpserver\b", ["CONFIG_LWIP_DHCPS"]),
    (r"\bOpenThread\b|\bThread\b", ["CONFIG_OPENTHREAD_ENABLED"]),
    (r"\bWPA3\b|\bSAE\b", ["CONFIG_ESP_WIFI_ENABLE_WPA3_SAE"]),
    (r"\bEAP\b|\bWPA2-Enterprise\b|\benterprise\b", ["CONFIG_ESP_WIFI_ENTERPRISE_SUPPORT"]),
    (r"\bWPS\b", ["CONFIG_ESP_WIFI_WPS_SOFTAP_REGISTRAR", "CONFIG_WPA_WPS_STRICT"]),
    (r"\bmesh\b", ["CONFIG_ESP_WIFI_MESH_ENABLE", "CONFIG_BLE_MESH"]),
    (r"\bWi-?Fi\b", ["CONFIG_ESP_WIFI_ENABLED"]),
    (r"\bUSB\b", ["CONFIG_TINYUSB", "CONFIG_USB_OTG_SUPPORTED"]),
]


@dataclass
class Verdict:
    state: str  # CycloneDX analysis state: not_affected | in_triage
    justification: str | None  # code_not_present | requires_configuration | None
    detail: str
    named_files: list[str]
    compiled_named_files: list[str]


_SYMBOLS: dict[Path, set[str]] = {}


def kconfig_symbols(root: Path) -> set[str]:
    """Every CONFIG_ symbol defined in the Kconfig files under `root` (cached)."""
    root = Path(root).resolve()
    if root not in _SYMBOLS:
        syms = set()
        for f in root.rglob("Kconfig*"):
            if f.is_file() and ".git" not in f.parts:
                try:
                    text = f.read_text(errors="ignore")
                except OSError:
                    continue
                syms |= {"CONFIG_" + m for m in re.findall(r"(?m)^\s*(?:menu)?config\s+([A-Za-z0-9_]+)", text)}
        _SYMBOLS[root] = syms
    return _SYMBOLS[root]


def _norm(p: str) -> str:
    return p.strip("./").replace("\\", "/")


def assess(description: str, compiled_rel_paths: set[str], kconfig: dict[str, str], framework: str = "zephyr",
           components_built: set[str] | None = None, components_known: set[str] | None = None,
           tree_root: Path | None = None, symbols: set[str] | None = None) -> Verdict:
    """compiled_rel_paths: source files in the firmware, relative to the framework root (ZEPHYR_BASE or
    IDF_PATH), e.g. "subsys/net/lib/lwm2m/lwm2m_engine.c". kconfig: {"CONFIG_X": "y", ...}.
    tree_root: the framework root; named paths that do not exist there are not used as evidence.
    symbols: Kconfig symbols defined in this framework version; other options are not used as evidence."""
    path_re = ESPIDF_PATH_RE if framework == "esp-idf" else PATH_RE
    named = sorted({_norm(p) for p in path_re.findall(description)})
    sources = [p for p in named if not p.endswith(".h")]
    if tree_root is not None:  # a renamed file or another repository's path proves nothing
        sources = [p for p in sources if (Path(tree_root) / p).exists()]
    if sources:
        def present(p: str) -> bool:
            if "." in p.rsplit("/", 1)[-1]:  # a file
                return p in compiled_rel_paths
            return any(c.startswith(p + "/") for c in compiled_rel_paths)  # a directory
        compiled = [p for p in sources if present(p)]
        if compiled:
            return Verdict("in_triage", None, "Affected code is in this firmware (compiled and linked): " + ", ".join(compiled),
                           named, compiled)
        return Verdict("not_affected", "code_not_present",
                       "The CVE names " + ", ".join(sources) + "; none of this code is in this firmware (not compiled, or removed by the linker).",
                       named, [])
    if framework == "esp-idf" and components_known:
        # "the esp_tee component", "protocomm", "esp_http_server": named ESP-IDF components.
        # Only distinctive names count (contain "_" or "esp"), so words like "log" or "heap" do not.
        named_c = sorted({c for c in components_known if ("_" in c or "esp" in c) and len(c) > 3
                          and re.search(r"(?<![A-Za-z0-9_])" + re.escape(c) + r"(?![A-Za-z0-9])", description)})
        if named_c:
            built = [c for c in named_c if c in (components_built or set())]
            if built:
                return Verdict("in_triage", None, "Named component is in this build: " + ", ".join(built), [], [])
            return Verdict("not_affected", "code_not_present",
                           "The CVE concerns component " + ", ".join(named_c) + ", which is not part of this build.",
                           [], [])
    enabled_any, mapped = False, []
    for pat, opts in (ESPIDF_KEYWORD_KCONFIG if framework == "esp-idf" else KEYWORD_KCONFIG):
        if symbols is not None:
            opts = [o for o in opts if o in symbols]  # options this framework version does not define prove nothing
        if opts and re.search(pat, description):
            mapped.append((pat, opts))
            if any(kconfig.get(o) in ("y", "m") for o in opts):
                enabled_any = True
    if not kconfig:  # no configuration found: cannot tell what is enabled
        mapped, enabled_any = [], False
    if mapped and not enabled_any:
        opts = sorted({o for _, os_ in mapped for o in os_})
        return Verdict("not_affected", "requires_configuration",
                       "The CVE concerns a subsystem enabled by " + ", ".join(opts) + "; none is enabled in this build.",
                       [], [])
    why = ("Subsystem is enabled in this build." if mapped else
           "The CVE names no file and no known subsystem; review by hand.")
    return Verdict("in_triage", None, why, [], [])
