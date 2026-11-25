import json
import unittest
from pathlib import Path

from fwvex.applicability import assess

FIX = Path(__file__).parent / "fixtures" / "nvd_zephyr_4.4.0_descriptions.json"


class AssessTests(unittest.TestCase):
    def test_named_file_not_compiled(self):
        v = assess("parse_write_op() in subsys/net/lib/lwm2m/lwm2m_message_handling.c handles ...",
                   {"kernel/sched.c", "subsys/bluetooth/host/conn.c"}, {})
        self.assertEqual(v.state, "not_affected")
        self.assertEqual(v.justification, "code_not_present")

    def test_named_file_compiled(self):
        v = assess("net_tcp_foreach() (subsys/net/ip/tcp.c) ...", {"subsys/net/ip/tcp.c"}, {})
        self.assertEqual(v.state, "in_triage")
        self.assertEqual(v.compiled_named_files, ["subsys/net/ip/tcp.c"])

    def test_named_directory(self):
        d = "The Zephyr ext2 filesystem driver (subsys/fs/ext2) trusted the on-disk fields"
        self.assertEqual(assess(d, {"subsys/fs/fs.c"}, {}).state, "not_affected")
        self.assertEqual(assess(d, {"subsys/fs/ext2/ext2_impl.c"}, {}).state, "in_triage")

    def test_trailing_punctuation(self):
        v = assess("See subsys/net/ip/tcp.c.", {"subsys/net/ip/tcp.c"}, {})
        self.assertEqual(v.state, "in_triage")

    def test_header_only_is_not_proof(self):
        v = assess("A macro in include/zephyr/net/net_pkt.h is wrong.", set(), {})
        self.assertNotEqual(v.justification, "code_not_present")

    def test_keyword_subsystem_off(self):
        v = assess("A remote BLE peer can trigger an out-of-bounds write in the Bluetooth host.",
                   set(), {"CONFIG_NET_TCP": "y"})
        self.assertEqual(v.justification, "requires_configuration")

    def test_keyword_subsystem_on(self):
        v = assess("A remote BLE peer can trigger an out-of-bounds write in the Bluetooth host.",
                   set(), {"CONFIG_BT": "y"})
        self.assertEqual(v.state, "in_triage")

    def test_unknown_stays_in_triage(self):
        v = assess("A race condition can corrupt memory.", set(), {})
        self.assertEqual(v.state, "in_triage")

    def test_real_cves_no_false_not_affected_when_everything_compiled(self):
        """If every file a CVE names is compiled in, nothing may be marked code_not_present."""
        import re
        from fwvex.applicability import PATH_RE
        cves = json.loads(FIX.read_text())
        everything = set()
        for c in cves:
            for p in PATH_RE.findall(c["description"]):
                everything.add(p.strip("./"))
                everything.add(p.strip("./") + "/x.c")
        for c in cves:
            v = assess(c["description"], everything, {})
            self.assertNotEqual(v.justification, "code_not_present", c["id"])


if __name__ == "__main__":
    unittest.main()


class SafetyTests(unittest.TestCase):
    def test_path_missing_from_tree_is_not_evidence(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "subsys/net/ip").mkdir(parents=True)
            (Path(t) / "subsys/net/ip/tcp.c").write_text("")
            # names a file that does not exist in this tree (renamed / other repo): no verdict from it
            v = assess("bug in subsys/net/ip/tcp_old.c", set(), {"CONFIG_X": "y"}, tree_root=Path(t))
            self.assertEqual(v.state, "in_triage")
            v = assess("bug in subsys/net/ip/tcp.c", set(), {"CONFIG_X": "y"}, tree_root=Path(t))
            self.assertEqual(v.justification, "code_not_present")

    def test_unknown_kconfig_symbol_is_not_evidence(self):
        v = assess("A remote BLE peer can crash the Bluetooth host.", set(), {"CONFIG_NET_TCP": "y"},
                   symbols={"CONFIG_NET_TCP"})  # this version defines no CONFIG_BT
        self.assertEqual(v.state, "in_triage")

    def test_no_kconfig_means_no_config_verdict(self):
        v = assess("A remote BLE peer can crash the Bluetooth host.", set(), {})
        self.assertEqual(v.state, "in_triage")
