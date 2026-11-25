"""`west fwvex ...`: the same as the `fwvex` command, from inside a west workspace."""
import sys
from pathlib import Path

from west.commands import WestCommand

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fwvex.cli import main  # noqa: E402


class FwSbom(WestCommand):
    def __init__(self):
        super().__init__("fwvex", "CycloneDX SBOM and CVE/VEX check for a Zephyr build",
                         "Run `west fwvex sbom -d build` or `west fwvex check -d build`.", accepts_unknown_args=True)

    def do_add_parser(self, parser_adder):
        return parser_adder.add_parser(self.name, help=self.help, description=self.description, add_help=False)

    def do_run(self, args, unknown):
        raise SystemExit(main(unknown))
