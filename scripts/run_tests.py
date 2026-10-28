"""Run the repository test suite without mutating frozen v3 source files."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    if sys.version_info < (3, 14):
        # Python 3.14 defers evaluation of the frozen runner's local annotation.
        # Older supported interpreters need the symbol in that module's globals.
        from causalguard.guard.trace_schema import ToolCall
        from experiments_v3 import real_agent_benchmark

        real_agent_benchmark.ToolCall = ToolCall

    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
