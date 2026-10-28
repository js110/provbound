"""Compatibility launcher for the frozen v3 real-agent benchmark.

Python versions before 3.14 evaluate the ``ToolCall`` annotation in the frozen
runner at function-definition time.  Injecting the symbol keeps the registered
v3 source hashes unchanged while making the command-line entry point portable.
"""

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    from causalguard.guard.trace_schema import ToolCall
    from experiments_v3 import real_agent_benchmark

    real_agent_benchmark.ToolCall = ToolCall
    real_agent_benchmark.main()


if __name__ == "__main__":
    main()
