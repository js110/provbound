import unittest

from causalguard.guard.causal_graph import CausalGraph
from causalguard.guard.trace_schema import SourceTrust, TraceEvent


class GraphScalingTests(unittest.TestCase):
    def test_cycle_does_not_recurse_forever_or_duplicate_a_path(self):
        graph = CausalGraph(
            [
                TraceEvent(
                    event_id="source",
                    kind="tool_observation",
                    content="external instruction",
                    trust=SourceTrust.UNTRUSTED,
                ),
                TraceEvent(
                    event_id="middle",
                    kind="transform",
                    content="derived",
                    trust=SourceTrust.DERIVED,
                    parents=["source", "call"],
                ),
                TraceEvent(
                    event_id="call",
                    kind="tool_call",
                    content="send_email",
                    trust=SourceTrust.DERIVED,
                    parents=["middle"],
                ),
            ]
        )

        paths = graph.untrusted_paths_to("call")

        self.assertEqual(
            [[event.event_id for event in path] for path in paths],
            [["source", "middle", "call"]],
        )

    def test_one_thousand_node_trace_is_traversed_without_recursion_failure(self):
        events = [
            TraceEvent(
                event_id="node-0",
                kind="tool_observation",
                content="external source",
                trust=SourceTrust.UNTRUSTED,
            )
        ]
        events.extend(
            TraceEvent(
                event_id=f"node-{index}",
                kind="transform",
                content=f"step {index}",
                trust=SourceTrust.DERIVED,
                parents=[f"node-{index - 1}"],
            )
            for index in range(1, 1000)
        )

        path = CausalGraph(events).shortest_untrusted_path_to("node-999")

        self.assertEqual(len(path), 1000)
        self.assertEqual(path[0].event_id, "node-0")
        self.assertEqual(path[-1].event_id, "node-999")


if __name__ == "__main__":
    unittest.main()
