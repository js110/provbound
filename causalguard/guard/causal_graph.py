from causalguard.guard.trace_schema import SourceTrust, TraceEvent


class CausalGraph:
    def __init__(
        self,
        events: list[TraceEvent],
        *,
        max_depth: int = 4096,
        max_paths: int = 1024,
    ):
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if max_paths < 1:
            raise ValueError("max_paths must be at least 1")
        self.events = {event.event_id: event for event in events}
        self.max_depth = max_depth
        self.max_paths = max_paths

    def get(self, event_id: str) -> TraceEvent:
        return self.events[event_id]

    def untrusted_paths_to(self, event_id: str) -> list[list[TraceEvent]]:
        if event_id not in self.events:
            return []
        paths: list[list[TraceEvent]] = []
        seen_paths: set[tuple[str, ...]] = set()
        stack: list[tuple[str, tuple[str, ...], frozenset[str]]] = [
            (event_id, (event_id,), frozenset({event_id}))
        ]

        while stack and len(paths) < self.max_paths:
            current_id, reverse_path, path_seen = stack.pop()
            current = self.events.get(current_id)
            if current is None:
                continue
            if current.trust == SourceTrust.UNTRUSTED:
                ordered_ids = tuple(reversed(reverse_path))
                if ordered_ids not in seen_paths:
                    seen_paths.add(ordered_ids)
                    paths.append([self.events[item] for item in ordered_ids])
                continue
            if len(reverse_path) >= self.max_depth:
                continue
            for parent_id in reversed(current.parents):
                if parent_id in path_seen or parent_id not in self.events:
                    continue
                stack.append(
                    (
                        parent_id,
                        reverse_path + (parent_id,),
                        path_seen | {parent_id},
                    )
                )
        return paths

    def has_untrusted_influence(self, event_id: str) -> bool:
        return bool(self.untrusted_paths_to(event_id))

    def shortest_untrusted_path_to(self, event_id: str) -> list[TraceEvent]:
        paths = self.untrusted_paths_to(event_id)
        if not paths:
            return []
        return min(paths, key=len)
