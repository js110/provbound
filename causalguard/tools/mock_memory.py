from dataclasses import dataclass, field


@dataclass
class MockMemoryTool:
    memories: list[str] = field(default_factory=list)

    def read_memory(self) -> str:
        return "\n".join(self.memories)

    def write_memory(self, content: str) -> None:
        self.memories.append(content)
