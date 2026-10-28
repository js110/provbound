import hashlib
import json
import unittest
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[1]
RESULTS = WORKSPACE / "results_v3"


class ResultsV3ManifestTests(unittest.TestCase):
    def test_registered_formal_runs_match_recorded_artifact_hashes(self):
        manifest = json.loads(
            (RESULTS / "manifest.json").read_text(encoding="utf-8")
        )
        runs = {run["run_id"]: run for run in manifest["runs"]}
        self.assertEqual(
            set(runs),
            {
                "offline-frozen-test-v1",
                "provenance-test-v2",
                "real-agent-test-v2-all-providers",
                "agentdojo-test-v4",
            },
        )
        frozen = runs["offline-frozen-test-v1"]
        run_directory = (RESULTS / frozen["path"]).parent
        self._assert_hash(run_directory / "rows.csv", frozen["rows_sha256"])
        self._assert_hash(run_directory / "summary.json", frozen["summary_sha256"])
        self._assert_hash(
            run_directory / "statistics.json", frozen["statistics_sha256"]
        )
        provenance = runs["provenance-test-v2"]
        self._assert_hash(RESULTS / provenance["path"], provenance["output_sha256"])
        for run_id in ("real-agent-test-v2-all-providers", "agentdojo-test-v4"):
            self.assertTrue((RESULTS / runs[run_id]["path"]).is_file(), run_id)

    def _assert_hash(self, path: Path, expected: str) -> None:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(actual, expected, f"registered result changed: {path}")


if __name__ == "__main__":
    unittest.main()
