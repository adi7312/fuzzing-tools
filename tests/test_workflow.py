import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


class TestWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import workflow
        except ImportError as exc:
            raise unittest.SkipTest(f"workflow import failed: {exc}")
        cls.workflow = workflow

    def test_load_env_file_parses_export_and_quotes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            env = tmp_path / "env.sh"
            env.write_text(
                """
                # comment
                export A=1
                B="two"
                C='three'
                INVALID
                """.strip()
            )

            out = self.workflow.load_env_file(str(env))
            self.assertEqual(out, {"A": "1", "B": "two", "C": "three"})

    def test_get_fuzzer_output_locations_computes_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            cfg = {"campaigns": 2}
            base = str(tmp_path / "out")

            f1 = self.workflow.Fuzzer("aflpp", binaries=["/bin/true"])
            f2 = self.workflow.Fuzzer("hfuzz", binaries=["/bin/true", "/bin/false"])

            fuzzer_objs = [(f1, {}), (f2, {"jobs": 10})]
            loc = self.workflow.get_fuzzer_output_locations(cfg, base, fuzzer_objs)

            self.assertEqual(loc["aflpp"]["expected_campaigns"], 2)
            self.assertEqual(loc["aflpp"]["jobs_per_campaign"], 1)
            self.assertEqual(loc["hfuzz"]["jobs_per_campaign"], 10)
            self.assertTrue(loc["aflpp"]["campaign_pattern"].endswith("c{n}"))

    def test_schedule_fuzzing_jobs_dry_run_returns_locations(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            config = tmp_path / "cfg.yaml"
            config.write_text(
                                textwrap.dedent(
                                        """\
                                        target_name: demo
                                        input_corpora: /tmp/corpus
                                        timeout: 1h
                                        campaigns: 2
                                        fuzzers:
                                            aflpp:
                                                binaries: [/bin/true]
                                                jobs: 2
                                        """
                                ).strip()
            )

            with patch.object(self.workflow.os, "makedirs", lambda *a, **k: None):
                loc = self.workflow.schedule_fuzzing_jobs(str(config), str(tmp_path), dry_run=True)

            self.assertIn("aflpp", loc)
            self.assertEqual(loc["aflpp"]["expected_campaigns"], 2)

    def test_schedule_fuzzing_jobs_requires_fields(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            config = tmp_path / "cfg.yaml"
            config.write_text("target_name: demo\n")

            with self.assertRaises(ValueError):
                self.workflow.schedule_fuzzing_jobs(str(config), str(tmp_path), dry_run=True)
