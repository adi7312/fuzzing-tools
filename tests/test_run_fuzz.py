import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestRunFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from runner import run_fuzz
        except ImportError as exc:
            raise unittest.SkipTest(f"runner.run_fuzz import failed: {exc}")
        cls.run_fuzz = run_fuzz

    def test_abspath_if_not_none(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x"
            self.assertEqual(self.run_fuzz.abspath_if_not_none(str(p)), os.path.abspath(str(p)))
            self.assertIsNone(self.run_fuzz.abspath_if_not_none(None))

    def test_run_fuzzing_session_validates_targets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(ValueError):
                self.run_fuzz.run_fuzzing_session(
                    fuzzer_type="afl",
                    targets=[],
                    input_dir=str(root / "in"),
                    output_dir=str(root / "out"),
                    clusters=1,
                    jobs=1,
                    timeout="1h",
                )

    def test_run_fuzzing_session_concolic_requires_bin(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(Exception):
                self.run_fuzz.run_fuzzing_session(
                    fuzzer_type="afl",
                    targets=["/bin/true"],
                    input_dir=str(root / "in"),
                    output_dir=str(root / "out"),
                    clusters=1,
                    jobs=1,
                    timeout="1h",
                    concolic="symcc",
                    concolic_bin=None,
                )

    def test_run_fuzzing_session_invokes_launcher_and_writes_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out_dir = root / "out"
            in_dir = root / "in"
            out_dir.mkdir()
            in_dir.mkdir()

            launched = []

            def fake_launch_afl(**kwargs):
                launched.append(kwargs)

            with patch.object(self.run_fuzz, "launch_afl", side_effect=fake_launch_afl), patch.object(
                self.run_fuzz, "setup_system", lambda *a, **k: None
            ), patch.object(self.run_fuzz.multiprocessing, "cpu_count", lambda: 4):
                self.run_fuzz.run_fuzzing_session(
                    fuzzer_type="aflpp",
                    targets=["/bin/true"],
                    input_dir=str(in_dir),
                    output_dir=str(out_dir),
                    clusters=1,
                    jobs=2,
                    timeout="1h",
                )

            self.assertEqual(len(launched), 2)
            cfg = out_dir / "fuzzer_config.yaml"
            self.assertTrue(cfg.exists())
