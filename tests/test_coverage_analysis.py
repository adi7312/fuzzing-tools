import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestCoverageAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import analysis.coverage_analysis as cov
        except ImportError as exc:
            raise unittest.SkipTest(f"analysis.coverage_analysis import failed: {exc}")
        cls.cov = cov

    def test_get_time_series_buckets_last_window(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "corpus"
            d.mkdir()

            f1 = d / "a"
            f2 = d / "b"
            f1.write_text("a")
            f2.write_text("b")

            os.utime(f1, (1000, 1000))
            os.utime(f2, (1900, 1900))

            buckets = self.cov.get_time_series(str(d), T=1000)
            self.assertTrue(buckets)
            self.assertTrue(all(k % 900 == 0 for k in buckets.keys()))

    def test_get_coverage_success(self):
        class Result:
            def __init__(self, stdout="", stderr=""):
                self.stdout = stdout
                self.stderr = stderr.encode("utf-8")

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, tuple):
                profraw = kwargs["env"]["LLVM_PROFILE_FILE"]
                Path(profraw).write_bytes(b"prof")
                return Result()
            if isinstance(cmd, list) and cmd[:2] == ["llvm-profdata", "merge"]:
                return Result()
            if isinstance(cmd, list) and cmd[:2] == ["llvm-cov", "export"]:
                payload = {"data": [{"totals": {"branches": {"covered": 42}}}]}
                return Result(stdout=json.dumps(payload))
            raise AssertionError(f"unexpected cmd: {cmd}")

        with patch.object(self.cov.subprocess, "run", side_effect=fake_run), patch.object(
            self.cov.os.path, "exists", return_value=True
        ):
            self.assertEqual(self.cov.get_coverage("/bin/true", "/tmp/corpus"), 42)

    def test_get_coverage_retries_then_gives_up(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout"))

        with patch.object(self.cov.subprocess, "run", side_effect=fake_run):
            self.assertEqual(self.cov.get_coverage("/bin/true", "/tmp/corpus", max_retries=2, base_timeout=1), 0)

    def test_analyze_fuzzer_dir_discovers_instances(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / "aflpp_out"
            corpus = out / "c1" / "fuzz01" / "queue"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_text("x")

            with patch.object(self.cov, "get_coverage", return_value=7):
                data = self.cov.analyze_fuzzer_dir("/bin/true", str(out))

            self.assertTrue(data)
            key = next(iter(data.keys()))
            self.assertTrue(key.startswith("AFL++"))
            self.assertEqual(data[key], [7])
