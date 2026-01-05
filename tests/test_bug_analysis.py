import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestBugAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import analysis.bug_analysis as bug_analysis
        except ImportError as exc:
            raise unittest.SkipTest(f"analysis.bug_analysis import failed: {exc}")
        cls.bug_analysis = bug_analysis

    def test_extract_fuzzer_id_campaign_instance(self):
        fuzz_dir = "/tmp/out"
        crash = "/tmp/out/c2/fuzz03/crashes/id_000001"
        self.assertEqual(self.bug_analysis._extract_fuzzer_id(crash, fuzz_dir), "c2/fuzz03")

    def test_extract_fuzzer_id_fallbacks(self):
        fuzz_dir = "/tmp/out"
        crash = "/tmp/out/fuzz01/crashes/id_1"
        self.assertEqual(self.bug_analysis._extract_fuzzer_id(crash, fuzz_dir), "fuzz01")

        crash2 = "/tmp/out/other/id_2"
        self.assertEqual(self.bug_analysis._extract_fuzzer_id(crash2, fuzz_dir), os.path.basename(crash2))

    def test_count_expected_fuzzers_campaign_layout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "c1" / "fuzz01").mkdir(parents=True)
            (root / "c1" / "fuzz02").mkdir(parents=True)
            (root / "c2" / "fuzz01").mkdir(parents=True)
            self.assertEqual(self.bug_analysis._count_expected_fuzzers(str(root)), 3)

    def test_collect_crash_files_filters_readme_and_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crash_dir = root / "c1" / "fuzz01" / "crashes"
            crash_dir.mkdir(parents=True)
            (crash_dir / "README.txt").write_text("ignore")
            (crash_dir / "a.report").write_text("ignore")
            keep = crash_dir / "id_000001"
            keep.write_bytes(b"X")

            files = self.bug_analysis._collect_crash_files(str(root), tool_name="Honggfuzz")
            self.assertIn(str(keep), files)
            self.assertTrue(all(not p.endswith("README.txt") for p in files))
            self.assertTrue(all(not p.endswith(".report") for p in files))

    def test_analyze_crash_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crash_file = root / "crash"
            crash_file.write_bytes(b"AA")

            def fake_run(*args, **kwargs):
                raise subprocess.TimeoutExpired(cmd=kwargs.get("args", "cmd"), timeout=3)

            with patch.object(self.bug_analysis.subprocess, "run", side_effect=fake_run), patch.object(
                self.bug_analysis.os.path, "getmtime", return_value=100
            ):
                out = self.bug_analysis._analyze_crash(
                    crash_file_path=str(crash_file),
                    fuzz_dir=str(root),
                    tool_name="AFL++",
                    asan_binary_path="/bin/true",
                    llvm_instr=False,
                )

            self.assertEqual(out["error_type"], "timeout")
            self.assertEqual(out["signature"], "generic_dos_signature")
            self.assertEqual(out["tte"], 100)

    def test_analyze_crash_success_uses_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crash_file = root / "crash"
            crash_file.write_bytes(b"AA")

            class R:
                stderr = b"AddressSanitizer: boom"
                stdout = b""

            with patch.object(self.bug_analysis.subprocess, "run", return_value=R()), patch.object(
                self.bug_analysis.os.path, "getmtime", return_value=123
            ), patch.object(
                self.bug_analysis,
                "parse_asan",
                return_value={
                    "source_frames": [{"function": "f", "file": "x.c", "line": 1}],
                    "error_type": "heap",
                },
            ), patch.object(
                self.bug_analysis,
                "get_source_functions",
                return_value=[{"function": "f", "file": "x.c", "line": 1}],
            ), patch.object(
                self.bug_analysis,
                "get_error_type",
                return_value="heap",
            ), patch.object(
                self.bug_analysis,
                "get_stack_signature",
                return_value="sig",
            ):
                out = self.bug_analysis._analyze_crash(
                    crash_file_path=str(crash_file),
                    fuzz_dir=str(root),
                    tool_name="AFL++",
                    asan_binary_path="/bin/true",
                    llvm_instr=False,
                )

            self.assertEqual(
                out,
                {
                    "signature": "sig",
                    "error_type": "heap",
                    "fuzzer_id": os.path.basename(str(crash_file)),
                    "functions": [{"function": "f", "file": "x.c", "line": 1}],
                    "tte": 123,
                },
            )

    def test_summarize_results_effectiveness_and_tte(self):
        bucket = self.bug_analysis.BugBucket(start_time=0)
        b1 = bucket.add("sig1", "heap", "c1/fuzz01", 10)
        b1.add_finder("c1/fuzz02", 30)
        b1.set_stack_if_missing(["frame1"])

        summary = self.bug_analysis._summarize_results({"AFL++": bucket}, {"AFL++": 4})
        afl = summary["AFL++"]
        self.assertEqual(afl["total_fuzzers"], 4)
        self.assertEqual(len(afl["bugs"]), 1)
        bug = afl["bugs"][0]
        self.assertEqual(bug["signature"], "sig1")
        self.assertEqual(bug["count"], 2)
        self.assertEqual(bug["effectiveness"], 0.5)
        self.assertEqual(bug["min_tte"], 10)
        self.assertEqual(bug["mean_tte"], 20)
