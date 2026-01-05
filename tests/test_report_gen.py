import tempfile
import textwrap
import unittest
from pathlib import Path


class TestReportGen(unittest.TestCase):
    def test_format_duration(self):
        from report.report_gen import _format_duration

        self.assertEqual(_format_duration(0), "00:00:00")
        self.assertEqual(_format_duration(1), "00:00:01")
        self.assertEqual(_format_duration(61), "00:01:01")
        self.assertEqual(_format_duration(3661), "01:01:01")
        self.assertIsNone(_format_duration(None))
        self.assertIsNone(_format_duration("bad"))

    def test_collect_coverage_stats_and_table(self):
        from report.report_gen import _collect_coverage_stats, _render_coverage_table

        cov = {
            "aflpp_fuzz01": [1, 2, 3],
            "aflpp_fuzz02": [10, "x", None],
            "libfuzzer_fuzz01": [],
        }
        stats = _collect_coverage_stats(cov)
        self.assertTrue(any(row["fuzzer"] == "AFL++" for row in stats))

        html = _render_coverage_table(cov)
        self.assertIn("<table", html)

    def test_generate_report_writes_file(self):
        from report.report_gen import generate_report

        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            cfg_path = tmp_path / "cfg.yaml"
            cfg_path.write_text(
                                textwrap.dedent(
                                        """\
                                        target_name: demo
                                        timeout: 1h
                                        campaigns: 1
                                        fuzzers:
                                            aflpp:
                                                binaries: [./bin]
                                        """
                                ).strip()
            )

            template_path = tmp_path / "template.html"
            template_path.write_text(
                """
                <html><body>
                <h1>${target_name}</h1>
                <div id='bench'>${benchmark_table}</div>
                <div id='fuzz'>${fuzzer_list}</div>
                <div id='covn'>${coverage_normal_table}</div>
                <div id='cova'>${coverage_asan_table}</div>
                <div id='bugs'>${bug_matrix_table}</div>
                </body></html>
                """.strip()
            )

            analysis_dir = tmp_path / "analysis"
            analysis_dir.mkdir()

            out_path = tmp_path / "out" / "report.html"

            coverage_summary = {"aflpp_fuzz01": [1, 2, 3], "aflpp_fuzz02": [4, 5]}
            bug_summary = {
                "aflpp": {
                    "total_fuzzers": 2,
                    "bugs": [
                        {
                            "error_type": "heap",
                            "signature": "sig",
                            "stack": [{"function": "f", "file": "x.c", "line": 1}],
                            "count": 1,
                            "total_fuzzers": 2,
                            "effectiveness": 0.5,
                            "found_in": ["c1/fuzz01"],
                            "mean_tte": 1,
                            "min_tte": 1,
                            "max_tte": 1,
                        }
                    ],
                }
            }

            rendered_path = generate_report(
                config_path=str(cfg_path),
                analysis_dir=str(analysis_dir),
                coverage_summary=coverage_summary,
                bug_summary=bug_summary,
                template_path=str(template_path),
                output_path=str(out_path),
            )

            self.assertEqual(rendered_path, str(out_path))
            self.assertTrue(out_path.exists())
            html = out_path.read_text(encoding="utf-8")
            self.assertIn("<h1>demo</h1>", html)
