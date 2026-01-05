import tempfile
import unittest
from pathlib import Path


class TestStatisticsAndVisuals(unittest.TestCase):
    def test_statistics_tests_import_and_basic_df(self):
        try:
            import analysis.statistics_tests as st
        except ImportError as exc:
            raise unittest.SkipTest(f"analysis.statistics_tests not importable: {exc}")

        df = st.get_branch_cov_df({"A": [1, 2], "B": [3]})
        self.assertEqual(set(df.columns), {"Fuzzer", "Sample", "Coverage"})
        self.assertEqual(len(df), 3)

    def test_bug_visualization_plot_summary_empty(self):
        try:
            from analysis.visuals.bug_visualization import plot_summary
        except ImportError as exc:
            raise unittest.SkipTest(f"bug_visualization not importable: {exc}")

        with tempfile.TemporaryDirectory() as td:
            plot_summary({}, out_dir=str(Path(td)))

    def test_coverage_visualization_exports_no_data(self):
        try:
            from analysis.visuals.coverage_visualization import export_pairwise_heatmap, export_mann_whitney_heatmap
        except ImportError as exc:
            raise unittest.SkipTest(f"coverage_visualization not importable: {exc}")

        with tempfile.TemporaryDirectory() as td:
            export_pairwise_heatmap({}, td)
            export_mann_whitney_heatmap({}, td)
