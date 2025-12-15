import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from collections import defaultdict
from analysis.statistics_tests import pairwise_unique_coverage, mann_whitney_heatmap


def export_pairwise_heatmap(data, output_dir):
    print("[*] Creating pairwise coverage heatmap...")
    if not data:
        print("[!] No coverage data available for heatmap.")
        return
    subsets = [
        ("coverage_pairwise_heatmap_normal", "Pairwise Coverage Advantage (Normal)", {k: v for k, v in data.items() if "fuzz01" in k}),
        ("coverage_pairwise_heatmap_asan", "Pairwise Coverage Advantage (ASAN)", {k: v for k, v in data.items() if "fuzz02" in k}),
    ]
    any_exported = False
    for filename, title, subset in subsets:
        if not subset:
            print(f"[!] Skipping {title} (no data).")
            continue
        figure_path = os.path.join(output_dir, f"{filename}.png")
        csv_path = os.path.join(output_dir, f"{filename}.csv")
        matrix = pairwise_unique_coverage(subset, save_path=figure_path, title=title)
        matrix.to_csv(csv_path)
        any_exported = True
        print(f"[+] Pairwise heatmap saved to {figure_path}")
    if not any_exported:
        print("[!] No pairwise heatmaps generated.")


def export_mann_whitney_heatmap(data, output_dir):
    print("[*] Creating Mann-Whitney heatmaps...")
    if not data:
        print("[!] No coverage data available for statistical heatmaps.")
        return
    subsets = [
        ("mann_whitney_heatmap_normal", "Wilcoxon rank-sum test (Normal)", {k: v for k, v in data.items() if "fuzz01" in k}),
        ("mann_whitney_heatmap_asan", "Wilcoxon rank-sum test (ASAN)", {k: v for k, v in data.items() if "fuzz02" in k}),
    ]
    any_exported = False
    for filename, title, subset in subsets:
        if not subset:
            print(f"[!] Skipping {title} (no data).")
            continue
        figure_path = os.path.join(output_dir, f"{filename}.png")
        csv_path = os.path.join(output_dir, f"{filename}.csv")
        matrix = mann_whitney_heatmap(subset, save_path=figure_path, title=title)
        matrix.to_csv(csv_path)
        any_exported = True
        print(f"[+] Mann-Whitney heatmap saved to {figure_path}")
    if not any_exported:
        print("[!] No Mann-Whitney heatmaps generated.")


def plot_violin(data, output_dir, plot_title):
    print("[*] Creating violin plots...")

    if not data:
        print("  [!] No data to plot.")
        return

    def infer_build_type(key: str) -> str:
        suffix = key.rsplit('_', 1)[-1].lower()
        digits = ''.join(ch for ch in suffix if ch.isdigit())
        if digits:
            try:
                return 'ASAN' if int(digits) % 2 == 0 else 'Normal'
            except ValueError:
                pass
        return 'ASAN' if 'asan' in key.lower() else 'Normal'

    buckets = {'Normal': {}, 'ASAN': {}}
    for key, coverages in data.items():
        build = infer_build_type(key)
        buckets.setdefault(build, {})[key] = coverages

    sns.set(style="whitegrid")

    def do_plot(subset, build_type):
        if not subset:
            print(f"  [!] No data to plot for {build_type} builds.")
            return
        rows = []
        for key, coverages in subset.items():
            fuzzer_name = key.rsplit('_', 1)[0]
            for cov in coverages:
                rows.append({"Fuzzer": fuzzer_name, "Coverage": cov})
        if not rows:
            print(f"  [!] No coverage samples for {build_type} builds.")
            return
        df = pd.DataFrame(rows)
        if df.empty:
            print(f"  [!] DataFrame empty for {build_type}, skipping plot.")
            return
        order = df.groupby('Fuzzer')['Coverage'].mean().sort_values(ascending=False).index
        plt.figure(figsize=(12, 8))
        ax = sns.violinplot(
            x="Fuzzer",
            y="Coverage",
            data=df,
            inner="box",
            bw_adjust=0.5,
            cut=0,
            scale="width",
            order=order,
            palette="viridis"
        )
        sns.stripplot(
            x="Fuzzer",
            y="Coverage",
            data=df,
            order=order,
            dodge=False,
            jitter=True,
            alpha=0.5,
            color="k",
            ax=ax
        )
        plt.title(f"{plot_title} - {build_type}")
        plt.ylabel("Branch Coverage")
        plt.xlabel("Fuzzer")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plot_path = os.path.join(output_dir, f"coverage_violin_{build_type.lower()}.png")
        plt.savefig(plot_path)
        plt.close()
        print(f"  [+] Violin plot saved to {plot_path}")

    do_plot(buckets.get('Normal'), 'Normal')
    do_plot(buckets.get('ASAN'), 'ASAN')


def plot_coverage_growth(data, output_dir, plot_title):
    """Plot coverage growth over time, creating separate plots for ASAN and Normal builds."""
    print("[*] Creating coverage growth plots...")
    if not data:
        print("  [!] No data to plot.")
        return

    normal_data = {k: v for k, v in data.items() if 'ASAN' not in k}
    asan_data = {k: v for k, v in data.items() if 'ASAN' in k}

    def do_plot(plot_data, build_type):
        if not plot_data:
            print(f"  [!] No data to plot for {build_type} builds.")
            return
        plt.figure(figsize=(12, 8))
        import matplotlib.ticker as mticker
        sorted_fuzzer_names = sorted(plot_data.keys())
        xmax = 0.0
        for fuzzer_name in sorted_fuzzer_names:
            coverage_data = plot_data[fuzzer_name]
            if not coverage_data:
                continue
            df = pd.DataFrame(list(coverage_data.items()), columns=['Time', 'Coverage']).sort_values(by='Time')
            # convert seconds to hours for x-axis
            df['TimeHours'] = df['Time'] / 3600.0
            plt.plot(df['TimeHours'], df['Coverage'], linestyle='-', label=fuzzer_name.replace(f' ({build_type})', ''))
            xmax = max(xmax, df['TimeHours'].max())

        plt.title(f"{plot_title} - {build_type}")
        plt.xlabel("Time (hours)")
        plt.ylabel("Average Branch Coverage")
        plt.grid(True)
        plt.legend()

        # start x-axis at 15 minutes (0.25 hours) if the data extends beyond that,
        # otherwise keep the x-axis starting at 0 to avoid empty plots.
        xmin = 0.25 if xmax > 0.25 else 0.0
        if xmax > 0:
            plt.xlim(left=xmin, right=xmax)
        ax = plt.gca()
        ax.xaxis.set_major_formatter(mticker.FormatStrFormatter('%.2f'))
        plt.tight_layout()

        plot_path = os.path.join(output_dir, f"coverage_growth_{build_type.lower()}.png")
        plt.savefig(plot_path)
        print(f"  [+] Coverage growth plot saved to {plot_path}")
        plt.close()

    do_plot(normal_data, "Normal")
    do_plot(asan_data, "ASAN")

def plot_histogram(data, output_dir, plot_title):
    """Create a histogram of mean total reached coverage for each fuzzer."""
    print("[*] Creating histogram of mean coverage...")

    if not data:
        print("  [!] No data to plot.")
        return

    normal_data = {k: v for k, v in data.items() if 'fuzz01' in k}
    asan_data = {k: v for k, v in data.items() if 'fuzz02' in k}

    def do_plot(plot_data, build_type):
        if not plot_data:
            print(f"  [!] No data to plot for {build_type} builds.")
            return

        mean_coverage_data = defaultdict(list)
        for key, coverages in plot_data.items():
            fuzzer_name = key.rsplit('_', 1)[0]
            mean_coverage_data[fuzzer_name].extend(coverages)

        processed_plot_data = []
        for fuzzer_name, coverages in mean_coverage_data.items():
            if coverages:
                mean_cov = sum(coverages) / len(coverages)
                processed_plot_data.append({"Fuzzer": fuzzer_name, "Mean Coverage": mean_cov})

        if not processed_plot_data:
            print(f"  [!] No data to create a plot from for {build_type} builds.")
            return

        df = pd.DataFrame(processed_plot_data)
        if df.empty:
            print(f"  [!] DataFrame is empty for {build_type}, skipping plot.")
            return

        df = df.sort_values(by='Mean Coverage', ascending=False)

        plt.figure(figsize=(12, 8))
        sns.set(style="whitegrid")
        ax = sns.barplot(x="Fuzzer", y="Mean Coverage", data=df, palette="viridis")

        plt.title(f"Mean Total Reached Coverage - {plot_title} - {build_type}")
        plt.ylabel("Mean Branch Coverage")
        plt.xlabel("Fuzzer")
        plt.xticks(rotation=45)
        plt.tight_layout()

        for p in ax.patches:
            ax.annotate(f"{p.get_height():.1f}",
                        (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center',
                        xytext=(0, 9),
                        textcoords='offset points')

        plot_path = os.path.join(output_dir, f"mean_coverage_histogram_{build_type.lower()}.png")
        plt.savefig(plot_path)
        plt.close()
        print(f"  [+] Histogram saved to {plot_path}")

    do_plot(normal_data, "Normal")
    do_plot(asan_data, "ASAN")