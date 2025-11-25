#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import tempfile
import json
import concurrent.futures
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import shutil
from collections import defaultdict

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Efficient code coverage analysis tool for fuzzers.")
    parser.add_argument("-b", "--binary", required=True, help="Path to the instrumented binary.")
    parser.add_argument("-d", "--directories", required=True, nargs='+', help="List of fuzzer output directories.")
    parser.add_argument("-o", "--output", default="coverage_analysis", help="Output directory for plots and data.")
    parser.add_argument("-t", "--title", default="Code Coverage Analysis", help="Title for the plots.")
    parser.add_argument("--time-limit", type=int, default=3600*12, help="Time limit in seconds for coverage growth analysis.")
    return parser.parse_args()

def get_coverage(binary_path, corpus_dir):
    """Run the instrumented binary and get absolute branch coverage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        profraw_file = os.path.join(temp_dir, "output.profraw")
        env = os.environ.copy()
        env["LLVM_PROFILE_FILE"] = profraw_file

        run_cmd = (binary_path, corpus_dir)
        try:
            subprocess.run(run_cmd, env=env, check=True, capture_output=True, text=True, timeout=3)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        if not os.path.exists(profraw_file):
            return 0

        profdata_file = os.path.join(temp_dir, "coverage.profdata")
        merge_cmd = ["llvm-profdata", "merge", "-sparse", profraw_file, "-o", profdata_file]
        try:
            subprocess.run(merge_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"  [!] llvm-profdata failed: {e.stderr}")
            return 0

        cov_cmd = ["llvm-cov", "export", binary_path, f"-instr-profile={profdata_file}", "-summary-only"]
        try:
            result = subprocess.run(cov_cmd, check=True, capture_output=True, text=True,timeout=3)
            cov_data = json.loads(result.stdout)
            branches_summary = cov_data['data'][0]['totals']['branches']
            return branches_summary['covered']
        except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError, KeyError) as e:
            print(f"  [!] Error processing coverage data: {e}")
    return 0

def format_fuzzer_name(dir_name):
    """Format fuzzer directory names for display."""
    name_map = {"aflpp": "AFL++", "symcc_afl": "SYMCC+AFL", "symcc": "SYMCC", "afl": "AFL", "hfuzz": "Honggfuzz", "libfuzzer": "LibFuzzer", "lf": "LibFuzzer"}
    base_name = os.path.basename(dir_name)
    for key, formatted_name in name_map.items():
        if key in base_name.lower():
            return formatted_name
    return base_name.replace('_out', '').replace('_', ' ').title()

def get_time_series(sub_dir, T):
    """Get a time series of files, bucketed by modification time."""
    ts_file_map = {}
    for file in os.listdir(sub_dir):
        path = os.path.join(sub_dir, file)
        if os.path.isfile(path):
            ts = os.path.getmtime(path)
            ts_file_map[int(ts)] = path
    
    if not ts_file_map:
        return {}

    sorted_ts = sorted(ts_file_map.keys())
    T_latest = sorted_ts[-1]
    T_0 = T_latest - T
    
    filtered_map = {ts: f for ts, f in ts_file_map.items() if ts >= T_0}
    if not filtered_map:
        return {}

    T_0_filtered = min(filtered_map.keys())
    relative_map = {int(ts) - T_0_filtered: f for ts, f in filtered_map.items()}
    
    delta = 900
    bucketed = defaultdict(list)
    for rel_time, path in relative_map.items():
        bucket_key = (rel_time // delta) * delta
        bucketed[bucket_key].append(path)
    return bucketed

def copy_files_parallel(files, dest_dir):
    """Copy files to a directory in parallel."""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        list(executor.map(lambda f: shutil.copy(f, dest_dir), files))

def analyze_coverage_growth_in_time(binary_path, fuzzer_out_dir, time_limit):
    """Analyze coverage growth and return raw campaign results for a fuzzer directory."""
    print(f"[*] Analyzing coverage growth for {fuzzer_out_dir}...")
    fuzzer_name = format_fuzzer_name(fuzzer_out_dir)
    campaign_results = defaultdict(list)

    campaign_dirs = sorted([d for d in os.listdir(fuzzer_out_dir) if d.startswith('c') and os.path.isdir(os.path.join(fuzzer_out_dir, d))], key=lambda d: int(d[1:]))

    for campaign_dir in campaign_dirs:
        campaign_path = os.path.join(fuzzer_out_dir, campaign_dir)
        for fuzzer_instance_dir in os.listdir(campaign_path):
            if not fuzzer_instance_dir.startswith('fuzz'):
                continue
            
            fuzzer_instance_path = os.path.join(campaign_path, fuzzer_instance_dir)
            corpus_path = next((os.path.join(fuzzer_instance_path, d) for d in ['queue', 'corpus'] if os.path.isdir(os.path.join(fuzzer_instance_path, d))), None)
            if not corpus_path and os.path.isdir(fuzzer_instance_path) and any(os.path.isfile(os.path.join(fuzzer_instance_path, f)) for f in os.listdir(fuzzer_instance_path)):
                corpus_path = fuzzer_instance_path
            if not corpus_path:
                continue

            time_series_data = get_time_series(corpus_path, time_limit)
            if not time_series_data:
                continue

            with tempfile.TemporaryDirectory() as temp_dir:
                coverage_over_time = {}
                sorted_buckets = sorted(time_series_data.keys())
                last_coverage = 0

                for timestamp_bucket in sorted_buckets:
                    files_to_copy = time_series_data[timestamp_bucket]
                    copy_files_parallel(files_to_copy, temp_dir)
                    coverage = get_coverage(binary_path, temp_dir)
                    if coverage < last_coverage:
                        coverage = last_coverage
                    coverage_over_time[timestamp_bucket] = coverage
                    last_coverage = coverage
                
                if coverage_over_time:
                    df = pd.DataFrame(list(coverage_over_time.items()), columns=['Time', 'Coverage'])
                    fuzzer_id = fuzzer_instance_dir.replace('fuzz', '')
                    campaign_results[fuzzer_id].append(df)
    
    return fuzzer_name, campaign_results


def plot_violin(data, output_dir, plot_title):
    print("[*] Creating violin plot...")
    
    if not data:
        print("  [!] No data to plot.")
        return

    plot_data = []
    for key, coverages in data.items():
        parts = key.rsplit('_', 1)
        fuzzer_name = parts[0]
        fuzzer_id = parts[1] if len(parts) > 1 else '1'
        for cov in coverages:
            plot_data.append({"Fuzzer": fuzzer_name, "ID": fuzzer_id, "Coverage": cov})
    
    if not plot_data:
        print("  [!] No data to create a plot from.")
        return
        
    df = pd.DataFrame(plot_data)
    if df.empty:
        print("  [!] DataFrame is empty, skipping plot.")
        return

    # Rename IDs for clarity in the plot legend
    df['ID'] = df['ID'].replace({'fuzz01': 'Normal', 'fuzz02': 'ASAN'})
    hue_order = ['Normal', 'ASAN']

    # Order fuzzers by mean coverage (descending)
    mean_cov = df.groupby('Fuzzer')['Coverage'].mean().sort_values(ascending=False)
    order = mean_cov.index

    plt.figure(figsize=(12, 8))
    sns.set(style="whitegrid")

    # --- Main improvement section ---
    ax = sns.violinplot(
        x="Fuzzer",
        y="Coverage",
        hue="ID",
        data=df,
        split=True,
        inner="box",              # clearer than quartile lines
        bw_adjust=0.5,            # reduces oversmoothing for small samples
        cut=0,                    # prevents extending beyond data range
        scale="width",            # keeps violins visually balanced
        order=order,
        hue_order=hue_order
    )

    # Overlay individual data points for context
    sns.stripplot(
        x="Fuzzer",
        y="Coverage",
        hue="ID",
        data=df,
        order=order,
        hue_order=hue_order,
        dodge=True,
        jitter=True,
        alpha=0.5,
        color="k",
        ax=ax
    )

    plt.title(plot_title)
    plt.ylabel("Branch Coverage")
    plt.xlabel("Fuzzer")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Prevent duplicate legends (from stripplot)
    handles, labels = ax.get_legend_handles_labels()
    plt.legend(handles[:2], labels[:2], title="ID")

    plot_path = os.path.join(output_dir, "coverage_violin_plot.png")
    plt.savefig(plot_path)
    plt.close()
    print(f"  [+] Violin plot saved to {plot_path}")


def analyze_fuzzer_dir(binary_path, fuzzer_out_dir):
    """
    Analyze a single fuzzer's output directory.
    The fuzzer name is inferred from the directory name.
    """
    coverage_data = {}
    fuzzer_name = format_fuzzer_name(os.path.basename(fuzzer_out_dir))

    # Directory structure: fuzzer_name_out/c{campain_id}/fuzzer{id}
    campaign_dirs = sorted(
        [d for d in os.listdir(fuzzer_out_dir) if d.startswith('c') and os.path.isdir(os.path.join(fuzzer_out_dir, d))],
        key=lambda d: int(d[1:])
    )
    for campaign_dir in campaign_dirs:
        campaign_path = os.path.join(fuzzer_out_dir, campaign_dir)
        if not os.path.isdir(campaign_path):
            continue

        for fuzzer_instance_dir in os.listdir(campaign_path):
            if not fuzzer_instance_dir.startswith('fuzz'):
                continue
            
            fuzzer_instance_path = os.path.join(campaign_path, fuzzer_instance_dir)
            corpus_path = None
            possible_corpus_dirs = ['queue', 'corpus']
            for d in possible_corpus_dirs:
                path = os.path.join(fuzzer_instance_path, d)
                if os.path.isdir(path):
                    corpus_path = path
                    break

            if not corpus_path and os.path.isdir(fuzzer_instance_path):
                if any(os.path.isfile(os.path.join(fuzzer_instance_path, f)) for f in os.listdir(fuzzer_instance_path)):
                    corpus_path = fuzzer_instance_path
            
            if corpus_path:
                fuzzer_id = fuzzer_instance_dir.replace('fuzzer', '')
                key = f"{fuzzer_name}_{fuzzer_id}"
                coverage = get_coverage(binary_path, corpus_path)
                if key not in coverage_data:
                    coverage_data[key] = []
                coverage_data[key].append(coverage)
            else:
                print(f"  [!] No corpus found for instance {fuzzer_instance_dir} in {campaign_path}")

    return coverage_data

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

    # Separate data into Normal and ASAN
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


def plot_boxplot(data, output_dir, plot_title):
    """
    Create a boxplot of coverage data (Normal vs ASAN) for each fuzzer.
    """
    print("[*] Creating boxplot...")

    if not data:
        print("  [!] No data to plot.")
        return

    plot_data = []
    for key, coverages in data.items():
        parts = key.rsplit('_', 1)
        fuzzer_name = parts[0]
        fuzzer_id = parts[1] if len(parts) > 1 else '1'
        for cov in coverages:
            plot_data.append({"Fuzzer": fuzzer_name, "ID": fuzzer_id, "Coverage": cov})
    
    if not plot_data:
        print("  [!] No data to create a plot from.")
        return

    df = pd.DataFrame(plot_data)
    if df.empty:
        print("  [!] DataFrame is empty, skipping plot.")
        return

    # Rename IDs for clarity
    df['ID'] = df['ID'].replace({'fuzz01': 'Normal', 'fuzz02': 'ASAN'})
    hue_order = ['Normal', 'ASAN']

    # Order fuzzers by mean coverage (descending)
    mean_cov = df.groupby('Fuzzer')['Coverage'].mean().sort_values(ascending=False)
    order = mean_cov.index

    plt.figure(figsize=(12, 8))
    sns.set(style="whitegrid")

    # --- Main plot ---
    ax = sns.boxplot(
        x="Fuzzer",
        y="Coverage",
        hue="ID",
        data=df,
        order=order,
        hue_order=hue_order,
        width=0.6,
        fliersize=5,        # control size of outlier markers
        linewidth=1.2
    )

    # Optional: overlay actual data points
    sns.stripplot(
        x="Fuzzer",
        y="Coverage",
        hue="ID",
        data=df,
        order=order,
        hue_order=hue_order,
        dodge=True,
        jitter=True,
        alpha=0.4,
        color="k",
        ax=ax
    )

    plt.title(plot_title)
    plt.ylabel("Branch Coverage")
    plt.xlabel("Fuzzer")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Remove duplicate legend from stripplot overlay
    handles, labels = ax.get_legend_handles_labels()
    plt.legend(handles[:2], labels[:2], title="ID")

    plot_path = os.path.join(output_dir, "coverage_boxplot.png")
    plt.savefig(plot_path)
    plt.close()
    print(f"  [+] Boxplot saved to {plot_path}")

def main():
    """Main function."""
    args = parse_args()
    if not os.path.exists(args.binary):
        print(f"Error: Binary not found at '{args.binary}'")
        sys.exit(1)
    os.makedirs(args.output, exist_ok=True)


    all_coverage_data = {}
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dir = {
            executor.submit(analyze_fuzzer_dir, args.binary, fuzzer_dir): fuzzer_dir
            for fuzzer_dir in args.directories if os.path.isdir(fuzzer_dir)
        }
        
        for future in concurrent.futures.as_completed(future_to_dir):
            fuzzer_dir = future_to_dir[future]
            try:
                coverage_data = future.result()
                all_coverage_data.update(coverage_data)
            except Exception as exc:
                print(f"  [!] Error analyzing directory {fuzzer_dir}: {exc}")
    
    plot_violin(all_coverage_data, args.output, args.title)
    plot_boxplot(all_coverage_data, args.output, args.title)
    plot_histogram(all_coverage_data, args.output, args.title)

    all_campaign_results = defaultdict(lambda: defaultdict(list))
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dir = {
            executor.submit(analyze_coverage_growth_in_time, args.binary, fuzzer_dir, args.time_limit): fuzzer_dir
            for fuzzer_dir in args.directories if os.path.isdir(fuzzer_dir)
        }
        for future in concurrent.futures.as_completed(future_to_dir):
            fuzzer_dir = future_to_dir[future]
            try:
                fuzzer_name, campaign_results = future.result()
                for fuzzer_id, dfs in campaign_results.items():
                    all_campaign_results[fuzzer_name][fuzzer_id].extend(dfs)
            except Exception as exc:
                print(f"  [!] Error analyzing coverage growth for {fuzzer_dir}: {exc}")

    averaged_results = {}
    for fuzzer_name, fuzzer_id_data in all_campaign_results.items():
        for fuzzer_id, dfs in fuzzer_id_data.items():
            if not dfs:
                continue
            
            combined_df = pd.concat(dfs)
            # Use median as it's more robust to outliers from failed runs
            median_df = combined_df.groupby('Time')['Coverage'].median().reset_index()
            
            try:
                is_asan = int(fuzzer_id) % 2 == 0
            except (ValueError, TypeError):
                is_asan = False
            build_type = 'ASAN' if is_asan else 'Normal'
            
            key = f"{fuzzer_name} ({build_type})"
            
            # Enforce monotonicity on the final median data
            sorted_times = sorted(median_df['Time'])
            coverage_dict = dict(zip(median_df['Time'], median_df['Coverage']))
            
            last_coverage = 0
            final_coverage_over_time = {}
            for t in sorted_times:
                coverage = coverage_dict[t]
                if coverage < last_coverage:
                    coverage = last_coverage
                final_coverage_over_time[t] = coverage
                last_coverage = coverage
            
            averaged_results[key] = final_coverage_over_time
    plot_coverage_growth(averaged_results, args.output, f"Median Coverage Growth Over Time - {args.title}")
    print(f"\n[+] Plots and data saved in '{args.output}'")

if __name__ == "__main__":
    main()
