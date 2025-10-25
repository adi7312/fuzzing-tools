#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import tempfile
import re
import json
import concurrent.futures
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime
import time
import shutil

from collections import defaultdict

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Code coverage analysis tool for fuzzers.")
    parser.add_argument("-b", "--binary", required=True, help="Path to the instrumented binary.")
    parser.add_argument("-d", "--directories", required=True, nargs='+', help="List of fuzzer output directories (e.g., aflpp_out, lf_out).")
    parser.add_argument("-o", "--output", default="coverage_analysis", help="Output directory for plots and data.")
    parser.add_argument("-t", "--title", default="Code Coverage Analysis", help="Title for the plots.")
    parser.add_argument("--time-limit", type=int, default=3600*12, help="Time limit in seconds for coverage growth analysis.")
    parser.add_argument("cmdline", nargs=argparse.REMAINDER, help="Command line for the target application.")
    return parser.parse_args()

def get_coverage(binary_path, corpus_dir):
    """
    Run the instrumented binary and get absolute branch coverage.
    """
    print(f"[*] Getting coverage for {corpus_dir}...")
    covered_branches = 0
    
    with tempfile.TemporaryDirectory() as temp_dir:
        profraw_file = os.path.join(temp_dir, "output.profraw")
        env = os.environ.copy()
        env["LLVM_PROFILE_FILE"] = profraw_file

        run_cmd = (binary_path, corpus_dir)
        try:
            subprocess.run(run_cmd, env=env, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            pass  # Non-zero exit status is okay
        except Exception as e:
            print(f"  [!] Error running binary with {corpus_dir}: {e}")

        if not os.path.exists(profraw_file):
            print(f"  [!] No profraw file generated for {corpus_dir}.")
            return 0

        profdata_file = os.path.join(temp_dir, "coverage.profdata")
        merge_cmd = ["llvm-profdata", "merge", "-sparse", profraw_file, "-o", profdata_file]
        try:
            subprocess.run(merge_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"  [!] llvm-profdata failed: {e.stderr}")
            return 0
        except Exception as e:
            print(f"  [!] Error running llvm-profdata: {e}")
            return 0

        cov_cmd = ["llvm-cov", "export", binary_path, f"-instr-profile={profdata_file}", "-summary-only"]
        try:
            result = subprocess.run(cov_cmd, check=True, capture_output=True, text=True)
            cov_data = json.loads(result.stdout)
            
            branches_summary = cov_data['data'][0]['totals']['branches']
            covered_branches = branches_summary['covered']
            
            print(f"  [*] Covered Branches: {covered_branches}")

        except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError, KeyError) as e:
            print(f"  [!] Error processing coverage data: {e}")

    return covered_branches

def format_fuzzer_name(dir_name):
    """Format fuzzer directory names for display."""

    name_map = {
        "aflpp": "AFL++",
        "symcc_afl": "SYMCC+AFL",
        "symcc": "SYMCC",
        "afl": "AFL",
        "hfuzz": "Honggfuzz",
        "libfuzzer": "LibFuzzer",
        "lf": "LibFuzzer"
    }
    
    for key, formatted_name in name_map.items():
        if key in dir_name.lower():
            return formatted_name
    
    # Default to a cleaned-up version of the directory name
    return dir_name.replace('_out', '').replace('_', ' ').title()

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

    return coverage_data


def get_time_series(sub_dir, T):

    ts_file_map = {}
    for file in os.listdir(sub_dir):
        path = os.path.join(sub_dir, file)
        if os.path.isfile(path):
            ts = os.path.getmtime(path)
            ts_file_map[int(ts)] = path
    ts_file_map = dict(sorted(ts_file_map.items()))

    if not ts_file_map:
        return {}

    T_latest = list(ts_file_map)[-1]  
    filtered_map = {ts: f for ts, f in ts_file_map.items() if (T_latest - ts) <= T}
    
    if not filtered_map:
        return {}

    T_0_filtered = next(iter(filtered_map))
    relative_map = {int(ts) - T_0_filtered: f for ts, f in filtered_map.items()}
    delta = 900 # 15 minute buckets
    bucketed = defaultdict(list)
    for rel_time, path in relative_map.items():
        bucket_key = (rel_time // delta) * delta
        bucketed[bucket_key].append(path)
    return bucketed

def analyze_coverage_growth_in_time(binary_path, fuzzer_out_dir, time_limit):
    """
    Analyze and average coverage growth over time across all campaigns for a fuzzer.
    """
    print(f"[*] Analyzing coverage growth for {fuzzer_out_dir}...")
    fuzzer_name = format_fuzzer_name(os.path.basename(fuzzer_out_dir))
    
    campaign_results = defaultdict(list)

    campaign_dirs = sorted(
        [d for d in os.listdir(fuzzer_out_dir) if d.startswith('c') and os.path.isdir(os.path.join(fuzzer_out_dir, d))],
        key=lambda d: int(d[1:])
    )

    for campaign_dir in campaign_dirs:
        campaign_path = os.path.join(fuzzer_out_dir, campaign_dir)
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

            if not corpus_path:
                continue

            time_series_data = get_time_series(corpus_path, time_limit)
            if not time_series_data:
                continue

            coverage_over_time = {}
            all_files_so_far = []
            sorted_buckets = sorted(time_series_data.keys())

            for timestamp_bucket in sorted_buckets:
                all_files_so_far.extend(time_series_data[timestamp_bucket])
                with tempfile.TemporaryDirectory() as temp_dir:
                    for f in all_files_so_far:
                        shutil.copy(f, temp_dir)
                    coverage = get_coverage(binary_path, temp_dir)
                    coverage_over_time[timestamp_bucket] = coverage
            
            if coverage_over_time:
                df = pd.DataFrame(list(coverage_over_time.items()), columns=['Time', 'Coverage'])
                fuzzer_id = fuzzer_instance_dir.replace('fuzzer', '')
                campaign_results[fuzzer_id].append(df)

    averaged_results = {}
    for fuzzer_id, dfs in campaign_results.items():
        if not dfs:
            continue
        
        combined_df = pd.concat(dfs)
        average_df = combined_df.groupby('Time')['Coverage'].mean().reset_index()
        
        build_type = 'ASAN' if fuzzer_id == '02' else 'Normal'
        key = f"{fuzzer_name} ({build_type})"
        averaged_results[key] = dict(zip(average_df['Time'], average_df['Coverage']))

    return averaged_results


def plot_violin(data, output_dir, plot_title):
    """
    Create a single, split violin plot of the coverage data.
    """
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
    sns.violinplot(x="Fuzzer", y="Coverage", hue="ID", data=df, split=True, inner="quartile", order=order, hue_order=hue_order)
    plt.title(plot_title)
    plt.ylabel("Branch Coverage")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    plot_path = os.path.join(output_dir, "coverage_violin_plot.png")
    plt.savefig(plot_path)
    print(f"  [+] Violin plot saved to {plot_path}")
    plt.close()

def plot_coverage_growth(data, output_dir, plot_title):
    """
    Plot coverage growth over time, creating separate plots for ASAN and Normal builds.
    """
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
        
        sorted_fuzzer_names = sorted(plot_data.keys())
        for fuzzer_name in sorted_fuzzer_names:
            coverage_data = plot_data[fuzzer_name]
            if not coverage_data:
                continue
            
            df = pd.DataFrame(list(coverage_data.items()), columns=['Time', 'Coverage'])
            df = df.sort_values(by='Time')
            
            plt.plot(df['Time'], df['Coverage'], linestyle='-', label=fuzzer_name.replace(f' ({build_type})', ''))

        plt.title(f"{plot_title} - {build_type}")
        plt.xlabel("Time (seconds)")
        plt.ylabel("Average Branch Coverage")
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        
        plot_path = os.path.join(output_dir, f"coverage_growth_{build_type.lower()}.png")
        plt.savefig(plot_path)
        print(f"  [+] Coverage growth plot saved to {plot_path}")
        plt.close()

    do_plot(normal_data, "Normal")
    do_plot(asan_data, "ASAN")


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
    
    print("\n[*] Analysis complete. Collected data:")
    print(all_coverage_data)

    plot_violin(all_coverage_data, args.output, args.title)

    all_growth_data = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dir = {
            executor.submit(analyze_coverage_growth_in_time, args.binary, fuzzer_dir, args.time_limit): fuzzer_dir
            for fuzzer_dir in args.directories if os.path.isdir(fuzzer_dir)
        }
        
        for future in concurrent.futures.as_completed(future_to_dir):
            fuzzer_dir = future_to_dir[future]
            try:
                growth_data = future.result()
                if growth_data:
                    all_growth_data.update(growth_data)
            except Exception as exc:
                print(f"  [!] Error analyzing coverage growth for {fuzzer_dir}: {exc}")

    plot_coverage_growth(all_growth_data, args.output, "Coverage Growth Over Time")

    print(f"\n[+] Plots and data saved in '{args.output}'")

if __name__ == "__main__":
    main()
