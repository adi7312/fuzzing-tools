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
    parser = argparse.ArgumentParser(description="Efficient code coverage analysis tool for fuzzers.")
    parser.add_argument("-b", "--binary", required=True, help="Path to the instrumented binary.")
    parser.add_argument("-d", "--directories", required=True, nargs='+', help="List of fuzzer output directories.")
    parser.add_argument("-o", "--output", default="coverage_analysis", help="Output directory for plots and data.")
    parser.add_argument("-t", "--title", default="Code Coverage Analysis", help="Title for the plots.")
    parser.add_argument("--time-limit", type=int, default=3600*12, help="Time limit in seconds for coverage growth analysis.")
    parser.add_argument("cmdline", nargs=argparse.REMAINDER, help="Command line for the target application.")
    return parser.parse_args()

def get_coverage(binary_path, corpus_dir):
    """Run the instrumented binary and get absolute branch coverage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        profraw_file = os.path.join(temp_dir, "output.profraw")
        env = os.environ.copy()
        env["LLVM_PROFILE_FILE"] = profraw_file

        run_cmd = (binary_path, corpus_dir)
        try:
            subprocess.run(run_cmd, env=env, check=True, capture_output=True, text=True, timeout=60)
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
            result = subprocess.run(cov_cmd, check=True, capture_output=True, text=True)
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

                for timestamp_bucket in sorted_buckets:
                    files_to_copy = time_series_data[timestamp_bucket]
                    copy_files_parallel(files_to_copy, temp_dir)
                    coverage = get_coverage(binary_path, temp_dir)
                    coverage_over_time[timestamp_bucket] = coverage
                
                if coverage_over_time:
                    df = pd.DataFrame(list(coverage_over_time.items()), columns=['Time', 'Coverage'])
                    fuzzer_id = fuzzer_instance_dir.replace('fuzz', '')
                    campaign_results[fuzzer_id].append(df)
    
    return fuzzer_name, campaign_results

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
        sorted_fuzzer_names = sorted(plot_data.keys())
        for fuzzer_name in sorted_fuzzer_names:
            coverage_data = plot_data[fuzzer_name]
            if not coverage_data:
                continue
            df = pd.DataFrame(list(coverage_data.items()), columns=['Time', 'Coverage']).sort_values(by='Time')
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
            average_df = combined_df.groupby('Time')['Coverage'].mean().reset_index()
            
            try:
                is_asan = int(fuzzer_id) % 2 == 0
            except (ValueError, TypeError):
                is_asan = False
            build_type = 'ASAN' if is_asan else 'Normal'
            
            key = f"{fuzzer_name} ({build_type})"
            averaged_results[key] = dict(zip(average_df['Time'], average_df['Coverage']))

    plot_coverage_growth(averaged_results, args.output, f"Median Coverage Growth Over Time - {args.title}")
    print(f"\n[+] Plots and data saved in '{args.output}'")

if __name__ == "__main__":
    main()
