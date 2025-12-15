import argparse
import os
import subprocess
import sys
import tempfile
import json
import concurrent.futures
import pandas as pd
import shutil

from collections import defaultdict
from utilities.utils import format_fuzzer_name
from analysis.visuals.coverage_visualization import (
    export_pairwise_heatmap,
    export_mann_whitney_heatmap,
    plot_coverage_growth,
    plot_histogram,
    plot_violin,
)


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
    with concurrent.futures.ThreadPoolExecutor() as executor:
        list(executor.map(lambda f: shutil.copy(f, dest_dir), files))

def analyze_coverage_growth_in_time(binary_path, fuzzer_out_dir, time_limit):
    print(f"[*] Analyzing coverage growth for {fuzzer_out_dir}...")
    print(f"d1: {fuzzer_out_dir}")
    if(fuzzer_out_dir[-1] == '/'):
        tmp = list(fuzzer_out_dir)
        tmp[-1] = ''
        fuzzer_out_dir = ''.join(list(tmp))
    fuzzer_name = format_fuzzer_name(fuzzer_out_dir)
    print(f"Fuzzer name: {fuzzer_name}")
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



def analyze_fuzzer_dir(binary_path, fuzzer_out_dir):
    """
    Analyze a single fuzzer's output directory.
    The fuzzer name is inferred from the directory name.
    """
    coverage_data = {}
    print(f"d1: {fuzzer_out_dir}")
    if(fuzzer_out_dir[-1] == '/'):
        tmp = list(fuzzer_out_dir)
        tmp[-1] = ''
        fuzzer_out_dir = ''.join(list(tmp))
    fuzzer_name = format_fuzzer_name(fuzzer_out_dir)

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



def run_cov_analysis(oracle_binary, directories, output, title, time_limit):
    if not os.path.exists(oracle_binary):
        print(f"Error: Binary not found at '{oracle_binary}'")
        sys.exit(1)
    os.makedirs(output, exist_ok=True)


    all_coverage_data = {}
    print(directories)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dir = {
            executor.submit(analyze_fuzzer_dir, oracle_binary, fuzzer_dir): fuzzer_dir
            for fuzzer_dir in directories if os.path.isdir(fuzzer_dir)
        }
        
        for future in concurrent.futures.as_completed(future_to_dir):
            fuzzer_dir = future_to_dir[future]
            try:
                coverage_data = future.result()
                all_coverage_data.update(coverage_data)
            except Exception as exc:
                print(f"  [!] Error analyzing directory {fuzzer_dir}: {exc}")
    
    plot_violin(all_coverage_data, output, title)
    plot_histogram(all_coverage_data, output, title)
    export_pairwise_heatmap(all_coverage_data, output)
    export_mann_whitney_heatmap(all_coverage_data, output)

    all_campaign_results = defaultdict(lambda: defaultdict(list))
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dir = {
            executor.submit(analyze_coverage_growth_in_time, oracle_binary, fuzzer_dir, time_limit): fuzzer_dir
            for fuzzer_dir in directories if os.path.isdir(fuzzer_dir)
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
            median_df = combined_df.groupby('Time')['Coverage'].median().reset_index()
            
            try:
                is_asan = int(fuzzer_id) % 2 == 0
            except (ValueError, TypeError):
                is_asan = False
            build_type = 'ASAN' if is_asan else 'Normal'
            
            key = f"{fuzzer_name} ({build_type})"
            
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
    print(averaged_results)
    plot_coverage_growth(averaged_results, output, f"Median Coverage Growth Over Time - {title}")
    print(f"\n[+] Plots and data saved in '{output}'")
    return all_coverage_data

def parse_args():
    parser = argparse.ArgumentParser(description="Efficient code coverage analysis tool for fuzzers.")
    parser.add_argument("-b", "--binary", required=True, help="Path to the instrumented binary.")
    parser.add_argument("-d", "--directories", required=True, nargs='+', help="List of fuzzer output directories.")
    parser.add_argument("-o", "--output", default="coverage_analysis", help="Output directory for plots and data.")
    parser.add_argument("-t", "--title", default="Code Coverage Analysis", help="Title for the plots.")
    parser.add_argument("--time-limit", type=int, default=3600*12, help="Time limit in seconds for coverage growth analysis.")
    return parser.parse_args()

def main():
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
    plot_histogram(all_coverage_data, args.output, args.title)
    export_pairwise_heatmap(all_coverage_data, args.output)
    export_mann_whitney_heatmap(all_coverage_data, args.output)

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
            median_df = combined_df.groupby('Time')['Coverage'].median().reset_index()
            
            try:
                is_asan = int(fuzzer_id) % 2 == 0
            except (ValueError, TypeError):
                is_asan = False
            build_type = 'ASAN' if is_asan else 'Normal'
            
            key = f"{fuzzer_name} ({build_type})"
            
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
    return all_coverage_data

if __name__ == "__main__":
    main()
