import os
import multiprocessing
import subprocess
import yaml
from time import sleep
from datetime import datetime, timedelta
import sched
import time
from typing import List
from pathlib import Path
from runner.run_fuzz import (
    run_fuzzing_session,
    is_asan,
    setup_system
)


class Fuzzer:
    def __init__(self, name: str, binaries: List, out_root: str = None):
        self.name = name
        self.binaries = binaries
        self.concolic_binaries = []
        self.out_root = os.path.abspath(out_root) if out_root else None

    def set_concolic_bins(self, concolic_bins: List):
        self.concolic_binaries = concolic_bins

    def set_out_root(self, out_root: str):
        self.out_root = os.path.abspath(out_root)


class Benchmark:
    def __init__(self, target_name: str, input_path: str, timeout: int, campaigns: int, fuzzers: List[Fuzzer]):
        self.target_name = target_name
        self.input_path = input_path
        self.timeout = timeout
        self.campaigns = campaigns
        self.fuzzers = fuzzers


def get_fuzzer_output_locations(config: dict, base_output_dir: str, fuzzer_objs: List):
    locations = {}
    for (fuzzer, fuzzer_config) in fuzzer_objs:
        fuzzer_name = fuzzer.name
        explicit_out = fuzzer_config.get('out_root')
        if explicit_out:
            out_root = os.path.abspath(explicit_out)
        else:
            out_root = os.path.abspath(os.path.join(base_output_dir, fuzzer_name))

        expected_campaigns = config.get('campaigns', 0)
        jobs_cfg = fuzzer_config.get('jobs')
        jobs_per_campaign = jobs_cfg if jobs_cfg is not None else max(1, len(fuzzer.binaries))


        locations[fuzzer_name] = {
            'out_root': out_root,
            'campaign_pattern': os.path.join(out_root, 'c{n}'),
            'instance_pattern': os.path.join(out_root, 'c{n}', 'fuzz{idx:02d}'),
            'expected_campaigns': expected_campaigns,
            'jobs_per_campaign': jobs_per_campaign,
        }

    return locations


def parse_duration(duration_str):
    """Convert duration string like '12h' or '1d' to seconds."""
    unit = duration_str[-1]
    value = int(duration_str[:-1])
    if unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400
    elif unit == 'm':
        return value * 60
    else:
        raise ValueError(f"Unsupported duration unit: {unit}")

def schedule_fuzzing_jobs(config_path, output_dir, dry_run: bool = False):
    """Schedule fuzzing jobs based on config file."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    required_fields = ['target_name', 'input_corpora', 'timeout', 'campaigns', 'fuzzers']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field in config: {field}")

    base_timeout = parse_duration(config['timeout'])
    campaigns = config['campaigns']
    scheduler = sched.scheduler(time.time, time.sleep)
    current_time = time.time()

    base_output_dir = os.path.join(output_dir, config['target_name'])
    os.makedirs(base_output_dir, exist_ok=True)

    fuzzer_objs: List[Fuzzer] = []
    for fuzzer_name, fuzzer_config in config['fuzzers'].items():
        if not isinstance(fuzzer_config, dict):
            continue
        binaries = fuzzer_config.get('binaries', [])
        if not binaries:
            print(f"[!] Warning: No binaries specified for {fuzzer_name}, skipping")
            continue

        explicit_out = fuzzer_config.get('out_root')
        f = Fuzzer(fuzzer_name, binaries, out_root=explicit_out)
        concolic = fuzzer_config.get('concolic')
        if concolic:
            con_bins = fuzzer_config.get('concolic_bin')
            if con_bins:
                f.set_concolic_bins(con_bins if isinstance(con_bins, list) else [con_bins])
        fuzzer_objs.append((f, fuzzer_config))

    benchmark = Benchmark(config['target_name'], config['input_corpora'], config['timeout'], campaigns, [f for f, _ in fuzzer_objs])

    locations = get_fuzzer_output_locations(config, base_output_dir, fuzzer_objs)
    print("\n[+] Fuzzer output locations summary:")
    for fname, desc in locations.items():
        print(f" - {fname}: out_root={desc['out_root']} campaigns={desc['expected_campaigns']} jobs_per_campaign={desc['jobs_per_campaign']}")

    if dry_run:
        print("[+] Dry-run enabled, not scheduling any fuzzing jobs.")
        return locations, 0

    accumulated_delay = 0
    for (fuzzer, fuzzer_config) in fuzzer_objs:
        fuzzer_name = fuzzer.name
        fuzzer_bins = fuzzer.binaries

        asan_binaries = []
        for fuzzer_bin in fuzzer_bins:
            try:
                if is_asan(fuzzer_bin):
                    asan_binaries.append(fuzzer_bin)
            except Exception as e:
                print(f"  [!] Warning: could not check ASAN for '{fuzzer_bin}': {e}")

        if asan_binaries:
            print(f"  [+] ASAN-instrumented binaries detected for {fuzzer_name}: {asan_binaries}")

        concolic = fuzzer_config.get('concolic')
        concolic_bin = fuzzer_config.get('concolic_bin')

        if concolic and not concolic_bin:
            print(f"[!] Warning: Concolic execution specified for {fuzzer_name} but no binary provided")
            continue

        start_time = current_time + accumulated_delay
        output_dir = os.path.join(base_output_dir, fuzzer_name)

        # choose number of jobs from config if provided, otherwise default to number of binaries
        jobs = fuzzer_config.get('jobs', len(fuzzer_bins))

        scheduler.enterabs(
            start_time,
            1,
            run_fuzzing_session,
            kwargs={
                'fuzzer_type': fuzzer_name,
                'targets': [os.path.abspath(b) for b in fuzzer_bins],
                'input_dir': config['input_corpora'],
                'output_dir': output_dir,
                'timeout': config['timeout'],
                'clusters': campaigns,
                'jobs': jobs,
                'dictionary': config.get('dict'),
                'concolic': concolic,
                'concolic_bin': concolic_bin,
            }
        )

        accumulated_delay += base_timeout

    # Run the scheduler
    print(f"[*] Starting fuzzing pipeline for {config['target_name']}")
    print(f"[*] Total duration will be: {timedelta(seconds=accumulated_delay)}")
    scheduler.run()

    # return discovered locations and total duration (seconds) for downstream analysis
    return locations

def main():
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="Fuzzing workflow orchestrator")
    parser.add_argument("--config", required=True, help="Path to benchmark configuration YAML file")
    parser.add_argument("--output", required=True, help="Directory for fuzzing results and final report")
    parser.add_argument("--dry-run", action="store_true", help="Print planned paths and mappings but don't schedule or launch fuzzers")
    parser.add_argument("--run-bugs", action="store_true", help="Run bug analysis after scheduling (uses 'oracle_binary' from config)")
    parser.add_argument("--run-coverage", action="store_true", help="Run coverage analysis after scheduling (uses 'coverage_binary' from config)")
    parser.add_argument("--analysis-output", help="Directory where analysis outputs (plots, JSON) will be written", default=None)
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"[!] Error: Config file not found: {args.config}")
        return 1

    # read config early so we can pick up analysis binary paths
    try:
        with open(args.config, 'r') as f:
            cfg = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] Failed to read config: {e}")
        cfg = {}

    setup_system(False)
    try:
        locations = schedule_fuzzing_jobs(args.config, args.output, dry_run=args.dry_run)
    except Exception as e:
        print(f"[!] Error running workflow: {e}")
        return 1

    wait_seconds = parse_duration(cfg.get("timeout")) + 60 # additional 60 s for finishing up benchmarking
    print(f"[*] Waiting {wait_seconds}s for fuzzing to complete before running analysis...")
    time.sleep(wait_seconds)
 

    analysis_out = args.analysis_output or os.path.join(args.output, 'analysis')
    if args.run_bugs:
        asan_bin = cfg.get('oracle_binary')
        if not asan_bin:
            print("[!] --run-bugs requires 'oracle_binary' to be set in the config file")
        else:
            try:
                import analysis.bug_analysis as bug_analysis
                os.makedirs(analysis_out, exist_ok=True)
                bug_dirs = [d['out_root'] for d in locations.values()]
                print(f"[*] Running bug analysis on: {bug_dirs}")
                summary = bug_analysis.get_unique_bugs(asan_bin, bug_dirs)
                out_json = os.path.join(analysis_out, 'bug_summary.json')
                try:
                    with open(out_json, 'w') as jf:
                        import json
                        json.dump(summary, jf, indent=2)
                    print(f"  [+] Bug summary written to {out_json}")
                except Exception as e:
                    print(f"  [!] Failed to write bug summary: {e}")
                # plots
                try:
                    bug_analysis.plot_summary(summary, analysis_out)
                except Exception as e:
                    print(f"  [!] Failed to plot bug summary: {e}")
            except Exception as e:
                print(f"  [!] Bug analysis import or run failed: {e}")

    if args.run_coverage:
        coverage_bin = cfg.get('coverage_binary')
        if not coverage_bin:
            print("[!] --run-coverage requires 'coverage_binary' to be set in the config file")
        else:
            try:
                import analysis.coverage_analysis as cov
                os.makedirs(analysis_out, exist_ok=True)
                fuzzer_dirs = [d['out_root'] for d in locations.values()]
                print(f"[*] Running coverage analysis on: {fuzzer_dirs}")
                all_coverage_data = {}
                for fd in fuzzer_dirs:
                    try:
                        cov_data = cov.analyze_fuzzer_dir(coverage_bin, fd)
                        all_coverage_data.update(cov_data)
                    except Exception as e:
                        print(f"  [!] Error analyzing {fd}: {e}")
                try:
                    cov.plot_violin(all_coverage_data, analysis_out, "Coverage Violin")
                    cov.plot_boxplot(all_coverage_data, analysis_out, "Coverage Boxplot")
                    cov.plot_histogram(all_coverage_data, analysis_out, "Mean Coverage Histogram")
                except Exception as e:
                    print(f"  [!] Failed to create coverage plots: {e}")
            except Exception as e:
                print(f"  [!] Coverage analysis import or run failed: {e}")

    return 0

if __name__ == "__main__":
    exit(main())


