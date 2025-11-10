import os
import multiprocessing
import subprocess
import yaml
from time import sleep
from datetime import datetime, timedelta
import sched
import time
from pathlib import Path
from runner.run_fuzz import (
    run_fuzzing_session,
    is_asan
)

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

def schedule_fuzzing_jobs(config_path):
    """Schedule fuzzing jobs based on config file."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Validate required fields
    required_fields = ['target_name', 'input_corpora', 'timeout', 'campaigns', 'fuzzers']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field in config: {field}")

    base_timeout = parse_duration(config['timeout'])
    campaigns = config['campaigns']  # Note: typo in the example YAML
    scheduler = sched.scheduler(time.time, time.sleep)
    current_time = time.time()

    # Create output directories for each fuzzer
    base_output_dir = os.path.join("output", config['target_name'])
    os.makedirs(base_output_dir, exist_ok=True)

    # Schedule fuzzing sessions for each fuzzer
    accumulated_delay = 0
    for fuzzer_name, fuzzer_config in config['fuzzers'].items():
        if not isinstance(fuzzer_config, dict):
            continue

        # Extract fuzzer binaries
        fuzzer_bins = fuzzer_config.get('binaries', [])
        if not fuzzer_bins or len(fuzzer_bins) < 1:
            print(f"[!] Warning: No binaries specified for {fuzzer_name}, skipping")
            continue

        # Extract fuzzer-specific configuration
        concolic = fuzzer_config.get('concolic')
        concolic_bin = fuzzer_config.get('concolic_bin')
        
        # Validate concolic configuration
        if concolic and not concolic_bin:
            print(f"[!] Warning: Concolic execution specified for {fuzzer_name} but no binary provided")
            continue

        # Calculate delay for this fuzzer
        start_time = current_time + accumulated_delay
        output_dir = os.path.join(base_output_dir, fuzzer_name)

        # Schedule the fuzzing session
        scheduler.enterabs(
            start_time,
            1,  # priority
            run_fuzzing_session,
            kwargs={
                'fuzzer_type': fuzzer_name,
                'target': fuzzer_bins[0],  # First binary is normal
                'asan_target': fuzzer_bins[1] if len(fuzzer_bins) > 1 else None,  # Second binary is ASAN
                'input_dir': config['input_corpora'],
                'output_dir': output_dir,
                'timeout': config['timeout'],
                'clusters': campaigns,
                'jobs': 2,  # Fixed as per requirement (1 normal, 1 ASAN)
                'dictionary': config.get('dict'),
                'concolic': concolic,
                'concolic_bin': concolic_bin,
                'no_setup': False
            }
        )

        # Add delay for next fuzzer
        accumulated_delay += base_timeout

    # Run the scheduler
    print(f"[*] Starting fuzzing pipeline for {config['target_name']}")
    print(f"[*] Total duration will be: {timedelta(seconds=accumulated_delay)}")
    scheduler.run()

def main():
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="Fuzzing workflow orchestrator")
    parser.add_argument("config", help="Path to benchmark configuration YAML file")
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"[!] Error: Config file not found: {args.config}")
        return 1

    try:
        schedule_fuzzing_jobs(args.config)
    except Exception as e:
        print(f"[!] Error running workflow: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())


