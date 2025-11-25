import json
from typing import List, Dict, Any
import hashlib
import subprocess
import os
import matplotlib.pyplot as plt
from collections import defaultdict
from statistics import mean 

from analysis.parse.parse_asan import parse_asan
from analysis.parse.parse_afl import get_start_time as get_start_time_afl
from analysis.parse.parse_hfuzz import get_start_time as get_start_time_hfuzz

class Bug:
    def __init__(self, signature: str, error_type: str):
        self.signature = signature
        self.error_type = error_type
        self.found_in = {} # fuzzer_id : tte
        self.stack = []

    def add_finder(self, fuzzer_id: str, tte: int):
        if not self.found_in.get(fuzzer_id):
            self.found_in[fuzzer_id] = tte

    def set_stack_if_missing(self, function_stack: List[str]):
        if not self.stack and function_stack:
            self.stack = list(function_stack)

    def count(self) -> int:
        return len(self.found_in)


class BugBucket:
    def __init__(self,start_time):
        self._bugs: Dict[str, Bug] = {}
        self.start_time = start_time

    def add(self, signature: str, error_type: str, fuzzer_id: str, tte: int):
        if signature not in self._bugs:
            self._bugs[signature] = Bug(signature, error_type)
        self._bugs[signature].add_finder(fuzzer_id, tte)
        return self._bugs[signature]

    def signatures(self):
        return list(self._bugs.keys())

    def items(self):
        return self._bugs.items()

def _extract_fuzzer_id(crash_file_path: str, fuzz_dir: str) -> str:
    rel = os.path.relpath(os.path.dirname(crash_file_path), fuzz_dir)
    parts = rel.split(os.sep)
    for i, p in enumerate(parts):
        if p.startswith('c'):
            if i + 1 < len(parts) and parts[i + 1].startswith('fuzz'):
                return f"{p}/{parts[i+1]}"
            return p
    for p in parts:
        if p.startswith('fuzz'):
            return p
    return os.path.basename(crash_file_path)


def _count_expected_fuzzers(fuzz_dir: str) -> int:
    try:
        entries = os.listdir(fuzz_dir)
    except FileNotFoundError:
        return 0

    campaigns = [d for d in entries if os.path.isdir(os.path.join(fuzz_dir, d)) and d.startswith('c')]
    if campaigns:
        total = 0
        for c in campaigns:
            p = os.path.join(fuzz_dir, c)
            total += len([d for d in os.listdir(p) if os.path.isdir(os.path.join(p, d)) and d.startswith('fuzz')])
        return total

    fuzz_dirs = len([d for d in entries if os.path.isdir(os.path.join(fuzz_dir, d)) and d.startswith('fuzz')])
    if fuzz_dirs:
        return fuzz_dirs

    return len([f for f in entries if os.path.isfile(os.path.join(fuzz_dir, f))])



def _collect_crash_files(fuzz_dir: str, tool_name: str) -> List[str]:
    crash_files = []
    for root, _, files in os.walk(fuzz_dir):
        if 'crashes' in root or tool_name == "LibFuzzer":
            for file in files:
                if file == "README.txt" or file.endswith('.report'):
                    continue
                crash_file_path = os.path.join(root, file)
                crash_files.append(crash_file_path)
    return crash_files

def _analyze_crash(crash_file_path: str, fuzz_dir: str, tool_name: str, asan_binary_path: str, llvm_instr: bool) -> dict:
    try:
        if llvm_instr:
            print(f"[DEBUG] Executing: {asan_binary_path} {crash_file_path}")
            result = subprocess.run([asan_binary_path, crash_file_path], stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=3)
        else:
            with open(crash_file_path, "rb") as fh:
                result = subprocess.run([asan_binary_path], stdin=fh, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=3)

        stderr = result.stderr.decode(errors='replace')
        tte = os.path.getmtime(crash_file_path)
        if "AddressSanitizer" in stderr:
            parsed_asan = parse_asan(stderr)
            functions = get_source_functions(parsed_asan)
            error_type = get_error_type(parsed_asan)
            if functions and error_type:
                signature = get_stack_signature(functions, error_type)
                fuzzer_id = _extract_fuzzer_id(crash_file_path, fuzz_dir)
                return {
                    'signature': signature,
                    'error_type': error_type,
                    'fuzzer_id': fuzzer_id,
                    'functions': functions,
                    'tte':int(tte)
                }
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Error processing {crash_file_path}: {e}")
    return None

def _summarize_results(tool_buckets: Dict[str, BugBucket], tool_totals: Dict[str, int]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for tool_name, bucket in tool_buckets.items():
        total = tool_totals.get(tool_name, 0) or 0
        bugs_summary = []
        for signature, bug in bucket.items():
            cnt = bug.count()
            eff = cnt / total if total > 0 else 0.0
            bugs_summary.append({
                'error_type': bug.error_type,
                'signature': bug.signature,
                'stack': list(bug.stack),
                'count': cnt,
                'total_fuzzers': total,
                'effectiveness': eff,
                'found_in': sorted(list(bug.found_in.keys())),
                'mean_tte': mean(sorted(list(bug.found_in.values()))),
                'min_tte': min(list(bug.found_in.values()))
            })
        result[tool_name] = {
            'total_fuzzers': total,
            'bugs': bugs_summary
        }
    return result


def plot_summary(summary: Dict[str, Any], out_dir: str = '.') -> None:

    os.makedirs(out_dir, exist_ok=True)

    # Build a consistent color map across error types
    global_error_types = set()
    for data in summary.values():
        for b in data.get('bugs', []):
            global_error_types.add(b.get('error_type', 'unknown'))

    sorted_errors = sorted(global_error_types)
    cmap = plt.get_cmap('tab20')
    color_map = {err: cmap(i % cmap.N) for i, err in enumerate(sorted_errors)}

    # Per-tool pie charts
    for tool_name, data in summary.items():
        counts = defaultdict(int)
        for b in data.get('bugs', []):
            counts[b.get('error_type', 'unknown')] += 1

        if not counts:
            continue

        labels = list(counts.keys())
        sizes = [counts[k] for k in labels]
        colors = [color_map.get(l, (0.6, 0.6, 0.6)) for l in labels]

        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        plt.axis('equal')
        plt.title(f"{tool_name} - unique bugs by error type")
        outpath = os.path.join(out_dir, f"{tool_name.replace(' ', '_')}_pie.png")
        plt.tight_layout()
        plt.savefig(outpath)
        plt.close()
        print(f"[+] Saved pie chart: {outpath}")

    # Overall pie across all tools
    global_counts = defaultdict(int)
    for data in summary.values():
        for b in data.get('bugs', []):
            global_counts[b.get('error_type', 'unknown')] += 1

    if global_counts:
        labels = list(global_counts.keys())
        sizes = [global_counts[k] for k in labels]
        colors = [color_map.get(l, (0.6, 0.6, 0.6)) for l in labels]
        plt.figure(figsize=(7, 7))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        plt.axis('equal')
        plt.title("All tools - unique bugs by error type")
        outpath = os.path.join(out_dir, "all_tools_pie.png")
        plt.tight_layout()
        plt.savefig(outpath)
        plt.close()
        print(f"[+] Saved overall pie chart: {outpath}")

    # Histogram: number of unique bugs per tool
    tools = []
    counts = []
    for tool_name, data in summary.items():
        tools.append(tool_name)
        counts.append(len(data.get('bugs', [])))

    if tools:
        plt.figure(figsize=(max(6, len(tools)), 6))
        bars = plt.bar(tools, counts, color='tab:blue')
        plt.ylabel('Unique bug signatures')
        plt.title('Number of unique bugs per fuzzer')
        plt.xticks(rotation=45, ha='right')
        for bar, cnt in zip(bars, counts):
            plt.text(bar.get_x() + bar.get_width() / 2.0, bar.get_height(), str(cnt), ha='center', va='bottom')
        plt.tight_layout()
        outpath = os.path.join(out_dir, 'bugs_per_fuzzer_hist.png')
        plt.savefig(outpath)
        plt.close()
        print(f"[+] Saved histogram: {outpath}")

def _get_start_time_universal(fuzz_dir):
    return

def _determine_start_time(fuzz_dir, toolname) -> int:
    if "afl" in toolname.lower():
        return get_start_time_afl(fuzz_dir)
    elif "honggfuzz" in toolname.lower():
        return get_start_time_hfuzz(fuzz_dir)
    return _get_start_time_universal(fuzz_dir)
 

def get_unique_bugs(asan_binary_path: str, fuzzing_output_dirs: List[str], llvm_instr=False):
    """Scan provided fuzzer output directories and return structured bug data."""
    tool_buckets: Dict[str, BugBucket] = {}
    tool_totals: Dict[str, int] = {}

    for fuzz_dir in fuzzing_output_dirs:
        tool_name = format_fuzzer_name(fuzz_dir)
        start_time = int(_determine_start_time(fuzz_dir, tool_name))
        tool_buckets.setdefault(tool_name, BugBucket(start_time=start_time))
        tool_totals[tool_name] = tool_totals.get(tool_name, 0) + _count_expected_fuzzers(fuzz_dir)
        crash_files = _collect_crash_files(fuzz_dir, tool_name)
        for crash_file_path in crash_files:
            analyzed = _analyze_crash(crash_file_path, fuzz_dir, tool_name, asan_binary_path, llvm_instr)
            if analyzed:
                bucket = tool_buckets[tool_name]
                bug = bucket.add(analyzed['signature'], analyzed['error_type'], analyzed['fuzzer_id'], analyzed['tte']-start_time)
                bug.set_stack_if_missing(analyzed['functions'])

    return _summarize_results(tool_buckets, tool_totals)




def get_source_functions(parsed_asan: Dict) -> List:
    src_frames = parsed_asan["source_frames"]
    functions = []
    for frame in src_frames:
        if not frame['function'].startswith("__"):
            functions.append((frame['function'],frame['line']))
    return functions

def get_error_type(parsed_asan: Dict) -> str:
    return parsed_asan["error_type"]



def get_stack_signature(function_stack: List, error_type: str):
    func_str = f"{function_stack[0][0]}{function_stack[0][1]}{error_type}"
    for i in range(1,len(function_stack)):
        func_str += function_stack[i][0]
    hash_object = hashlib.sha1(func_str.encode("utf-8"))
    return hash_object.hexdigest()

def format_fuzzer_name(dir_name):
    name_map = {"symcc_aflpp": "SYMCC & AFL++", "aflpp": "AFL++", "symcc_afl": "SYMCC & AFL", "symcc": "SYMCC", "afl": "AFL", "hfuzz": "Honggfuzz", "libfuzzer": "LibFuzzer", "lf": "LibFuzzer"}
    base_name = os.path.basename(dir_name)
    for key, formatted_name in name_map.items():
        if key in base_name.lower():
            return formatted_name
    return base_name.replace('_out', '').replace('_', ' ').title()


import argparse


def main():
    parser = argparse.ArgumentParser(description="Find unique bugs from fuzzer crash outputs.")
    parser.add_argument("-b", "--binary", required=True, help="Path to the ASAN-instrumented binary.")
    parser.add_argument("-d", "--directories", required=True, nargs='+', help="List of fuzzer output directories.")
    parser.add_argument("--llvm-instr", action="store_true", help="Run binary with file as argument instead of stdin.")
    parser.add_argument("--json-out", help="Write the summary JSON to this path (optional).", default=None)
    parser.add_argument("--plot-out", help="Directory where plots (PNGs) will be written (optional).", default=None)

    args = parser.parse_args()

    summary = get_unique_bugs(args.binary, args.directories, args.llvm_instr)

    total_bugs = sum(len(tool['bugs']) for tool in summary.values())
    print(f"Found {total_bugs} unique bug signatures across {len(summary)} tools:\n")

    for tool, data in summary.items():
        total_fuzzers = data.get('total_fuzzers', 0)
        bugs = data.get('bugs', [])
        print(f"=== {tool} - {len(bugs)} unique signatures (total fuzzers: {total_fuzzers}) ===")
        for b in bugs:
            eff_pct = b['effectiveness'] * 100
            print(f"- {b['error_type']} | sig: {b['signature']} | found in {b['count']}/{b['total_fuzzers']} ({eff_pct:.1f}%)")
            print(f"  instances: {', '.join(b['found_in'][:10])}{'...' if len(b['found_in'])>10 else ''}")

    if args.json_out:
        try:
            out_dir = os.path.dirname(args.json_out)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(args.json_out, 'w') as jf:
                json.dump(summary, jf, indent=2)
            print(f"\n[+] JSON summary written to: {args.json_out}")
        except Exception as e:
            print(f"[!] Failed to write JSON summary to {args.json_out}: {e}")

    if args.plot_out:
        try:
            plot_summary(summary, args.plot_out)
        except Exception as e:
            print(f"[!] Failed to generate plots: {e}")


if __name__ == "__main__":
    main()
