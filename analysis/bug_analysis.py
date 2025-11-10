import re
import json
from typing import List, Dict, Any
import hashlib
import subprocess
import os


class Bug:
    def __init__(self, signature: str, error_type: str):
        self.signature = signature
        self.error_type = error_type
        self.found_in = set()
        self.stack = []

    def add_finder(self, fuzzer_id: str):
        self.found_in.add(fuzzer_id)

    def set_stack_if_missing(self, function_stack: List[str]):
        if not self.stack and function_stack:
            self.stack = list(function_stack)

    def count(self) -> int:
        return len(self.found_in)


class BugBucket:
    def __init__(self):
        self._bugs: Dict[str, Bug] = {}

    def add(self, signature: str, error_type: str, fuzzer_id: str):
        if signature not in self._bugs:
            self._bugs[signature] = Bug(signature, error_type)
        self._bugs[signature].add_finder(fuzzer_id)
        return self._bugs[signature]

    def signatures(self):
        return list(self._bugs.keys())

    def items(self):
        return self._bugs.items()

def _extract_fuzzer_id(crash_file_path: str, fuzz_dir: str) -> str:
    """Extract a compact fuzzer instance identifier from a crash file path.

    Examples:
      /.../out/c1/fuzz01/crashes/0001 -> 'c1/fuzz01'
      /.../out/fuzz01/crash -> 'fuzz01'
      fallback to filename if structure is unknown
    """
    rel = os.path.relpath(os.path.dirname(crash_file_path), fuzz_dir)
    parts = rel.split(os.sep)
    for i, p in enumerate(parts):
        if p.startswith('c'):
            # campaign directory, check next for fuzz instance
            if i + 1 < len(parts) and parts[i + 1].startswith('fuzz'):
                return f"{p}/{parts[i+1]}"
            return p
    for p in parts:
        if p.startswith('fuzz'):
            return p
    # fallback
    return os.path.basename(crash_file_path)


def _count_expected_fuzzers(fuzz_dir: str) -> int:
    """Estimate how many fuzzer instances ran for this tool by scanning c*/fuzz* dirs.

    Falls back to counting top-level 'fuzz*' dirs or files if campaign dirs are missing.
    """
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

    # no campaign dirs, count fuzz* dirs at top level
    fuzz_dirs = len([d for d in entries if os.path.isdir(os.path.join(fuzz_dir, d)) and d.startswith('fuzz')])
    if fuzz_dirs:
        return fuzz_dirs

    # as a last resort, count files existing in the directory
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
        if "AddressSanitizer" in stderr:
            parsed_asan = parse_asan(stderr)
            print(parsed_asan)
            functions = get_source_functions(parsed_asan)
            error_type = get_error_type(parsed_asan)
            print(f"[DEBUG] Function: {functions[0][0]} at line {functions[0][1]}")
            if functions and error_type:
                signature = get_stack_signature(functions, error_type)
                fuzzer_id = _extract_fuzzer_id(crash_file_path, fuzz_dir)
                return {
                    'signature': signature,
                    'error_type': error_type,
                    'fuzzer_id': fuzzer_id,
                    'functions': functions
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
                'found_in': sorted(list(bug.found_in))
            })
        result[tool_name] = {
            'total_fuzzers': total,
            'bugs': bugs_summary
        }
    return result

def get_unique_bugs(asan_binary_path: str, fuzzing_output_dirs: List[str], llvm_instr=False):
    """Scan provided fuzzer output directories and return structured bug data."""
    tool_buckets: Dict[str, BugBucket] = {}
    tool_totals: Dict[str, int] = {}

    for fuzz_dir in fuzzing_output_dirs:
        tool_name = format_fuzzer_name(fuzz_dir)
        tool_buckets.setdefault(tool_name, BugBucket())
        tool_totals[tool_name] = tool_totals.get(tool_name, 0) + _count_expected_fuzzers(fuzz_dir)
        crash_files = _collect_crash_files(fuzz_dir, tool_name)
        for crash_file_path in crash_files:
            analyzed = _analyze_crash(crash_file_path, fuzz_dir, tool_name, asan_binary_path, llvm_instr)
            if analyzed:
                bucket = tool_buckets[tool_name]
                bug = bucket.add(analyzed['signature'], analyzed['error_type'], analyzed['fuzzer_id'])
                bug.set_stack_if_missing(analyzed['functions'])

    return _summarize_results(tool_buckets, tool_totals)

def parse_asan(log_text: str):
    header_re = re.compile(r"ERROR: AddressSanitizer: (?P<error_type>[\w\-]+).*address (?P<address>0x[0-9a-fA-F]+)", re.MULTILINE)
    access_re = re.compile(r"(?P<access>READ|WRITE) of size (?P<size>\d+)")
    frame_line_re = re.compile(
        r"^\s*#(?P<num>\d+)\s+(?P<pc>0x[0-9a-fA-F]+)\s+in\s+(?P<func>[^\s]+)"
        r"(?:\s+(?P<file>[^:]+):(?P<line>\d+)(?::(?P<col>\d+))?)?",
        re.MULTILINE
    )
    summary_re = re.compile(
        r"^SUMMARY: AddressSanitizer: (?P<etype>[\w\-]+)\s+(?P<file>[^:]+):(?P<line>\d+)\s+in\s+(?P<func>[^\n]+)",
        re.MULTILINE
    )

    freed_by_re = re.compile(r"freed by thread (?P<thread>\w+) here:", re.MULTILINE)
    alloc_by_re = re.compile(r"allocated by thread (?P<thread>\w+) here:", re.MULTILINE)

    parsed = {
        "error_type": None,
        "address": None,
        "access": None,
        "source_frames": [],
        "freed_frames": [],
        "alloc_frames": [],
        "summary": None
    }

    if (h := header_re.search(log_text)):
        parsed["error_type"] = h.group("error_type")
        parsed["address"] = h.group("address")

    if (a := access_re.search(log_text)):
        parsed["access"] = {"type": a.group("access"), "size": int(a.group("size"))}

    freed_match = freed_by_re.search(log_text)
    alloc_match = alloc_by_re.search(log_text)
    freed_start = freed_match.start() if freed_match else None
    alloc_start = alloc_match.start() if alloc_match else None

    for m in frame_line_re.finditer(log_text):
        frame_obj = {
            "frame": int(m.group("num")),
            "pc": m.group("pc"),
            "function": m.group("func"),
            "file": m.group("file") or "",
            "line": int(m.group("line")) if m.group("line") else None,
            "col": int(m.group("col")) if m.group("col") else None,
        }

        pos = m.start()
        if alloc_start and pos >= alloc_start:
            parsed["alloc_frames"].append(frame_obj)
        elif freed_start and pos >= freed_start:
            parsed["freed_frames"].append(frame_obj)
        else:
            parsed["source_frames"].append(frame_obj)

    if (s := summary_re.search(log_text)):
        parsed["summary"] = {
            "error_type": s.group("etype"),
            "file": s.group("file"),
            "line": int(s.group("line")),
            "function": s.group("func").strip()
        }

    return parsed


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
    name_map = {"aflpp": "AFL++", "symcc_afl": "SYMCC+AFL", "symcc": "SYMCC", "afl": "AFL", "hfuzz": "Honggfuzz", "libfuzzer": "LibFuzzer", "lf": "LibFuzzer"}
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


if __name__ == "__main__":
    main()
