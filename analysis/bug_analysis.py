import re
import json
from typing import List, Dict, Any
import hashlib
import subprocess
import os
from collections import defaultdict

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

    # Header and access info
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
        functions.append(frame['function'])
    return functions

def get_stack_signature(function_stack: List):
    func_str = ''.join(function_stack).encode('utf-8')
    hash_object = hashlib.sha1(func_str)
    return hash_object.hexdigest()

def format_fuzzer_name(dir_name):
    """Format fuzzer directory names for display."""
    name_map = {"aflpp": "AFL++", "symcc_afl": "SYMCC+AFL", "symcc": "SYMCC", "afl": "AFL", "hfuzz": "Honggfuzz", "libfuzzer": "LibFuzzer", "lf": "LibFuzzer"}
    base_name = os.path.basename(dir_name)
    for key, formatted_name in name_map.items():
        if key in base_name.lower():
            return formatted_name
    return base_name.replace('_out', '').replace('_', ' ').title()

def get_unique_bugs(asan_binary_path: str, fuzzing_output_dirs: List[str], is_libfuzzer=False, llvm_instr=False):
    unique_bugs = defaultdict(set)

    for fuzz_dir in fuzzing_output_dirs:
        tool_name = format_fuzzer_name(fuzz_dir)
        for root, _, files in os.walk(fuzz_dir):
            if 'crashes' in root or is_libfuzzer:
                for file in files:
                    if file == "README.txt" or file.endswith('.report'):
                        continue

                    crash_file_path = os.path.join(root, file)
                    
                    try:
                        if llvm_instr:
                            result = subprocess.run([asan_binary_path, crash_file_path], stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=10)
                        else:
                            with open(crash_file_path, "rb") as f:
                                result = subprocess.run([asan_binary_path], stdin=f, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=10)
                        
                        stderr = result.stderr.decode(errors='replace')
                        
                        if "AddressSanitizer" in stderr:
                            print(stderr)
                            parsed_asan = parse_asan(stderr)
                            functions = get_source_functions(parsed_asan)
                            if functions:
                                signature = get_stack_signature(functions)
                                unique_bugs[tool_name].add(signature)
                    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                        print(f"Error processing {crash_file_path}: {e}")
                        continue
    
    return {tool: list(sigs) for tool, sigs in unique_bugs.items()}

# --- Example usage ---
if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Find unique bugs from fuzzer crash outputs.")
    parser.add_argument("-b", "--binary", required=True, help="Path to the ASAN-instrumented binary.")
    parser.add_argument("-d", "--directories", required=True, nargs='+', help="List of fuzzer output directories.")
    parser.add_argument("--is-libfuzzer", action="store_true", help="Indicates if the fuzzer is libfuzzer style.")
    parser.add_argument("--llvm-instr", action="store_true", help="Run binary with file as argument instead of stdin.")
    
    args = parser.parse_args()

    unique_bugs_by_tool = get_unique_bugs(args.binary, args.directories, args.is_libfuzzer, args.llvm_instr)
    
    total_bugs = sum(len(sigs) for sigs in unique_bugs_by_tool.values())
    print(f"Found {total_bugs} unique bugs across {len(unique_bugs_by_tool)} tools:")
    
    for tool, signatures in unique_bugs_by_tool.items():
        print(f"\n--- {tool} ({len(signatures)} unique bugs) ---")
        for sig in signatures:
            print(sig)
