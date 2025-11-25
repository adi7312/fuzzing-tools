from typing import Optional
import glob
import os

fuzzer_log_name = "fuzzer_stats"

def _load_afl_stats(path: str):
    parsed = {}
    with open(path, "r") as f:
        stats = f.readlines()
        for line in stats:
            entry = line.split(":")
            parsed[entry[0].strip()] = entry[1].strip()
    return parsed

def find_first_stat(path: str) -> str:
    path = os.path.join(path, "**", fuzzer_log_name)
    result = glob.glob(path, recursive=True)
    if not result:
        return ""
    return result[0]

def get_start_time(path: str) -> Optional[int]:
    path = find_first_stat(path)
    stats = _load_afl_stats(path)
    return stats["start_time"]


