from typing import Optional
import glob
import os

fuzzer_log_format = ""

def find_first_stat(path: str) -> str:
    path = os.path.join(path, "**", fuzzer_log_format)
    result = glob.glob(path, recursive=True)
    if not result:
        return ""
    return result[0]

def get_start_time(path: str) -> Optional[int]:
    try:
        with open(path, "r") as f:
            raw = [l.rstrip('\n') for l in f]

        for idx, line in enumerate(raw):
            if 'unix_time' in line:
                for j in range(idx + 1, len(raw)):
                    data_line = raw[j].strip()
                    if not data_line or data_line.startswith('#'):
                        continue
                    parts = [p.strip() for p in data_line.split(',')]
                    if parts:
                        try:
                            return int(parts[0])
                        except (ValueError, TypeError):
                            return None

        for line in raw:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            parts = [p.strip() for p in s.split(',')]
            if parts:
                try:
                    return int(parts[0])
                except (ValueError, TypeError):
                    break
    except Exception:
        pass

    return None

