import re

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