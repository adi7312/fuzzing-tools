import os

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
    
def format_fuzzer_name(dir_name):
    if(dir_name[-1] == '/'):
        tmp = list(dir_name)
        tmp[-1] = ''
        dir_name = ''.join(list(tmp))
    name_map = {"symcc_aflpp": "SYMCC & AFL++", "aflpp": "AFL++",  "symcc": "SYMCC", "afl": "AFL", "hfuzz": "Honggfuzz", "libfuzzer": "LibFuzzer", "lf": "LibFuzzer"}
    base_name = os.path.basename(dir_name)
    for key, formatted_name in name_map.items():
        if key in base_name.lower():
            return formatted_name
    
    return base_name.replace('_out', '').replace('_', ' ').title()