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