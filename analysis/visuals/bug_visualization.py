import os
import matplotlib.pyplot as plt

from typing import  Dict, Any
from collections import defaultdict

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