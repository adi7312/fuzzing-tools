import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap, BoundaryNorm
import numpy as np
import pandas as pd
import seaborn as sns
import os
import re
from itertools import combinations
from collections import OrderedDict
from scipy.stats import mannwhitneyu


_SUFFIX_PATTERN = re.compile(r"(_fuzz\d+)$", re.IGNORECASE)


def _normalize_fuzzer_label(raw_name: str) -> str:
    clean = _SUFFIX_PATTERN.sub("", raw_name or "").replace("_", " ").strip()
    return clean or raw_name or "Unknown"


def _aggregate_coverage(coverage_data):
    aggregated = OrderedDict()
    for raw_name, samples in (coverage_data or {}).items():
        label = _normalize_fuzzer_label(raw_name)
        aggregated.setdefault(label, []).extend(samples)
    return aggregated

def get_branch_cov_df(coverage_data):
    
    if not coverage_data:
        return pd.DataFrame(columns=["Fuzzer", "Sample", "Coverage"])
    records = []
    for fuzzer, samples in coverage_data.items():
        for idx, cov in enumerate(samples, start=1):
            records.append({"Fuzzer": fuzzer, "Sample": idx, "Coverage": cov})
    return pd.DataFrame(records)

def pairwise_unique_coverage(coverage_data, save_path=None, title="Pairwise Unique Branch Coverage Advantage"):

    if not coverage_data:
        raise ValueError("coverage_data is empty.")
    aggregated = _aggregate_coverage(coverage_data)
    if not aggregated:
        raise ValueError("coverage_data is empty.")
    fuzzers = sorted(aggregated.keys())
    matrix = pd.DataFrame(
        np.zeros((len(fuzzers), len(fuzzers)), dtype=float),
        index=fuzzers,
        columns=fuzzers,
    )
    for ref in fuzzers:
        ref_vals = np.array(aggregated[ref], dtype=float)
        ref_mean = ref_vals.mean() if ref_vals.size else np.nan
        for cmp_ in fuzzers:
            if ref == cmp_:
                continue
            cmp_vals = np.array(aggregated[cmp_], dtype=float)
            cmp_mean = cmp_vals.mean() if cmp_vals.size else np.nan
            matrix.at[ref, cmp_] = np.nan if np.isnan(ref_mean) or np.isnan(cmp_mean) else ref_mean - cmp_mean
    fig, ax = plt.subplots(
        figsize=(max(len(fuzzers) * 1.6, 6), max(len(fuzzers) * 1.2, 4))
    )
    sns.heatmap(
        matrix,
        annot=True,
        fmt=".0f",
        cmap="RdYlGn",
        linewidths=0.5,
        linecolor="white",
        cbar_kws={"label": "Avg. Unique Branches"},
        annot_kws={"fontsize": max(8, 16 - len(fuzzers))},
        ax=ax,
    )
    ax.set_title(title)
    ax.set_ylabel("Reference Fuzzer")
    ax.set_xlabel("Comparison Fuzzer")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    if save_path:
        directory = os.path.dirname(save_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        fig.savefig(save_path, dpi=300)
    plt.close(fig)
    return matrix

def mann_whitney(coverage_data, alternative="two-sided"):

    aggregated = _aggregate_coverage(coverage_data)
    if not aggregated:
        return pd.DataFrame(columns=["Fuzzer A", "Fuzzer B", "U", "p", "Alternative"])
    rows = []
    for fuzzer_a, fuzzer_b in combinations(aggregated.keys(), 2):
        sample_a = aggregated.get(fuzzer_a, [])
        sample_b = aggregated.get(fuzzer_b, [])
        if not sample_a or not sample_b:
            stat = pval = np.nan
        else:
            stat, pval = mannwhitneyu(sample_a, sample_b, alternative=alternative)
        rows.append(
            {
                "Fuzzer A": fuzzer_a,
                "Fuzzer B": fuzzer_b,
                "U": stat,
                "p": pval,
                "Alternative": alternative,
            }
        )
    return pd.DataFrame(rows)


def mann_whitney_heatmap(coverage_data, save_path=None, title="Mann-Whitney U Test Significance", alternative="two-sided"):

    colors = [
        "#f7d6d5",  # NS (p ≥ 0.05) light pink
        "#a8d5a2",  # p < 0.05
        "#2c8c45",  # p < 0.01
        "#004d26",  # p < 0.001 (dark green)
    ]

    cmap = ListedColormap(list(reversed(colors)))

    bounds = [0.0, 0.001, 0.01, 0.05, 1.0]
    norm = BoundaryNorm(bounds, cmap.N)

    aggregated = _aggregate_coverage(coverage_data)
    if not aggregated:
        raise ValueError("coverage_data is empty.")

    fuzzers = sorted(aggregated.keys())
    size = len(fuzzers)
    matrix = pd.DataFrame(
        np.full((size, size), np.nan, dtype=float),
        index=fuzzers,
        columns=fuzzers,
    )

    for fuzzer in fuzzers:
        matrix.at[fuzzer, fuzzer] = 0.0

    for fuzzer_a, fuzzer_b in combinations(fuzzers, 2):
        sample_a = aggregated.get(fuzzer_a, [])
        sample_b = aggregated.get(fuzzer_b, [])
        if not sample_a or not sample_b:
            p_val = np.nan
        else:
            _, p_val = mannwhitneyu(sample_a, sample_b, alternative=alternative)
        matrix.at[fuzzer_a, fuzzer_b] = p_val
        matrix.at[fuzzer_b, fuzzer_a] = p_val

    fig, ax = plt.subplots(
        figsize=(max(len(fuzzers) * 1.6, 6), max(len(fuzzers) * 1.2, 4))
    )
    mask = matrix.isna()
    for idx in range(len(fuzzers)):
        mask.iat[idx, idx] = True
    heatmap = sns.heatmap(
        matrix,
        mask=mask,
        annot=False,
        cmap=cmap,
        norm=norm,
        vmin=0.0,
        vmax=1.0,
        linewidths=0.5,
        linecolor="white",
        cbar_kws={"label": "p-value"},
        ax=ax,
    )
    cbar = heatmap.collections[0].colorbar
    tick_positions = [
        (bounds[i] + bounds[i + 1]) / 2 for i in range(len(bounds) - 1)
    ]
    tick_labels = ["p < 0.001", "p < 0.01", "p < 0.05", "p ≥ 0.05"]
    cbar.set_ticks(tick_positions)
    cbar.set_ticklabels(tick_labels)
    ax.set_title(title)
    ax.set_ylabel("Fuzzer A")
    ax.set_xlabel("Fuzzer B")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    if save_path:
        directory = os.path.dirname(save_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        fig.savefig(save_path, dpi=300)
    plt.close(fig)
    return matrix

