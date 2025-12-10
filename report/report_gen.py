"""Report generation utilities for fuzzing benchmark results."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import StatisticsError, mean, median, stdev
from string import Template
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


DEFAULT_TEMPLATE = Path(__file__).with_name("template.html")

__all__ = ["generate_report"]


def _load_yaml(path: str) -> Dict[str, Any]:
	if not path:
		return {}
	try:
		with open(path, "r", encoding="utf-8") as fh:
			data = yaml.safe_load(fh) or {}
	except FileNotFoundError:
		return {}
	return data


def _load_json(path: Optional[str]) -> Dict[str, Any]:
	if not path:
		return {}
	try:
		with open(path, "r", encoding="utf-8") as fh:
			return json.load(fh)
	except FileNotFoundError:
		return {}


def _format_fuzzer_name(raw: str) -> str:
	mapping: List[Tuple[str, str]] = [
		("symcc_aflpp", "SYMCC & AFL++"),
		("afl++", "AFL++"),
		("aflpp", "AFL++"),
		("symcc_afl", "SYMCC & AFL"),
		("symcc", "SYMCC"),
		("afl", "AFL"),
		("hfuzz", "Honggfuzz"),
		("honggfuzz", "Honggfuzz"),
		("libfuzzer", "LibFuzzer"),
		("lf", "LibFuzzer"),
		("klee", "KLEE"),
	]
	normalized = raw.lower().replace(" ", "")
	if normalized.endswith("_out"):
		normalized = normalized[:-4]
	normalized = normalized.strip("_")
	for key, label in mapping:
		if normalized == key:
			return label
	for key, label in mapping:
		if key in normalized:
			return label
	clean = raw.replace("_out", "").replace("_", " ").strip()
	return clean or raw


def _render_table(headers: Sequence[str], rows: Sequence[Sequence[Any]], empty_text: str) -> str:
	if not rows:
		return f'<p class="placeholder">{empty_text}</p>'

	head_html = "".join(f"<th>{h}</th>" for h in headers)
	body_rows = []
	for row in rows:
		cells = "".join(f"<td>{cell}</td>" for cell in row)
		body_rows.append(f"<tr>{cells}</tr>")
	body_html = "".join(body_rows)
	return f"<table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>"


def _render_list(items: Sequence[str], empty_text: str) -> str:
	if not items:
		return f'<p class="placeholder">{empty_text}</p>'
	entries = "".join(f"<li>{item}</li>" for item in items)
	return f"<ul>{entries}</ul>"


def _render_figure_grid(figures: Sequence[Tuple[str, str]]) -> str:
	if not figures:
		return '<p class="placeholder">No figures available.</p>'
	blocks = ["<div class=\"figure-grid\">"]
	for src, caption in figures:
		alt_text = caption or "Figure"
		fig = ["<figure>", f'<img src="{src}" alt="{alt_text}" />']
		if caption:
			fig.append(f"<figcaption>{caption}</figcaption>")
		fig.append("</figure>")
		blocks.append("".join(fig))
	blocks.append("</div>")
	return "".join(blocks)


def _format_number(value: Optional[float]) -> str:
	if value is None:
		return "-"
	return f"{value:.2f}"


def _format_duration(seconds: Optional[float]) -> Optional[str]:
	"""Convert seconds into HH:MM:SS for readability."""
	if seconds is None:
		return None
	try:
		total_seconds = int(round(float(seconds)))
	except (TypeError, ValueError):
		return None
	total_seconds = max(total_seconds, 0)
	hours, remainder = divmod(total_seconds, 3600)
	minutes, secs = divmod(remainder, 60)
	return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _collect_coverage_stats(
	coverage_summary: Dict[str, Any],
	key_filter: Optional[Callable[[str], bool]] = None,
) -> List[Dict[str, Any]]:
	grouped: Dict[str, List[float]] = defaultdict(list)
	for key, values in coverage_summary.items():
		if key_filter and not key_filter(key):
			continue
		if not isinstance(values, Iterable):
			continue
		fuzzer_name = key.rsplit('_', 1)[0]
		display = _format_fuzzer_name(fuzzer_name)
		for value in values:
			try:
				grouped[display].append(float(value))
			except (TypeError, ValueError):
				continue

	stats: List[Dict[str, Any]] = []
	for fuzzer, values in grouped.items():
		if not values:
			continue
		try:
			std_val = stdev(values) if len(values) > 1 else 0.0
		except StatisticsError:
			std_val = 0.0
		stats.append(
			{
				"fuzzer": fuzzer,
				"samples": len(values),
				"mean": mean(values),
				"median": median(values),
				"std": std_val,
				"min": min(values),
				"max": max(values),
			}
		)

	stats.sort(key=lambda item: item["mean"], reverse=True)
	return stats


def _render_coverage_table(
	coverage_summary: Dict[str, Any],
	key_filter: Optional[Callable[[str], bool]] = None,
) -> str:
	stats = _collect_coverage_stats(coverage_summary, key_filter)
	headers = ["Fuzzer", "Samples", "Mean", "Std", "Min", "Median", "Max"]
	rows = [
		[
			entry["fuzzer"],
			entry["samples"],
			_format_number(entry["mean"]),
			_format_number(entry["std"]),
			_format_number(entry["min"]),
			_format_number(entry["median"]),
			_format_number(entry["max"]),
		]
		for entry in stats
	]
	return _render_table(headers, rows, "No coverage statistics available.")


def _infer_build_type(key: str) -> str:
	lower = key.lower()
	if "asan" in lower:
		return "ASAN"
	suffix = key.rsplit('_', 1)[-1].lower()
	if suffix.startswith("fuzz"):
		digits = "".join(ch for ch in suffix if ch.isdigit())
		if digits:
			try:
				return "ASAN" if int(digits) % 2 == 0 else "Normal"
			except ValueError:
				pass
	return "Normal"


def _compose_stats_notes(
	stats_note: Optional[str],
	pairwise_note: Optional[str],
) -> str:
	stats_html = stats_note or '<p class="placeholder">TBD: Statistical tests</p>'
	pair_html = pairwise_note or '<p class="placeholder">TBD: Pairwise coverage</p>'
	return (
		'<div class="stat-grid">'
		f'<div><h4>Statistical tests</h4>{stats_html}</div>'
		f'<div><h4>Pairwise coverage</h4>{pair_html}</div>'
		'</div>'
	)


def _collect_bug_details(bug_summary: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
	details: Dict[str, Dict[str, Any]] = {}
	for tool_name, tool_data in bug_summary.items():
		bugs = tool_data.get("bugs") or []
		for bug in bugs:
			signature = bug.get("signature") or "unknown"
			record = details.setdefault(
				signature,
				{
					"error_type": bug.get("error_type", "unknown"),
					"stack": bug.get("stack", []),
					"per_tool": {},
				},
			)
			record["per_tool"][tool_name] = {
				"count": bug.get("count", 0),
				"effectiveness": bug.get("effectiveness"),
				"min_tte": bug.get("min_tte"),
				"mean_tte": bug.get("mean_tte"),
				"max_tte": bug.get("max_tte"),
			}
	return details


def _render_bug_matrix(bug_summary: Dict[str, Any], ordered_tools: Sequence[str]) -> str:
	bugs = _collect_bug_details(bug_summary)
	if not bugs or not ordered_tools:
		return '<p class="placeholder">No bugs detected.</p>'

	headers = ["Bug (signature / type)", *ordered_tools]
	rows: List[List[str]] = []
	for signature, data in sorted(bugs.items()):
		label = f"{signature[:12]}:{data['error_type']}"
		row = [label]
		for tool in ordered_tools:
			row.append("X" if tool in data["per_tool"] else "")
		rows.append(row)
	return _render_table(headers, rows, "No bug data available.")


def _render_bug_details(bug_summary: Dict[str, Any], ordered_tools: Sequence[str]) -> str:
	bugs = _collect_bug_details(bug_summary)
	if not bugs:
		return '<p class="placeholder">No bug details available.</p>'

	sections: List[str] = []
	for signature, data in sorted(bugs.items()):
		error_type = data.get("error_type", "unknown")
		stack = data.get("stack") or []
		top_frame = stack[0] if stack else ("unknown", "?")
		function = top_frame[0] if isinstance(top_frame, (list, tuple)) and top_frame else str(top_frame)
		line = top_frame[1] if isinstance(top_frame, (list, tuple)) and len(top_frame) > 1 else "?"
		summary = f"Summary: {error_type} in {function} at line {line}"

		stack_lines = []
		for frame in stack:
			if isinstance(frame, (list, tuple)):
				frame_fn = frame[0]
				frame_line = frame[1] if len(frame) > 1 else "?"
				stack_lines.append(f"- {frame_fn} : {frame_line}")
			else:
				stack_lines.append(f"- {frame}")
		stack_html = "<br />".join(stack_lines) if stack_lines else "No stack trace available."

		metrics_headers = ["Metric", *ordered_tools]
		metric_rows: List[List[str]] = []

		def add_metric_row(label: str, extractor) -> None:
			values = []
			any_value = False
			for tool in ordered_tools:
				per_tool = data["per_tool"].get(tool)
				if per_tool is None:
					values.append("-")
					continue
				metric_value = extractor(per_tool)
				if metric_value is None:
					values.append("-")
				else:
					any_value = True
					values.append(metric_value)
			if any_value:
				metric_rows.append([label, *values])

		add_metric_row("Effectiveness", lambda m: f"{m.get('effectiveness', 0)*100:.1f}%" if m.get("effectiveness") is not None else None)
		add_metric_row("Finders", lambda m: str(m.get("count")) if m.get("count") is not None else None)
		add_metric_row("Min TTE", lambda m: _format_duration(m.get("min_tte")))
		add_metric_row("Mean TTE", lambda m: _format_duration(m.get("mean_tte")))
		add_metric_row("Max TTE", lambda m: str(m.get("max_tte")) if m.get("max_tte") is not None else None)

		metrics_table = _render_table(metrics_headers, metric_rows, "No per-tool data available.")

		section = (
			'<div class="bug-detail">'
			f"<h4>{signature}</h4>"
			f"<p>{summary}</p>"
			f"<div class=\"stack-trace\">{stack_html}</div>"
			f"{metrics_table}"
			"</div>"
		)
		sections.append(section)

	return "".join(sections)


def _rel_path(target: str, reference: str) -> str:
	try:
		return os.path.relpath(target, start=os.path.dirname(reference))
	except ValueError:
		return target



def _render_single_figure(base_dir: str, filename: str, caption: str, report_path: str) -> str:
	label = caption or "Figure"
	if not filename:
		return f'<p class="placeholder">{label} not available.</p>'
	path = os.path.join(base_dir, filename)
	if not os.path.exists(path):
		return f'<p class="placeholder">{label} not available.</p>'
	rel = _rel_path(path, report_path)
	parts = ['<figure class="figure-block">', f'<img src="{rel}" alt="{label}" />']
	if caption:
		parts.append(f"<figcaption>{label}</figcaption>")
	parts.append("</figure>")
	return "".join(parts)


def _discover_bug_figures(analysis_dir: str, report_path: str) -> List[Tuple[str, str]]:
	figures: List[Tuple[str, str]] = []
	png_files = sorted(Path(analysis_dir).glob("*.png"))
	for png in png_files:
		name = png.name
		if name.startswith("coverage_") or name.startswith("mean_coverage_") or name.startswith("mann_whitney"):
			continue
		caption = name.replace("_", " ").rsplit(".", 1)[0].title()
		figures.append((_rel_path(str(png), report_path), caption))
	return figures


def _build_benchmark_table(config: Dict[str, Any]) -> str:
	target_name = config.get("target_name", "unknown")
	duration = config.get("timeout", "unknown")
	trials = config.get("campaigns", "unknown")

	dict_present = "Yes" if config.get("dict") else "No"

	job_entries = []
	fuzzers_cfg = config.get("fuzzers") or {}
	for name, details in fuzzers_cfg.items():
		jobs = details.get("jobs")
		if jobs is None:
			binaries = details.get("binaries") or []
			print(binaries)
			jobs = len(binaries) if binaries else "?"
			print(f"[DEBUG] Jobs={jobs}")
		job_entries.append(f"{_format_fuzzer_name(name)}={jobs}")
	jobs_value = ", ".join(job_entries) if job_entries else "N/A"

	headers = ["Field", "Value"]
	rows = [
		("Target name", target_name),
		("Duration", duration),
		("Trials", trials),
		("Dict", dict_present),
		("Jobs per trial", jobs_value),
	]
	return _render_table(headers, rows, "Benchmark information unavailable.")


def _list_fuzzers(config: Dict[str, Any], bug_summary: Dict[str, Any]) -> List[str]:
	names = []
	for name in (config.get("fuzzers") or {}).keys():
		names.append(_format_fuzzer_name(name))
	for tool in bug_summary.keys():
		formatted = _format_fuzzer_name(tool)
		if formatted not in names:
			names.append(formatted)
	return names


def _ordered_tools(config: Dict[str, Any], bug_summary: Dict[str, Any]) -> List[str]:
	ordered = []
	for name in (config.get("fuzzers") or {}).keys():
		formatted = _format_fuzzer_name(name)
		if formatted not in ordered:
			ordered.append(formatted)
	for tool in bug_summary.keys():
		formatted = _format_fuzzer_name(tool)
		if formatted not in ordered:
			ordered.append(formatted)
	return ordered


def generate_report(
	config_path: str,
	analysis_dir: Optional[str] = None,
	coverage_summary: Optional[Dict[str, Any]] = None,
	bug_summary: Optional[Dict[str, Any]] = None,
	coverage_json_path: Optional[str] = None,
	bug_json_path: Optional[str] = None,
	template_path: Optional[str] = None,
	output_path: Optional[str] = None,
	coverage_stats_notes: Optional[str] = None,
	coverage_pairwise_notes: Optional[str] = None,
) -> str:

	config = _load_yaml(config_path)
	target_name = config.get("target_name", "unknown target")

	base_dir = os.path.dirname(os.path.abspath(config_path))
	analysis_dir = os.path.abspath(analysis_dir or os.path.join(base_dir, "analysis"))
	template_path = template_path or str(DEFAULT_TEMPLATE)

	if coverage_summary is None:
		default_cov = coverage_json_path or os.path.join(analysis_dir, "coverage_summary.json")
		coverage_summary = _load_json(default_cov)
	if not isinstance(coverage_summary, dict):
		coverage_summary = {}

	if bug_summary is None:
		default_bug = bug_json_path or os.path.join(analysis_dir, "bug_summary.json")
		bug_summary = _load_json(default_bug)
	if not isinstance(bug_summary, dict):
		bug_summary = {}

	if not output_path:
		report_dir = analysis_dir or base_dir
		os.makedirs(report_dir, exist_ok=True)
		filename = f"{target_name.replace(' ', '_')}_report.html"
		output_path = os.path.join(report_dir, filename)
	else:
		os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

	with open(template_path, "r", encoding="utf-8") as fh:
		template = Template(fh.read())

	benchmark_table = _build_benchmark_table(config)
	fuzzer_names = _list_fuzzers(config, bug_summary)
	fuzzer_list_html = _render_list(fuzzer_names, "No fuzzers configured.")

	coverage_normal_table = _render_coverage_table(
		coverage_summary,
		lambda key: _infer_build_type(key) == "Normal",
	)
	coverage_asan_table = _render_coverage_table(
		coverage_summary,
		lambda key: _infer_build_type(key) == "ASAN",
	)

	coverage_normal_growth = _render_single_figure(
		analysis_dir,
		"coverage_growth_normal.png",
		"Coverage growth (Normal)",
		output_path,
	)
	coverage_normal_violin = _render_single_figure(
		analysis_dir,
		"coverage_violin_normal.png",
		"Coverage distribution (Normal)",
		output_path,
	)
	coverage_normal_mean = _render_single_figure(
		analysis_dir,
		"mean_coverage_histogram_normal.png",
		"Mean coverage histogram (Normal)",
		output_path,
	)
	coverage_normal_pairwise = _render_single_figure(
		analysis_dir,
		"coverage_pairwise_heatmap_normal.png",
		"Pairwise coverage heatmap (Normal)",
		output_path,
	)
	coverage_normal_stats_heatmap = _render_single_figure(
		analysis_dir,
		"mann_whitney_heatmap_normal.png",
		"Mann-Whitney U heatmap (Normal)",
		output_path,
	)
	coverage_asan_growth = _render_single_figure(
		analysis_dir,
		"coverage_growth_asan.png",
		"Coverage growth (ASAN)",
		output_path,
	)
	coverage_asan_mean = _render_single_figure(
		analysis_dir,
		"mean_coverage_histogram_asan.png",
		"Mean coverage histogram (ASAN)",
		output_path,
	)
	coverage_asan_violin = _render_single_figure(
		analysis_dir,
		"coverage_violin_asan.png",
		"Coverage distribution (ASAN)",
		output_path,
	)
	coverage_asan_pairwise = _render_single_figure(
		analysis_dir,
		"coverage_pairwise_heatmap_asan.png",
		"Pairwise coverage heatmap (ASAN)",
		output_path,
	)
	coverage_asan_stats_heatmap = _render_single_figure(
		analysis_dir,
		"mann_whitney_heatmap_asan.png",
		"Mann-Whitney U heatmap (ASAN)",
		output_path,
	)

	coverage_stats_note_html = _compose_stats_notes(
		coverage_stats_notes,
		coverage_pairwise_notes
	)

	ordered_tools = _ordered_tools(config, bug_summary)
	bug_matrix_html = _render_bug_matrix(bug_summary, ordered_tools)
	bug_figures = _discover_bug_figures(analysis_dir, output_path)
	bug_figures_html = _render_figure_grid(bug_figures)
	bug_details_html = _render_bug_details(bug_summary, ordered_tools)

	context = {
		"target_name": target_name,
		"generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
		"benchmark_table": benchmark_table,
		"fuzzer_list": fuzzer_list_html,
		"coverage_normal_table": coverage_normal_table,
		"coverage_asan_table": coverage_asan_table,
		"coverage_normal_growth": coverage_normal_growth,
		"coverage_normal_mean": coverage_normal_mean,
		"coverage_normal_violin": coverage_normal_violin,
		"coverage_normal_pairwise": coverage_normal_pairwise,
		"coverage_normal_stats_heatmap": coverage_normal_stats_heatmap,
		"coverage_asan_growth": coverage_asan_growth,
		"coverage_asan_mean": coverage_asan_mean,
		"coverage_asan_violin": coverage_asan_violin,
		"coverage_asan_pairwise": coverage_asan_pairwise,
		"coverage_asan_stats_heatmap": coverage_asan_stats_heatmap,
		"coverage_stats_notes": coverage_stats_note_html,
		"bug_matrix_table": bug_matrix_html,
		"bug_figures": bug_figures_html,
		"bug_details": bug_details_html,
	}

	rendered = template.safe_substitute(context)
	with open(output_path, "w", encoding="utf-8") as fh:
		fh.write(rendered)

	return output_path


