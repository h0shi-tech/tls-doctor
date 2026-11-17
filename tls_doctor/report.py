"""Rendering and exit-code decisions for tls-doctor."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Sequence

from .checks import Finding

__all__ = [
    "EXIT_ERRORS",
    "EXIT_OK",
    "EXIT_USAGE",
    "EXIT_WARNINGS",
    "FAIL_ON_CHOICES",
    "HostReport",
    "decide_exit",
    "render",
    "render_json",
    "render_markdown",
    "render_table",
    "summary_line",
    "summarize",
]

EXIT_OK = 0
EXIT_WARNINGS = 1
EXIT_ERRORS = 2
EXIT_USAGE = 3

FAIL_ON_CHOICES = ("warning", "error", "never")


@dataclass(frozen=True, slots=True)
class HostReport:
    """All findings for one target host."""

    host: str
    findings: tuple[Finding, ...]


def summarize(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings by severity, with a total for convenience."""

    summary = {"ok": 0, "info": 0, "warning": 0, "error": 0}
    for finding in findings:
        summary[finding.severity] += 1
    summary["total"] = len(findings)
    return summary


def _plural(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def summary_line(summary: dict[str, int]) -> str:
    """Render the human summary line, for example ``2 ok, 3 warnings, 0 errors``."""

    parts = [
        f"{summary.get('ok', 0)} ok",
        f"{summary.get('warning', 0)} "
        f"{_plural(summary.get('warning', 0), 'warning', 'warnings')}",
        f"{summary.get('error', 0)} "
        f"{_plural(summary.get('error', 0), 'error', 'errors')}",
    ]
    info = summary.get("info", 0)
    if info:
        parts.append(f"{info} info")
    return ", ".join(parts)


def _host_payload(report: HostReport) -> dict[str, object]:
    return {
        "host": report.host,
        "findings": [finding.to_dict() for finding in report.findings],
        "summary": summarize(report.findings),
    }


def render_json(reports: Sequence[HostReport]) -> str:
    """Render one host object for a single host, or an array for many hosts."""

    if len(reports) == 1:
        payload: object = _host_payload(reports[0])
    else:
        payload = [_host_payload(report) for report in reports]
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _one_line(value: str) -> str:
    return " ".join(str(value).split())


def render_table(reports: Sequence[HostReport]) -> str:
    """Render an aligned plain-text table followed by a summary line."""

    headers = ("HOST", "CHECK", "SEVERITY", "FINDING", "DETAIL")
    rows: list[tuple[str, ...]] = []
    for report in reports:
        for finding in report.findings:
            rows.append(
                (
                    _one_line(report.host),
                    finding.id,
                    finding.severity.upper(),
                    _one_line(finding.title),
                    _one_line(finding.detail),
                )
            )

    widths = [len(header) for header in headers]
    for row in rows:
        widths = [
            max(current, len(cell)) for current, cell in zip(widths, row)
        ]

    def format_row(cells: Sequence[str]) -> str:
        return "  ".join(
            cell.ljust(width) for cell, width in zip(cells, widths)
        ).rstrip()

    lines = [format_row(headers)]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend(format_row(row) for row in rows)

    all_findings = [finding for report in reports for finding in report.findings]
    lines.append("")
    lines.append(summary_line(summarize(all_findings)))
    return "\n".join(lines) + "\n"


def _md_cell(value: str) -> str:
    text = _one_line(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    return text


def _md_row(values: Sequence[str]) -> str:
    return "| " + " | ".join(_md_cell(value) for value in values) + " |"


def render_markdown(reports: Sequence[HostReport]) -> str:
    """Render GitHub-flavoured markdown suitable for a pull-request comment."""

    lines: list[str] = []
    multiple = len(reports) > 1
    if multiple:
        lines.extend(["## TLS diagnosis", ""])
    else:
        host = reports[0].host if reports else "unknown host"
        lines.extend([f"## TLS diagnosis for `{host}`", ""])

    for report in reports:
        if multiple:
            lines.extend([f"### `{report.host}`", ""])
        lines.append(
            "| Check | Severity | Finding | Detail | Remediation |"
        )
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in report.findings:
            remediation = finding.remediation or "—"
            lines.append(
                _md_row(
                    (
                        f"`{finding.id}`",
                        finding.severity,
                        finding.title,
                        finding.detail,
                        remediation,
                    )
                )
            )
        lines.append("")
        lines.append(f"**Summary:** {summary_line(summarize(report.findings))}")
        lines.append("")

    if multiple:
        all_findings = [
            finding for report in reports for finding in report.findings
        ]
        lines.append(f"**Total:** {summary_line(summarize(all_findings))}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render(reports: Sequence[HostReport], output_format: str) -> str:
    """Render reports in ``table``, ``json`` or ``md`` format."""

    if output_format == "table":
        return render_table(reports)
    if output_format == "json":
        return render_json(reports)
    if output_format == "md":
        return render_markdown(reports)
    raise ValueError(f"unsupported output format: {output_format!r}")


def decide_exit(
    reports: Sequence[HostReport], fail_on: str = "error"
) -> int:
    """Map findings to the documented exit code contract.

    ``never`` always returns 0 (useful for reporting-only runs);
    ``error`` fails only when an error finding exists; ``warning`` fails on
    warnings as well.  Errors always take precedence over warnings.
    """

    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(f"invalid --fail-on value: {fail_on!r}")

    findings = [finding for report in reports for finding in report.findings]
    has_error = any(finding.severity == "error" for finding in findings)
    has_warning = any(finding.severity == "warning" for finding in findings)

    if fail_on == "never":
        return EXIT_OK
    if has_error:
        return EXIT_ERRORS
    if has_warning and fail_on == "warning":
        return EXIT_WARNINGS
    return EXIT_OK
