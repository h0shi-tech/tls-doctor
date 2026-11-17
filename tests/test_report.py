"""Offline tests for rendering and exit-code decisions."""

from __future__ import annotations

import json
import unittest

from tls_doctor.checks import Finding
from tls_doctor.report import (
    EXIT_ERRORS,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_WARNINGS,
    HostReport,
    decide_exit,
    render,
    render_json,
    render_markdown,
    render_table,
    summary_line,
    summarize,
)


def finding(
    finding_id: str,
    severity: str,
    title: str = "Title",
    detail: str = "Detail",
    remediation: str = "",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=title,
        detail=detail,
        remediation=remediation,
    )


class SummaryTests(unittest.TestCase):
    def test_summary_counts_and_line(self) -> None:
        findings = [
            finding("a", "ok"),
            finding("b", "ok"),
            finding("c", "warning"),
            finding("d", "warning"),
            finding("e", "warning"),
            finding("f", "info"),
        ]
        summary = summarize(findings)
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["warning"], 3)
        self.assertEqual(summary["error"], 0)
        self.assertEqual(summary["info"], 1)
        self.assertEqual(summary["total"], 6)
        self.assertEqual(
            summary_line(summary), "2 ok, 3 warnings, 0 errors, 1 info"
        )

    def test_summary_line_without_info(self) -> None:
        self.assertEqual(
            summary_line({"ok": 2, "info": 0, "warning": 3, "error": 0}),
            "2 ok, 3 warnings, 0 errors",
        )

    def test_singular_forms(self) -> None:
        self.assertEqual(
            summary_line({"ok": 1, "info": 0, "warning": 1, "error": 1}),
            "1 ok, 1 warning, 1 error",
        )


class JsonRenderingTests(unittest.TestCase):
    def test_single_host_schema(self) -> None:
        report = HostReport(
            "example.com:8443",
            (
                finding(
                    "cert.expiry",
                    "ok",
                    "Certificate is valid",
                    "90 days left",
                ),
                finding(
                    "http.hsts",
                    "warning",
                    "HSTS header is missing",
                    "No STS header",
                    "Add one",
                ),
            ),
        )
        payload = json.loads(render_json([report]))
        self.assertEqual(list(payload), ["host", "findings", "summary"])
        self.assertEqual(payload["host"], "example.com:8443")
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual(
            list(payload["findings"][0]),
            ["id", "severity", "title", "detail", "remediation"],
        )
        self.assertEqual(payload["findings"][1]["remediation"], "Add one")
        self.assertEqual(
            payload["summary"],
            {"ok": 1, "info": 0, "warning": 1, "error": 0, "total": 2},
        )

    def test_multiple_hosts_are_an_ordered_array(self) -> None:
        reports = [
            HostReport("b.example", (finding("cert.expiry", "ok"),)),
            HostReport("a.example", (finding("cert.expiry", "error"),)),
        ]
        payload = json.loads(render_json(reports))
        self.assertIsInstance(payload, list)
        self.assertEqual([item["host"] for item in payload], ["b.example", "a.example"])
        self.assertEqual(payload[1]["summary"]["error"], 1)

    def test_empty_reports_is_empty_array(self) -> None:
        self.assertEqual(json.loads(render_json([])), [])


class TableRenderingTests(unittest.TestCase):
    def test_header_rows_alignment_and_summary(self) -> None:
        report = HostReport(
            "example.com",
            (
                finding(
                    "cert.expiry",
                    "ok",
                    title="Certificate is valid",
                    detail="90 days left",
                ),
                finding(
                    "tls.version",
                    "error",
                    title="Obsolete TLS version",
                    detail="TLSv1.1 negotiated",
                ),
            ),
        )
        output = render_table([report])
        lines = output.rstrip("\n").splitlines()
        self.assertEqual(
            lines[0].split(),
            ["HOST", "CHECK", "SEVERITY", "FINDING", "DETAIL"],
        )
        self.assertIn("1 ok", lines[-1])
        self.assertIn("0 warnings", lines[-1])
        self.assertIn("1 error", lines[-1])
        self.assertTrue(lines[1].startswith("---"))

        severity_column = lines[0].index("SEVERITY")
        host_column = lines[0].index("HOST")
        for line in lines[2:-2]:
            self.assertEqual(
                line[severity_column : severity_column + len("SEVERITY")].strip()
                in {"OK", "WARNING", "ERROR", "INFO"},
                True,
            )
            self.assertTrue(line[host_column:].startswith("example.com"))

    def test_multiple_hosts_use_one_summary_line(self) -> None:
        output = render_table(
            [
                HostReport("one.example", (finding("cert.expiry", "ok"),)),
                HostReport("two.example", (finding("cert.expiry", "warning"),)),
            ]
        )
        self.assertIn("one.example", output)
        self.assertIn("two.example", output)
        self.assertEqual(
            output.rstrip().splitlines()[-1], "1 ok, 1 warning, 0 errors"
        )

    def test_newlines_in_details_are_collapsed(self) -> None:
        report = HostReport(
            "example.com",
            (finding("cert.expiry", "error", detail="line one\nline two"),),
        )
        self.assertNotIn("line one\nline two", render_table([report]))


class MarkdownRenderingTests(unittest.TestCase):
    def test_single_host_markdown(self) -> None:
        report = HostReport(
            "example.com",
            (
                finding(
                    "http.hsts",
                    "warning",
                    title="HSTS header is missing",
                    detail="No | header\npresent",
                    remediation="Add `Strict-Transport-Security`.",
                ),
            ),
        )
        output = render_markdown([report])
        self.assertIn("## TLS diagnosis for `example.com`", output)
        self.assertIn("| Check | Severity | Finding | Detail | Remediation |", output)
        self.assertIn("`http.hsts`", output)
        self.assertIn("No \\| header present", output)
        self.assertNotIn("No | header\npresent", output)
        self.assertIn("**Summary:** 0 ok, 1 warning, 0 errors", output)

    def test_multiple_hosts_have_sections_and_total(self) -> None:
        reports = [
            HostReport("one.example", (finding("cert.expiry", "ok"),)),
            HostReport("two.example", (finding("http.hsts", "warning"),)),
        ]
        output = render_markdown(reports)
        self.assertIn("## TLS diagnosis", output)
        self.assertIn("### `one.example`", output)
        self.assertIn("### `two.example`", output)
        self.assertIn("**Total:** 1 ok, 1 warning, 0 errors", output)

    def test_empty_remediation_uses_dash(self) -> None:
        report = HostReport("example.com", (finding("cert.expiry", "ok"),))
        self.assertIn("| — |", render_markdown([report]))


class ExitCodeTests(unittest.TestCase):
    def test_constants(self) -> None:
        self.assertEqual((EXIT_OK, EXIT_WARNINGS, EXIT_ERRORS, EXIT_USAGE), (0, 1, 2, 3))

    def test_decisions(self) -> None:
        ok = HostReport("ok.example", (finding("a", "ok"),))
        info = HostReport("info.example", (finding("a", "info"),))
        warning = HostReport("warn.example", (finding("a", "warning"),))
        error = HostReport("error.example", (finding("a", "error"),))
        mixed = HostReport(
            "mixed.example", (finding("a", "warning"), finding("b", "error"))
        )

        self.assertEqual(decide_exit([ok], "error"), EXIT_OK)
        self.assertEqual(decide_exit([info], "warning"), EXIT_OK)
        self.assertEqual(decide_exit([warning], "error"), EXIT_OK)
        self.assertEqual(decide_exit([warning], "warning"), EXIT_WARNINGS)
        self.assertEqual(decide_exit([error], "error"), EXIT_ERRORS)
        self.assertEqual(decide_exit([error], "warning"), EXIT_ERRORS)
        self.assertEqual(decide_exit([mixed], "warning"), EXIT_ERRORS)
        self.assertEqual(decide_exit([mixed], "never"), EXIT_OK)
        self.assertEqual(decide_exit([error], "never"), EXIT_OK)
        self.assertEqual(decide_exit([], "warning"), EXIT_OK)

    def test_invalid_fail_on(self) -> None:
        with self.assertRaises(ValueError):
            decide_exit([], "sometimes")


class DispatchTests(unittest.TestCase):
    def test_render_dispatch(self) -> None:
        report = HostReport("example.com", (finding("a", "ok"),))
        self.assertEqual(render([report], "json"), render_json([report]))
        self.assertEqual(render([report], "md"), render_markdown([report]))
        self.assertEqual(render([report], "table"), render_table([report]))

    def test_invalid_format(self) -> None:
        with self.assertRaises(ValueError):
            render([], "xml")

    def test_finding_validates_severity(self) -> None:
        with self.assertRaises(ValueError):
            Finding("x", "fatal", "title", "detail")


if __name__ == "__main__":
    unittest.main()
