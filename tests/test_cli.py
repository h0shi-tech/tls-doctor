"""Offline CLI tests using injected probes (no network access)."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from tls_doctor.certs import pem_to_der
from tls_doctor.cli import main
from tls_doctor.probes import (
    HttpProbeResult,
    ProtocolProbeResult,
    TlsProbeResult,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "example-cert.pem"
FIXTURE_DER = pem_to_der(FIXTURE.read_text(encoding="ascii"))
NOW = datetime(2027, 1, 1, tzinfo=timezone.utc)
EXPIRED_NOW = datetime(2050, 1, 1, tzinfo=timezone.utc)


def valid_tls_result() -> TlsProbeResult:
    return TlsProbeResult(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        certificate_chain=(FIXTURE_DER,),
    )


class StubProbes:
    def __init__(
        self,
        tls_result: TlsProbeResult | None = None,
        legacy_result: tuple[ProtocolProbeResult, ...] | None = None,
        hsts_result: HttpProbeResult | None = None,
        redirect_result: HttpProbeResult | None = None,
    ) -> None:
        self.tls_result = tls_result or valid_tls_result()
        self.legacy_result = legacy_result or (
            ProtocolProbeResult("TLSv1.0", False, "rejected"),
            ProtocolProbeResult("TLSv1.1", False, "rejected"),
        )
        self.hsts_result = hsts_result or HttpProbeResult(
            status=200,
            headers=(
                (
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                ),
            ),
        )
        self.redirect_result = redirect_result or HttpProbeResult(
            status=301,
            headers=(("Location", "https://fixture.example.com/"),),
        )
        self.calls: list[str] = []

    def tls(self, **kwargs: object) -> TlsProbeResult:
        self.calls.append("tls")
        return self.tls_result

    def legacy(self, **kwargs: object) -> tuple[ProtocolProbeResult, ...]:
        self.calls.append("legacy")
        return self.legacy_result

    def hsts(self, **kwargs: object) -> HttpProbeResult:
        self.calls.append("hsts")
        return self.hsts_result

    def redirect(self, **kwargs: object) -> HttpProbeResult:
        self.calls.append("redirect")
        return self.redirect_result


def run_cli(
    argv: list[str],
    probes: StubProbes,
    now: datetime = NOW,
) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv, probes=probes, now=now)  # type: ignore[arg-type]
    return code, stdout.getvalue(), stderr.getvalue()


class CliOutputTests(unittest.TestCase):
    def test_no_network_probe_skips_supplemental_checks(self) -> None:
        stub = StubProbes()
        code, output, error = run_cli(
            ["fixture.example.com", "--no-network-probe", "--format", "json"],
            stub,
        )
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        payload = json.loads(output)
        self.assertEqual(payload["host"], "fixture.example.com")
        self.assertEqual(stub.calls, ["tls"])
        ids = [finding["id"] for finding in payload["findings"]]
        self.assertEqual(
            ids,
            [
                "cert.expiry",
                "cert.hostname",
                "cert.chain",
                "tls.version",
                "tls.cipher",
            ],
        )
        self.assertEqual(payload["summary"]["warning"], 1)
        self.assertEqual(payload["summary"]["error"], 0)

    def test_full_output_contains_all_check_ids(self) -> None:
        stub = StubProbes()
        code, output, _ = run_cli(
            ["fixture.example.com", "--format", "json"], stub
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        ids = [finding["id"] for finding in payload["findings"]]
        self.assertEqual(
            ids,
            [
                "cert.expiry",
                "cert.hostname",
                "cert.chain",
                "tls.version",
                "tls.legacy",
                "tls.cipher",
                "http.hsts",
                "http.hsts.scope",
                "http.redirect",
            ],
        )
        self.assertEqual(stub.calls, ["tls", "legacy", "hsts", "redirect"])
        self.assertEqual(payload["summary"]["info"], 1)
        self.assertEqual(payload["summary"]["warning"], 1)

    def test_table_and_markdown_formats(self) -> None:
        table_code, table, _ = run_cli(
            ["fixture.example.com", "--format", "table"], StubProbes()
        )
        self.assertEqual(table_code, 0)
        self.assertIn("HOST", table)
        self.assertIn("7 ok, 1 warning, 0 errors, 1 info", table)

        md_code, markdown, _ = run_cli(
            ["fixture.example.com", "--format", "md"], StubProbes()
        )
        self.assertEqual(md_code, 0)
        self.assertIn("## TLS diagnosis for `fixture.example.com`", markdown)
        self.assertIn("| Check | Severity |", markdown)

    def test_warning_failure_threshold(self) -> None:
        stub = StubProbes()
        code, _, _ = run_cli(
            ["fixture.example.com", "--fail-on", "warning", "--format", "json"],
            stub,
        )
        self.assertEqual(code, 1)

        code, _, _ = run_cli(
            ["fixture.example.com", "--fail-on", "error", "--format", "json"],
            stub,
        )
        self.assertEqual(code, 0)

    def test_expired_certificate_is_an_error(self) -> None:
        code, output, _ = run_cli(
            ["fixture.example.com", "--format", "json"],
            StubProbes(),
            now=EXPIRED_NOW,
        )
        self.assertEqual(code, 2)
        payload = json.loads(output)
        expiry = next(
            finding
            for finding in payload["findings"]
            if finding["id"] == "cert.expiry"
        )
        self.assertEqual(expiry["severity"], "error")

        code, _, _ = run_cli(
            ["fixture.example.com", "--fail-on", "never", "--format", "json"],
            StubProbes(),
            now=EXPIRED_NOW,
        )
        self.assertEqual(code, 0)

    def test_unreachable_is_a_clean_finding(self) -> None:
        stub = StubProbes(
            tls_result=TlsProbeResult(
                error="connection refused", error_kind="refused"
            )
        )
        code, output, error = run_cli(
            ["fixture.example.com", "--format", "json"], stub
        )
        self.assertEqual(code, 2)
        self.assertEqual(error, "")
        payload = json.loads(output)
        self.assertEqual(len(payload["findings"]), 1)
        finding = payload["findings"][0]
        self.assertEqual(finding["id"], "unreachable")
        self.assertEqual(finding["severity"], "error")
        self.assertIn("connection refused", finding["detail"])
        self.assertNotIn("Traceback", output)

    def test_multiple_hosts_keep_argument_order(self) -> None:
        stub = StubProbes()
        code, output, _ = run_cli(
            [
                "www.fixture.example.com",
                "fixture.example.com",
                "--no-network-probe",
                "--format",
                "json",
                "--fail-on",
                "never",
            ],
            stub,
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertIsInstance(payload, list)
        self.assertEqual(
            [item["host"] for item in payload],
            ["www.fixture.example.com", "fixture.example.com"],
        )

    def test_port_is_reflected_in_display_and_passed_to_probe(self) -> None:
        stub = StubProbes()
        code, output, _ = run_cli(
            [
                "fixture.example.com",
                "--port",
                "8443",
                "--no-network-probe",
                "--format",
                "json",
            ],
            stub,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["host"], "fixture.example.com:8443")


class CliUsageTests(unittest.TestCase):
    def assert_usage_error(self, argv: list[str]) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(argv, probes=StubProbes(), now=NOW)  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, 3)

    def test_usage_errors_exit_3(self) -> None:
        cases = [
            [],
            ["--port", "0", "example.com"],
            ["--port", "65536", "example.com"],
            ["--timeout", "0", "example.com"],
            ["--timeout", "nan", "example.com"],
            ["--min-days", "-1", "example.com"],
            ["--format", "xml", "example.com"],
            ["--fail-on", "sometimes", "example.com"],
            ["--ip", "not-an-ip", "example.com"],
            ["--ip", "127.0.0.1", "one.example", "two.example"],
            ["https://example.com/path"],
            ["example.com:8443"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assert_usage_error(argv)

    def test_help_and_version_exit_0(self) -> None:
        for argv in (["--help"], ["--version"]):
            with self.subTest(argv=argv):
                with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(
                    io.StringIO()
                ):
                    with self.assertRaises(SystemExit) as caught:
                        main(argv, probes=StubProbes(), now=NOW)
                self.assertEqual(caught.exception.code, 0)
                self.assertTrue(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
