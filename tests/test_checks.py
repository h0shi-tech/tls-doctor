"""Offline tests for the pure finding rules."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from tls_doctor.certs import CertificateInfo
from tls_doctor.checks import (
    HSTS_MIN_MAX_AGE,
    assess_cipher,
    certificate_matches_host,
    check_chain,
    check_cipher,
    check_expiry,
    check_hostname,
    check_hsts,
    check_redirect,
    check_tls_legacy,
    check_tls_version,
    hostname_matches_san,
    is_https_redirect,
    parse_hsts,
    unreachable,
    version_rank,
)

NOW = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_certificate(
    *,
    subject: str = "CN=leaf.example.com",
    issuer: str = "CN=Test CA",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    dns_names: tuple[str, ...] = ("example.com",),
    ip_addresses: tuple[str, ...] = (),
) -> CertificateInfo:
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before or (NOW - timedelta(days=1)),
        not_after=not_after or (NOW + timedelta(days=90)),
        serial=12345,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
    )


class HostnameMatchingTests(unittest.TestCase):
    def test_exact_and_case_insensitive_matches(self) -> None:
        cases = [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("example.com", "EXAMPLE.COM"),
            ("example.com.", "example.com"),
            ("example.com", "example.com."),
            ("www.example.com", "www.example.com"),
        ]
        for host, san in cases:
            with self.subTest(host=host, san=san):
                self.assertTrue(hostname_matches_san(host, san))

    def test_obvious_non_matches(self) -> None:
        cases = [
            ("example.org", "example.com"),
            ("www.example.com", "example.com"),
            ("example.com", "www.example.com"),
            ("badexample.com", "example.com"),
            ("", "example.com"),
            ("example.com", ""),
            ("a..example.com", "example.com"),
        ]
        for host, san in cases:
            with self.subTest(host=host, san=san):
                self.assertFalse(hostname_matches_san(host, san))

    def test_wildcard_matches_exactly_one_label(self) -> None:
        cases = [
            ("a.example.com", "*.example.com", True),
            ("A.EXAMPLE.COM", "*.example.com", True),
            ("a.example.com.", "*.Example.Com.", True),
            ("example.com", "*.example.com", False),
            ("a.b.example.com", "*.example.com", False),
            ("a.b.c.example.com", "*.example.com", False),
            ("notexample.com", "*.example.com", False),
            ("evil-example.com", "*.example.com", False),
            ("example.com.evil.test", "*.example.com", False),
            (".example.com", "*.example.com", False),
            ("a..example.com", "*.example.com", False),
            ("foo.example.co.uk", "*.example.co.uk", True),
            ("foo.bar.example.co.uk", "*.example.co.uk", False),
        ]
        for host, san, expected in cases:
            with self.subTest(host=host, san=san):
                self.assertEqual(hostname_matches_san(host, san), expected)

    def test_wildcards_are_leftmost_only(self) -> None:
        cases = [
            ("www.example.com", "www.*.com"),
            ("www.example.com", "*.example.*"),
            ("www.example.com", "*.*.com"),
            ("www.example.com", "w*.example.com"),
            ("www.example.com", "*.com"),
            ("www.example.com", "*.example"),
            ("www.example.com", "*"),
        ]
        for host, san in cases:
            with self.subTest(host=host, san=san):
                self.assertFalse(hostname_matches_san(host, san))

    def test_wildcard_pattern_rejects_wildcard_host(self) -> None:
        self.assertFalse(hostname_matches_san("*.example.com", "*.example.com"))

    def test_idna_hostnames(self) -> None:
        self.assertTrue(
            hostname_matches_san("www.bücher.example", "*.xn--bcher-kva.example")
        )
        self.assertTrue(
            hostname_matches_san("BÜCHER.example", "xn--bcher-kva.example")
        )
        self.assertFalse(
            hostname_matches_san("a.b.bücher.example", "*.xn--bcher-kva.example")
        )

    def test_certificate_uses_every_san(self) -> None:
        certificate = make_certificate(
            dns_names=("first.example.com", "*.wild.example.com")
        )
        matched, value, _ = certificate_matches_host(certificate, "api.wild.example.com")
        self.assertTrue(matched)
        self.assertEqual(value, "DNS:*.wild.example.com")

        matched, value, _ = certificate_matches_host(certificate, "first.example.com")
        self.assertTrue(matched)
        self.assertEqual(value, "DNS:first.example.com")

        matched, _, _ = certificate_matches_host(certificate, "second.example.com")
        self.assertFalse(matched)

    def test_ip_sans_are_matched_by_ip_literal(self) -> None:
        certificate = make_certificate(
            dns_names=("example.com",),
            ip_addresses=("127.0.0.1", "::1"),
        )
        for host in ("127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1"):
            with self.subTest(host=host):
                matched, _, explanation = certificate_matches_host(certificate, host)
                self.assertTrue(matched)
                self.assertEqual(explanation, "iPAddress SAN")

    def test_ip_host_does_not_use_dns_san(self) -> None:
        certificate = make_certificate(
            dns_names=("127.0.0.1",), ip_addresses=()
        )
        matched, _, explanation = certificate_matches_host(certificate, "127.0.0.1")
        self.assertFalse(matched)
        self.assertIn("IP address", explanation)

    def test_common_name_is_not_used_as_fallback(self) -> None:
        certificate = make_certificate(
            subject="CN=example.com", dns_names=()
        )
        finding = check_hostname(certificate, "example.com")
        self.assertEqual(finding.severity, "error")
        self.assertIn("no DNS SAN", finding.detail)

    def test_hostname_findings(self) -> None:
        certificate = make_certificate(dns_names=("*.example.com",))
        ok = check_hostname(certificate, "api.example.com")
        self.assertEqual(ok.severity, "ok")
        self.assertIn("api.example.com", ok.detail)

        error = check_hostname(certificate, "example.com")
        self.assertEqual(error.id, "cert.hostname")
        self.assertEqual(error.severity, "error")
        self.assertIn("subjectAltName", error.detail)
        self.assertTrue(error.remediation.startswith("Reissue"))


class ExpiryTests(unittest.TestCase):
    def test_boundary_values(self) -> None:
        cases = [
            (-1, "error"),
            (0, "warning"),
            (13, "warning"),
            (14, "ok"),
            (15, "ok"),
        ]
        for days, expected in cases:
            with self.subTest(days=days):
                certificate = make_certificate(
                    not_after=NOW + timedelta(days=days)
                )
                finding = check_expiry(certificate, min_days=14, now=NOW)
                self.assertEqual(finding.severity, expected)
                self.assertEqual(finding.id, "cert.expiry")

    def test_floor_to_whole_days(self) -> None:
        warning = check_expiry(
            make_certificate(not_after=NOW + timedelta(seconds=1)),
            min_days=14,
            now=NOW,
        )
        self.assertEqual(warning.severity, "warning")

        error = check_expiry(
            make_certificate(not_after=NOW - timedelta(seconds=1)),
            min_days=14,
            now=NOW,
        )
        self.assertEqual(error.severity, "error")
        self.assertIn("Expired 1 day ago", error.detail)

    def test_zero_min_days(self) -> None:
        finding = check_expiry(
            make_certificate(not_after=NOW), min_days=0, now=NOW
        )
        self.assertEqual(finding.severity, "ok")

    def test_details_include_date_and_threshold(self) -> None:
        finding = check_expiry(
            make_certificate(not_after=NOW + timedelta(days=3)),
            min_days=14,
            now=NOW,
        )
        self.assertIn("3 days left", finding.detail)
        self.assertIn("2030-01-04", finding.detail)
        self.assertIn("14 days", finding.detail)
        self.assertEqual(finding.severity, "warning")


class CipherTests(unittest.TestCase):
    def test_known_weak_ciphers(self) -> None:
        cases = [
            ("TLS_RSA_WITH_NULL_SHA", 0),
            ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 40),
            ("EXP-RC4-MD5", 40),
            ("ECDHE-RSA-RC4-SHA", 128),
            ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 168),
            ("ECDHE-RSA-DES-CBC3-SHA", 168),
            ("TLS_RSA_WITH_DES40_CBC_SHA", 40),
            ("TLS_RSA_WITH_DES_CBC_SHA", 56),
            ("ECDHE-RSA-AES256-GCM-SHA384", 127),
        ]
        for name, bits in cases:
            with self.subTest(name=name, bits=bits):
                assessment = assess_cipher(name, bits)
                self.assertTrue(assessment.weak)
                finding = check_cipher(name, bits)
                self.assertEqual(finding.id, "tls.cipher")
                self.assertEqual(finding.severity, "error")
                self.assertTrue(finding.remediation)

    def test_strong_ciphers_are_not_flagged(self) -> None:
        cases = [
            ("TLS_AES_256_GCM_SHA384", 256),
            ("TLS_AES_128_GCM_SHA256", 128),
            ("TLS_CHACHA20_POLY1305_SHA256", 256),
            ("ECDHE-RSA-AES128-GCM-SHA256", 128),
            ("ECDHE-RSA-AES256-GCM-SHA384", 256),
            ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 256),
        ]
        for name, bits in cases:
            with self.subTest(name=name, bits=bits):
                self.assertFalse(assess_cipher(name, bits).weak)
                finding = check_cipher(name, bits)
                self.assertEqual(finding.severity, "ok")
                self.assertIn(name, finding.detail)

    def test_multiple_reasons_are_reported(self) -> None:
        assessment = assess_cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 40)
        self.assertGreaterEqual(len(assessment.reasons), 3)
        self.assertIn("export-grade cipher", assessment.reasons)
        self.assertIn("RC4 stream cipher", assessment.reasons)
        self.assertIn("effective key strength is only 40 bits", assessment.reasons)


class HstsParsingTests(unittest.TestCase):
    def test_full_header(self) -> None:
        policy = parse_hsts("max-age=31536000; includeSubDomains; preload")
        self.assertTrue(policy.present)
        self.assertEqual(policy.max_age, 31536000)
        self.assertTrue(policy.include_subdomains)
        self.assertTrue(policy.preload)
        self.assertEqual(
            policy.directives,
            (
                ("max-age", "31536000"),
                ("includesubdomains", None),
                ("preload", None),
            ),
        )

    def test_quoted_max_age(self) -> None:
        policy = parse_hsts('max-age="31536000"; includeSubDomains')
        self.assertEqual(policy.max_age, 31536000)
        self.assertTrue(policy.include_subdomains)

    def test_whitespace_and_case(self) -> None:
        policy = parse_hsts("  MAX-AGE = 86400 ; IncludeSubDomains ; Preload ")
        self.assertEqual(policy.max_age, 86400)
        self.assertTrue(policy.include_subdomains)
        self.assertTrue(policy.preload)

    def test_missing_max_age(self) -> None:
        policy = parse_hsts("includeSubDomains; preload")
        self.assertTrue(policy.present)
        self.assertIsNone(policy.max_age)
        self.assertTrue(policy.include_subdomains)
        self.assertTrue(policy.preload)

    def test_absent_header(self) -> None:
        for value in (None, "", "   "):
            with self.subTest(value=value):
                policy = parse_hsts(value)
                self.assertFalse(policy.present)
                self.assertIsNone(policy.max_age)

    def test_invalid_max_age(self) -> None:
        for value in (
            "max-age=",
            "max-age=abc",
            "max-age=-1",
            "max-age=3.14",
            'max-age="12x"',
            "max-age=0x10",
        ):
            with self.subTest(value=value):
                policy = parse_hsts(value)
                self.assertTrue(policy.present)
                self.assertIsNone(policy.max_age)

    def test_repeated_directive_uses_first(self) -> None:
        policy = parse_hsts("max-age=100; max-age=200")
        self.assertEqual(policy.max_age, 100)

    def test_commas_inside_quotes_do_not_split(self) -> None:
        policy = parse_hsts('max-age="100"; note="a,b"; includeSubDomains')
        self.assertEqual(policy.max_age, 100)
        self.assertTrue(policy.include_subdomains)

    def test_multiple_headers_can_be_combined_with_commas(self) -> None:
        policy = parse_hsts("max-age=100, includeSubDomains")
        self.assertEqual(policy.max_age, 100)
        self.assertTrue(policy.include_subdomains)


class HstsFindingTests(unittest.TestCase):
    def test_missing_header_warns(self) -> None:
        findings = check_hsts(None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "http.hsts")
        self.assertEqual(findings[0].severity, "warning")
        self.assertIn("missing", findings[0].title.lower())

    def test_short_max_age_warns(self) -> None:
        findings = check_hsts(f"max-age={HSTS_MIN_MAX_AGE - 1}")
        self.assertEqual(findings[0].severity, "warning")
        self.assertIn("max-age", findings[0].detail)

    def test_minimum_max_age_is_ok(self) -> None:
        findings = check_hsts(f"max-age={HSTS_MIN_MAX_AGE}")
        self.assertEqual(findings[0].severity, "ok")
        self.assertEqual(len(findings), 1)

    def test_valid_policy_with_scope_reports_info(self) -> None:
        findings = check_hsts(
            "max-age=31536000; includeSubDomains; preload"
        )
        self.assertEqual(findings[0].severity, "ok")
        self.assertEqual(len(findings), 2)
        scope = findings[1]
        self.assertEqual(scope.id, "http.hsts.scope")
        self.assertEqual(scope.severity, "info")
        self.assertIn("includeSubDomains", scope.detail)
        self.assertIn("preload", scope.detail)

    def test_include_subdomains_without_preload(self) -> None:
        findings = check_hsts("max-age=31536000; includeSubDomains")
        self.assertEqual(len(findings), 2)
        self.assertIn("includeSubDomains", findings[1].detail)
        self.assertNotIn("preload is declared", findings[1].detail)

    def test_probe_error_is_informational(self) -> None:
        findings = check_hsts(None, error="connection refused")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")
        self.assertIn("connection refused", findings[0].detail)


class RedirectTests(unittest.TestCase):
    def test_https_redirect_classifier(self) -> None:
        cases = [
            (301, "https://example.com/", True),
            (302, "HTTPS://EXAMPLE.COM/next", True),
            (303, "https://example.com:8443/", True),
            (307, "https://example.com/", True),
            (308, "https://example.com/", True),
            (200, "https://example.com/", False),
            (301, "http://example.com/", False),
            (301, "/relative", False),
            (301, "//example.com/", False),
            (301, None, False),
            (None, "https://example.com/", False),
            (301, "https://", False),
            (301, "https://example.com/a b", False),
        ]
        for status, location, expected in cases:
            with self.subTest(status=status, location=location):
                self.assertEqual(is_https_redirect(status, location), expected)

    def test_https_redirect_is_ok(self) -> None:
        finding = check_redirect(301, "https://example.com/")
        self.assertEqual(finding.id, "http.redirect")
        self.assertEqual(finding.severity, "ok")

    def test_http_redirect_warns(self) -> None:
        finding = check_redirect(302, "http://example.com/")
        self.assertEqual(finding.severity, "warning")
        self.assertIn("not an absolute HTTPS URL", finding.detail)

    def test_no_redirect_warns(self) -> None:
        finding = check_redirect(200, None)
        self.assertEqual(finding.severity, "warning")
        self.assertIn("HTTP 200", finding.detail)

    def test_relative_location_warns(self) -> None:
        finding = check_redirect(301, "/login")
        self.assertEqual(finding.severity, "warning")

    def test_refused_http_is_ok(self) -> None:
        finding = check_redirect(
            None, None, error="connection refused", error_kind="refused"
        )
        self.assertEqual(finding.severity, "ok")
        self.assertEqual(finding.title, "No plain HTTP listener")

    def test_other_probe_errors_warn(self) -> None:
        for kind in ("timeout", "dns", "network", "other"):
            with self.subTest(kind=kind):
                finding = check_redirect(
                    None, None, error="probe failed", error_kind=kind
                )
                self.assertEqual(finding.severity, "warning")


class ProtocolTests(unittest.TestCase):
    def test_version_ranks(self) -> None:
        self.assertLess(version_rank("TLSv1.1"), version_rank("TLSv1.2"))
        self.assertLess(version_rank("TLSv1"), version_rank("TLSv1.2"))
        self.assertIsNone(version_rank("nonsense"))

    def test_acceptable_versions(self) -> None:
        for version in ("TLSv1.2", "TLSv1.3"):
            with self.subTest(version=version):
                finding = check_tls_version(version)
                self.assertEqual(finding.severity, "ok")

    def test_obsolete_versions_are_errors(self) -> None:
        for version in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"):
            with self.subTest(version=version):
                finding = check_tls_version(version)
                self.assertEqual(finding.severity, "error")
                self.assertEqual(finding.id, "tls.version")

    def test_unknown_version_warns(self) -> None:
        self.assertEqual(check_tls_version("TLSv9.9").severity, "warning")

    def test_legacy_accepted_warns(self) -> None:
        finding = check_tls_legacy(
            [
                ("TLSv1.0", True, None),
                ("TLSv1.1", False, "alert protocol version"),
            ]
        )
        self.assertEqual(finding.id, "tls.legacy")
        self.assertEqual(finding.severity, "warning")
        self.assertIn("TLSv1.0", finding.detail)
        self.assertEqual(finding.detail.count("still accepts"), 1)

    def test_legacy_both_accepted_warns(self) -> None:
        finding = check_tls_legacy(
            [("TLSv1.0", True, None), ("TLSv1.1", True, None)]
        )
        self.assertEqual(finding.severity, "warning")

    def test_legacy_refused_is_ok(self) -> None:
        finding = check_tls_legacy(
            [
                ("TLSv1.0", False, "protocol version"),
                ("TLSv1.1", False, "protocol version"),
            ]
        )
        self.assertEqual(finding.severity, "ok")
        self.assertIn("Refused", finding.detail)

    def test_legacy_untestable_is_info(self) -> None:
        finding = check_tls_legacy(
            [
                ("TLSv1.0", None, "client does not support TLS 1.0"),
                ("TLSv1.1", None, "client does not support TLS 1.1"),
            ]
        )
        self.assertEqual(finding.severity, "info")
        self.assertIn("Could not test", finding.detail)

    def test_legacy_unexpected_client_error_is_info(self) -> None:
        finding = check_tls_legacy(
            [
                ("TLSv1.0", False, None),
                ("TLSv1.1", None, "connection reset"),
            ]
        )
        self.assertEqual(finding.severity, "info")
        self.assertIn("Refused", finding.detail)
        self.assertIn("Could not test", finding.detail)


class ChainTests(unittest.TestCase):
    def test_normal_chain(self) -> None:
        leaf = make_certificate(subject="CN=leaf", issuer="CN=Intermediate")
        intermediate = make_certificate(
            subject="CN=Intermediate",
            issuer="CN=Root",
            dns_names=(),
        )
        finding = check_chain([leaf, intermediate], now=NOW)
        self.assertEqual(finding.id, "cert.chain")
        self.assertEqual(finding.severity, "ok")
        self.assertIn("2 certificates", finding.detail)

    def test_self_signed_leaf_warns(self) -> None:
        certificate = make_certificate(
            subject="CN=localhost", issuer="CN=localhost"
        )
        finding = check_chain([certificate], now=NOW)
        self.assertEqual(finding.severity, "warning")
        self.assertIn("self-signed", finding.detail)

    def test_expired_intermediate_is_an_error(self) -> None:
        leaf = make_certificate(subject="CN=leaf", issuer="CN=Intermediate")
        expired = make_certificate(
            subject="CN=Intermediate",
            issuer="CN=Root",
            not_before=NOW - timedelta(days=400),
            not_after=NOW - timedelta(days=1),
            dns_names=(),
        )
        finding = check_chain([leaf, expired], now=NOW)
        self.assertEqual(finding.severity, "error")
        self.assertIn("expired", finding.detail)

    def test_single_leaf_certificate_warns_about_missing_chain(self) -> None:
        finding = check_chain(
            [make_certificate(subject="CN=leaf", issuer="CN=CA")], now=NOW
        )
        self.assertEqual(finding.severity, "warning")
        self.assertIn("only the leaf", finding.detail)

    def test_included_self_signed_root_is_not_a_failure(self) -> None:
        leaf = make_certificate(subject="CN=leaf", issuer="CN=Intermediate")
        intermediate = make_certificate(
            subject="CN=Intermediate", issuer="CN=Root", dns_names=()
        )
        root = make_certificate(
            subject="CN=Root", issuer="CN=Root", dns_names=()
        )
        finding = check_chain([leaf, intermediate, root], now=NOW)
        self.assertEqual(finding.severity, "ok")
        self.assertIn("self-signed root", finding.detail)

    def test_empty_chain_is_an_error(self) -> None:
        finding = check_chain([], now=NOW)
        self.assertEqual(finding.severity, "error")
        self.assertEqual(finding.id, "cert.chain")


class ConnectivityFindingTests(unittest.TestCase):
    def test_unreachable_finding(self) -> None:
        finding = unreachable(
            "example.com", 443, "timed out", error_kind="timeout"
        )
        self.assertEqual(finding.id, "unreachable")
        self.assertEqual(finding.severity, "error")
        self.assertIn("example.com:443", finding.detail)
        self.assertIn("timed out", finding.detail)
        self.assertIn("--timeout", finding.remediation)


if __name__ == "__main__":
    unittest.main()
