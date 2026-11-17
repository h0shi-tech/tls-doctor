"""Offline tests for certificate parsing and expiry arithmetic."""

from __future__ import annotations

import ssl
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tls_doctor.certs import (
    CertificateError,
    days_until,
    format_timestamp,
    parse_certificate,
    parse_certificate_pem,
    pem_to_der,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "example-cert.pem"


class CertificateParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pem = FIXTURE.read_text(encoding="ascii")
        cls.certificate = parse_certificate_pem(cls.pem)

    def test_fixture_metadata(self) -> None:
        certificate = self.certificate
        self.assertIn("fixture.example.com", certificate.subject)
        self.assertIn("TLS Doctor Tests", certificate.subject)
        self.assertEqual(certificate.subject, certificate.issuer)
        self.assertTrue(certificate.is_self_signed)
        self.assertGreater(certificate.serial, 0)
        self.assertIsNotNone(certificate.not_before.tzinfo)
        self.assertIsNotNone(certificate.not_after.tzinfo)
        self.assertEqual(certificate.not_before.utcoffset(), timedelta(0))
        self.assertEqual(certificate.not_after.utcoffset(), timedelta(0))
        self.assertEqual(
            (certificate.not_after - certificate.not_before).days, 3650
        )
        self.assertEqual(certificate.not_after.year, 2036)

    def test_fixture_sans(self) -> None:
        self.assertEqual(
            self.certificate.dns_names,
            ("fixture.example.com", "*.wild.example.com"),
        )
        self.assertEqual(self.certificate.ip_addresses, ("127.0.0.1",))
        self.assertIn("DNS:fixture.example.com", self.certificate.san_display)
        self.assertIn("IP:127.0.0.1", self.certificate.san_display)

    def test_pem_to_der_matches_stdlib(self) -> None:
        expected = ssl.PEM_cert_to_DER_cert(self.pem)
        actual = pem_to_der(self.pem)
        self.assertEqual(actual, expected)
        self.assertEqual(pem_to_der(self.pem.encode("ascii")), expected)

    def test_parse_der_directly(self) -> None:
        der = ssl.PEM_cert_to_DER_cert(self.pem)
        self.assertEqual(parse_certificate(der), self.certificate)

    def test_invalid_pem(self) -> None:
        with self.assertRaises(CertificateError):
            pem_to_der("this is not a certificate")
        with self.assertRaises(CertificateError):
            parse_certificate_pem(
                "-----BEGIN CERTIFICATE-----\nnot base64 at all\n"
                "-----END CERTIFICATE-----\n"
            )

    def test_invalid_der(self) -> None:
        for data in (
            b"",
            b"\x30\x03\x02\x01\x01",
            b"\x30\x82\xff\xff",
            b"\x00\x00",
        ):
            with self.subTest(data=data):
                with self.assertRaises(CertificateError):
                    parse_certificate(data)

    def test_wrong_input_type(self) -> None:
        with self.assertRaises(TypeError):
            parse_certificate("not bytes")  # type: ignore[arg-type]


class ExpiryMathTests(unittest.TestCase):
    def test_whole_day_flooring(self) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(
            days_until(now + timedelta(days=13, hours=23), now=now), 13
        )
        self.assertEqual(
            days_until(now + timedelta(seconds=1), now=now), 0
        )
        self.assertEqual(
            days_until(now - timedelta(seconds=1), now=now), -1
        )
        self.assertEqual(
            days_until(now - timedelta(days=1), now=now), -1
        )
        self.assertEqual(
            days_until(now + timedelta(days=14), now=now), 14
        )

    def test_naive_datetimes_are_utc(self) -> None:
        aware_now = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)
        naive_now = datetime(2030, 1, 1, 12)
        target = aware_now + timedelta(days=30)
        self.assertEqual(
            days_until(target, now=naive_now), days_until(target, now=aware_now)
        )

    def test_format_timestamp_normalizes_to_utc(self) -> None:
        value = datetime(
            2030, 1, 1, 14, 30, tzinfo=timezone(timedelta(hours=2))
        )
        self.assertEqual(format_timestamp(value), "2030-01-01 12:30:00 UTC")


if __name__ == "__main__":
    unittest.main()
