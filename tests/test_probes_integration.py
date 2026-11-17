"""Integration test against a local, openssl-generated TLS server.

The public internet is never used.  If the openssl executable is unavailable
the test class is skipped cleanly.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from tls_doctor.certs import parse_certificate
from tls_doctor.checks import check_chain, check_hostname, check_hsts
from tls_doctor.probes import probe_http_hsts, probe_legacy, probe_tls

OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "openssl executable is required for the local TLS server test")
class LocalTlsServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="tls-doctor-integration-")
        base = Path(cls._tmp.name)
        cls.cert_path = base / "cert.pem"
        cls.key_path = base / "key.pem"
        config_path = base / "openssl.cnf"
        config_path.write_text(
            """\
[req]
prompt = no
distinguished_name = dn
x509_extensions = ext

[dn]
CN = localhost
O = tls-doctor local test

[ext]
subjectAltName = DNS:localhost, IP:127.0.0.1
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
""",
            encoding="ascii",
        )

        try:
            completed = subprocess.run(
                [
                    OPENSSL,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-sha256",
                    "-nodes",
                    "-days",
                    "30",
                    "-keyout",
                    str(cls.key_path),
                    "-out",
                    str(cls.cert_path),
                    "-config",
                    str(config_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise unittest.SkipTest(f"could not run openssl: {exc}") from exc

        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip()
            raise unittest.SkipTest(f"openssl could not generate a test certificate: {message}")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cls.cert_path), str(cls.key_path))

        cls._context = context
        cls._stop = threading.Event()
        cls._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls._listener.bind(("127.0.0.1", 0))
        cls._listener.listen(8)
        cls._listener.settimeout(0.2)
        cls.port = cls._listener.getsockname()[1]
        cls._thread = threading.Thread(
            target=cls._serve,
            name="tls-doctor-test-server",
            daemon=True,
        )
        cls._thread.start()

    @classmethod
    def _serve(cls) -> None:
        while not cls._stop.is_set():
            try:
                connection, _ = cls._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                with cls._context.wrap_socket(
                    connection, server_side=True
                ) as tls_socket:
                    tls_socket.settimeout(2)
                    try:
                        request = tls_socket.recv(4096)
                    except (OSError, ssl.SSLError):
                        request = b""
                    if request.startswith((b"HEAD ", b"GET ")):
                        tls_socket.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Strict-Transport-Security: max-age=31536000; "
                            b"includeSubDomains; preload\r\n"
                            b"Content-Length: 0\r\n"
                            b"Connection: close\r\n"
                            b"\r\n"
                        )
            except (OSError, ssl.SSLError):
                pass
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stop.set()
        try:
            cls._listener.close()
        except OSError:
            pass
        cls._thread.join(timeout=5)
        cls._tmp.cleanup()

    def test_probe_observes_local_certificate(self) -> None:
        result = probe_tls("127.0.0.1", port=self.port, timeout=5)

        self.assertIsNone(result.error)
        self.assertIn(result.protocol_version, {"TLSv1.2", "TLSv1.3"})
        self.assertGreaterEqual(result.cipher_bits, 128)
        self.assertTrue(result.certificate_chain)

        certificate = parse_certificate(result.certificate_chain[0])
        self.assertIn("localhost", certificate.dns_names)
        self.assertIn("127.0.0.1", certificate.ip_addresses)
        self.assertTrue(certificate.is_self_signed)

        hostname_finding = check_hostname(certificate, "127.0.0.1")
        self.assertEqual(hostname_finding.severity, "ok")

        chain_finding = check_chain([certificate])
        self.assertEqual(chain_finding.severity, "warning")
        self.assertIn("self-signed", chain_finding.detail)

    def test_ip_override_connects_to_pinned_address(self) -> None:
        result = probe_tls(
            "unresolvable.tls-doctor.invalid",
            port=self.port,
            timeout=5,
            ip="127.0.0.1",
        )
        self.assertIsNone(result.error)
        self.assertTrue(result.certificate_chain)

    def test_legacy_probe_observes_modern_only_server(self) -> None:
        results = probe_legacy("127.0.0.1", port=self.port, timeout=5)
        self.assertEqual(
            [result.version for result in results], ["TLSv1.0", "TLSv1.1"]
        )
        self.assertFalse(any(result.supported is True for result in results))

    def test_hsts_probe_reads_local_https_headers(self) -> None:
        result = probe_http_hsts("127.0.0.1", port=self.port, timeout=5)

        self.assertIsNone(result.error)
        self.assertEqual(result.status, 200)
        header = result.header("strict-transport-security")
        self.assertIsNotNone(header)
        self.assertIn("max-age=31536000", header or "")

        findings = check_hsts(header)
        self.assertEqual(findings[0].severity, "ok")
        self.assertEqual(findings[1].id, "http.hsts.scope")
        self.assertEqual(findings[1].severity, "info")


if __name__ == "__main__":
    unittest.main()
