"""Offline failure-path tests for the real network probes.

These use a loopback port that was just closed, so no external network access is
required and no public host is contacted.
"""

from __future__ import annotations

import socket
import unittest

from tls_doctor.probes import probe_http_hsts, probe_tls


def closed_loopback_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class ProbeFailureTests(unittest.TestCase):
    def test_tls_refusal_is_a_clean_result(self) -> None:
        port = closed_loopback_port()
        result = probe_tls("127.0.0.1", port=port, timeout=1)
        self.assertIsNotNone(result.error)
        self.assertIn(result.error_kind, {"refused", "network"})
        self.assertNotIn("Traceback", result.error or "")

    def test_hsts_probe_failure_is_a_clean_result(self) -> None:
        port = closed_loopback_port()
        result = probe_http_hsts("127.0.0.1", port=port, timeout=1)
        self.assertIsNotNone(result.error)
        self.assertIn(result.error_kind, {"refused", "network"})

    def test_tls_timeout_is_a_clean_result(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = int(listener.getsockname()[1])
            result = probe_tls("127.0.0.1", port=port, timeout=0.2)
        finally:
            listener.close()
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error_kind, "timeout")
        self.assertNotIn("Traceback", result.error or "")


if __name__ == "__main__":
    unittest.main()
