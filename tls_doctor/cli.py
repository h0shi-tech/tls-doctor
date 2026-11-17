"""Command-line interface for tls-doctor."""

from __future__ import annotations

import argparse
import ipaddress
import math
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from . import __version__
from .certs import CertificateError, CertificateInfo, parse_certificate
from .checks import (
    Finding,
    check_chain,
    check_cipher,
    check_expiry,
    check_hostname,
    check_hsts,
    check_redirect,
    check_tls_legacy,
    check_tls_version,
    unreachable,
)
from .probes import (
    DEFAULT_PROBES,
    HttpProbeResult,
    Probes,
    describe_exception,
)
from .report import (
    EXIT_USAGE,
    FAIL_ON_CHOICES,
    HostReport,
    decide_exit,
    render,
)

__all__ = ["build_parser", "diagnose_host", "main"]

MAX_WORKERS = 8

_EPILOG = """\
Exit codes:
  0  no finding reached the failure threshold
  1  warnings were found and --fail-on warning was selected
  2  errors were found and --fail-on error or warning was selected
  3  usage error
"""


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors use the documented exit code 3."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _port_type(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _timeout_type(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive number")
    return timeout


def _min_days_type(value: str) -> int:
    try:
        days = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("min-days must be an integer") from exc
    if days < 0:
        raise argparse.ArgumentTypeError("min-days must be zero or greater")
    return days


def _ip_type(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid IP address: {value!r}"
        ) from exc


def _host_type(value: str) -> str:
    host = value.strip()
    if not host:
        raise argparse.ArgumentTypeError("host must not be empty")
    if "://" in host or any(character in host for character in "/?#"):
        raise argparse.ArgumentTypeError(
            "expected a hostname, not a URL or path"
        )
    if any(character.isspace() for character in host):
        raise argparse.ArgumentTypeError("host must not contain whitespace")
    if host.startswith("["):
        if not host.endswith("]"):
            raise argparse.ArgumentTypeError("unterminated IPv6 address")
        candidate = host[1:-1]
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid IPv6 address: {host!r}"
            ) from exc
        return candidate
    if host.count(":") > 1:
        # Unbracketed IPv6 literal.
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "invalid hostname; use --port to select a port"
            ) from exc
        return host
    if ":" in host:
        raise argparse.ArgumentTypeError(
            "hostname must not include a port; use --port"
        )
    if "*" in host:
        raise argparse.ArgumentTypeError(
            "wildcard hostnames are not accepted; pass a concrete hostname"
        )
    return host


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""

    parser = _ArgumentParser(
        prog="tls-doctor",
        description=(
            "Diagnose the TLS configuration and HTTPS behaviour of one or more "
            "hostnames."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "hosts",
        nargs="+",
        metavar="HOST",
        type=_host_type,
        help="hostname to inspect (repeat for multiple hosts)",
    )
    parser.add_argument(
        "--port",
        type=_port_type,
        default=443,
        metavar="PORT",
        help="TLS port to connect to (default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=_timeout_type,
        default=5.0,
        metavar="SECONDS",
        help="per-connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--min-days",
        type=_min_days_type,
        default=14,
        metavar="DAYS",
        help="warn when a certificate expires in fewer than DAYS days (default: 14)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "md"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="error",
        help="lowest severity that produces a non-zero exit (default: error)",
    )
    parser.add_argument(
        "--ip",
        type=_ip_type,
        default=None,
        metavar="ADDRESS",
        help="connect to this IP address while keeping the hostname for SNI and checks",
    )
    parser.add_argument(
        "--no-network-probe",
        action="store_true",
        help=(
            "skip supplemental legacy-TLS and HTTP probes; the primary TLS "
            "handshake still runs"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


@dataclass(frozen=True, slots=True)
class _Options:
    port: int
    timeout: float
    min_days: int
    no_network_probe: bool
    ip: str | None


def _display_target(host: str, port: int) -> str:
    shown = f"[{host}]" if ":" in host else host
    return shown if port == 443 else f"{shown}:{port}"


def _safe_exception(exc: BaseException) -> tuple[str, str]:
    try:
        return describe_exception(exc)
    except Exception:  # pragma: no cover - describe_exception is intentionally simple
        message = str(exc).strip() or type(exc).__name__
        return message, "other"


def _parse_chain(
    chain_der: Sequence[bytes],
) -> tuple[list[CertificateInfo], tuple[int, str] | None]:
    certificates: list[CertificateInfo] = []
    for index, der in enumerate(chain_der):
        try:
            certificates.append(parse_certificate(der))
        except (CertificateError, TypeError, ValueError) as exc:
            return certificates, (index, str(exc))
    return certificates, None


def _certificate_findings(
    probe_chain: Sequence[bytes],
    host: str,
    min_days: int,
    now: datetime | None,
) -> list[Finding]:
    certificates, parse_failure = _parse_chain(probe_chain)
    findings: list[Finding] = []

    if certificates:
        findings.append(check_expiry(certificates[0], min_days=min_days, now=now))
        findings.append(check_hostname(certificates[0], host))

    if parse_failure is not None:
        index, message = parse_failure
        if certificates:
            detail = (
                f"TLS handshake succeeded, but certificate {index + 1} of "
                f"{len(probe_chain)} could not be decoded: {message}"
            )
        else:
            detail = (
                "TLS handshake succeeded, but the leaf certificate could not be "
                f"decoded: {message}"
            )
        findings.append(
            Finding(
                id="cert.chain",
                severity="error",
                title="Certificate chain could not be parsed",
                detail=detail,
                remediation=(
                    "Verify that the server is presenting valid X.509 "
                    "certificates, then rerun the check."
                ),
            )
        )
    else:
        findings.append(check_chain(certificates, now=now))
    return findings


def diagnose_host(
    host: str,
    options: _Options,
    *,
    prober: Probes = DEFAULT_PROBES,
    now: datetime | None = None,
) -> HostReport:
    """Run every available check for one host.

    Probe exceptions become ordinary findings rather than escaping the
    function, so a bad target can never turn into a traceback.
    """

    target = _display_target(host, options.port)

    try:
        tls_result = prober.tls(
            host=host,
            port=options.port,
            timeout=options.timeout,
            ip=options.ip,
        )
    except Exception as exc:
        detail, kind = _safe_exception(exc)
        return HostReport(
            target, (unreachable(host, options.port, detail, error_kind=kind),)
        )

    if tls_result.error or not tls_result.certificate_chain:
        detail = tls_result.error or "the server did not present a certificate"
        return HostReport(
            target,
            (
                unreachable(
                    host,
                    options.port,
                    detail,
                    error_kind=tls_result.error_kind,
                ),
            ),
        )

    findings = _certificate_findings(
        tls_result.certificate_chain,
        host,
        options.min_days,
        now,
    )
    findings.append(check_tls_version(tls_result.protocol_version))

    if not options.no_network_probe:
        try:
            legacy_results = prober.legacy(
                host=host,
                port=options.port,
                timeout=options.timeout,
                ip=options.ip,
            )
            legacy_observations = [
                (result.version, result.supported, result.detail)
                for result in legacy_results
            ]
        except Exception as exc:
            detail, _ = _safe_exception(exc)
            legacy_observations = [
                ("TLSv1.0", None, f"probe failed: {detail}"),
                ("TLSv1.1", None, f"probe failed: {detail}"),
            ]
        findings.append(check_tls_legacy(legacy_observations))

    findings.append(check_cipher(tls_result.cipher_name, tls_result.cipher_bits))

    if not options.no_network_probe:
        try:
            hsts_result = prober.hsts(
                host=host,
                port=options.port,
                timeout=options.timeout,
                ip=options.ip,
            )
            hsts_values = hsts_result.header_values("strict-transport-security")
        except Exception as exc:
            detail, kind = _safe_exception(exc)
            hsts_result = HttpProbeResult(error=detail, error_kind=kind)
            hsts_values = ()
        hsts_header = ", ".join(hsts_values) if hsts_values else None
        findings.extend(check_hsts(hsts_header, error=hsts_result.error))

        try:
            redirect_result = prober.redirect(
                host=host,
                timeout=options.timeout,
                ip=options.ip,
            )
        except Exception as exc:
            detail, kind = _safe_exception(exc)
            redirect_result = HttpProbeResult(error=detail, error_kind=kind)
        findings.append(
            check_redirect(
                redirect_result.status,
                redirect_result.header("location"),
                error=redirect_result.error,
                error_kind=redirect_result.error_kind,
            )
        )

    return HostReport(target, tuple(findings))


def _diagnose_guarded(
    host: str,
    options: _Options,
    prober: Probes,
    now: datetime | None,
) -> HostReport:
    try:
        return diagnose_host(host, options, prober=prober, now=now)
    except Exception as exc:  # pragma: no cover - last-resort safety net
        detail, kind = _safe_exception(exc)
        return HostReport(
            _display_target(host, options.port),
            (unreachable(host, options.port, f"unexpected error: {detail}", error_kind=kind),),
        )


def _deduplicate(hosts: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for host in hosts:
        key = host.casefold()
        if key not in seen:
            seen.add(key)
            unique.append(host)
    return unique


def main(
    argv: Sequence[str] | None = None,
    *,
    probes: Probes | None = None,
    now: datetime | None = None,
) -> int:
    """Run the CLI and return the documented exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)

    hosts = _deduplicate(args.hosts)
    if not hosts:
        parser.error("at least one hostname is required")
    if args.ip is not None and len(hosts) > 1:
        parser.error("--ip can only be used with a single host")

    options = _Options(
        port=args.port,
        timeout=args.timeout,
        min_days=args.min_days,
        no_network_probe=args.no_network_probe,
        ip=args.ip,
    )
    prober = probes if probes is not None else DEFAULT_PROBES

    if len(hosts) == 1:
        reports = [_diagnose_guarded(hosts[0], options, prober, now)]
    else:
        workers = min(MAX_WORKERS, len(hosts))
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="tls-doctor"
        ) as executor:
            reports = list(
                executor.map(
                    lambda host: _diagnose_guarded(host, options, prober, now),
                    hosts,
                )
            )

    output = render(reports, args.format)
    try:
        sys.stdout.write(output)
        sys.stdout.flush()
    except BrokenPipeError:
        return decide_exit(reports, args.fail_on)

    return decide_exit(reports, args.fail_on)
