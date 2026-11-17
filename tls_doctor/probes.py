"""Network probes.

Every probe returns a frozen observation instead of raising for ordinary
network failures.  That keeps the CLI free of tracebacks and makes each probe
straightforward to replace in tests through :class:`Probes`.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from . import __version__

__all__ = [
    "DEFAULT_PROBES",
    "HttpProbeResult",
    "Probes",
    "ProtocolProbeResult",
    "TlsProbeResult",
    "describe_exception",
    "probe_http_hsts",
    "probe_http_redirect",
    "probe_legacy",
    "probe_tls",
]

_USER_AGENT: Final = f"tls-doctor/{__version__}"
_REQUEST_HEADERS: Final = {
    "User-Agent": _USER_AGENT,
    "Accept": "*/*",
    "Connection": "close",
}


@dataclass(frozen=True, slots=True)
class TlsProbeResult:
    """The outcome of the primary TLS handshake."""

    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    certificate_chain: tuple[bytes, ...] = ()
    error: str | None = None
    error_kind: str | None = None


@dataclass(frozen=True, slots=True)
class ProtocolProbeResult:
    """Whether a specific TLS protocol version was accepted.

    ``supported`` is ``True`` or ``False`` when the server answered the
    handshake attempt, and ``None`` when the local client could not complete the
    test (for example because OpenSSL disables the protocol entirely).
    """

    version: str
    supported: bool | None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    """A minimal HTTP observation: status and response headers."""

    status: int | None = None
    headers: tuple[tuple[str, str], ...] = ()
    error: str | None = None
    error_kind: str | None = None

    def header(self, name: str) -> str | None:
        """Return the first header value matching ``name`` (case-insensitive)."""

        values = self.header_values(name)
        return values[0] if values else None

    def header_values(self, name: str) -> tuple[str, ...]:
        """Return every value for ``name`` while preserving response order."""

        target = name.lower()
        return tuple(
            value
            for header_name, value in self.headers
            if header_name.lower() == target
        )


def _classify_exception(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, http.client.HTTPException):
        return "http"
    if isinstance(exc, OSError):
        return "network"
    return "other"


def describe_exception(exc: BaseException) -> tuple[str, str]:
    """Return a short, traceback-free description and kind for an exception."""

    kind = _classify_exception(exc)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        text = "timed out"
    elif isinstance(exc, ConnectionRefusedError):
        text = "connection refused"
    elif isinstance(exc, socket.gaierror):
        text = f"DNS resolution failed ({exc})"
    elif isinstance(exc, ssl.SSLCertVerificationError):
        text = f"certificate verification failed ({exc.verify_message or exc})"
    elif isinstance(exc, ssl.SSLError):
        reason = getattr(exc, "reason", None)
        text = f"TLS handshake failed ({reason or exc})"
    elif isinstance(exc, http.client.HTTPException):
        text = f"HTTP protocol error ({exc})"
    else:
        message = str(exc).strip()
        text = message if message else type(exc).__name__
    return text, kind


def _strip_brackets(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        return candidate[1:-1]
    return candidate


def _client_cannot_offer_protocol(exc: ssl.SSLError) -> bool:
    """Distinguish a local OpenSSL limitation from a server rejection."""

    reason = str(getattr(exc, "reason", "") or "").upper()
    message = str(exc).upper()
    markers = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE")
    return any(marker in reason or marker in message for marker in markers)


def _open_tls_socket(
    host: str,
    port: int,
    timeout: float,
    ip: str | None,
    context: ssl.SSLContext,
) -> ssl.SSLSocket:
    connect_host = _strip_brackets(ip or _wire_host(host))
    raw = socket.create_connection((connect_host, port), timeout=timeout)
    try:
        raw.settimeout(timeout)
        return context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # A diagnostic client should be able to observe old/weak configurations
    # rather than refusing to connect to them.
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        try:
            context.set_ciphers("DEFAULT")
        except ssl.SSLError:
            pass
    try:
        # Allow the probe to observe servers that still negotiate old
        # protocols; the negotiated version is reported separately.
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, ssl.SSLError):
        pass
    legacy_connect = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    if legacy_connect:
        context.options |= legacy_connect
    return context


def _https_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _certificate_to_der(certificate: object) -> bytes | None:
    if isinstance(certificate, (bytes, bytearray)):
        return bytes(certificate) or None

    public_bytes = getattr(certificate, "public_bytes", None)
    if not callable(public_bytes):
        return None

    encoding_der = getattr(ssl._ssl, "ENCODING_DER", 1)
    material = None
    for arguments in ((encoding_der,), ()):
        try:
            material = public_bytes(*arguments)
        except TypeError:
            continue
        except Exception:  # pragma: no cover - defensive against _ssl changes
            return None
        break

    if not isinstance(material, (bytes, bytearray)):
        return None
    data = bytes(material)
    if data.startswith(b"-----BEGIN"):
        try:
            data = ssl.PEM_cert_to_DER_cert(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return None
    return data or None


def _presented_chain(sock: ssl.SSLSocket, leaf: bytes | None) -> tuple[bytes, ...]:
    chain: list[bytes] = []

    getter = getattr(sock, "get_unverified_chain", None)
    if not callable(getter):
        ssl_object = getattr(sock, "_sslobj", None)
        getter = getattr(ssl_object, "get_unverified_chain", None)

    if callable(getter):
        try:
            certificates = getter()
        except (ssl.SSLError, ValueError, NotImplementedError):
            certificates = ()
        for certificate in certificates:
            der = _certificate_to_der(certificate)
            if der:
                chain.append(der)

    if leaf:
        if not any(existing == leaf for existing in chain):
            chain.insert(0, leaf)
    return tuple(chain)


def probe_tls(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    ip: str | None = None,
) -> TlsProbeResult:
    """Perform the primary TLS handshake and collect version, cipher and chain.

    Certificate verification is intentionally disabled so that expired,
    self-signed or misnamed certificates can still be diagnosed and reported as
    findings instead of aborting the handshake.
    """

    try:
        context = _client_context()
        with _open_tls_socket(host, port, timeout, ip, context) as tls_socket:
            version = tls_socket.version() or ""
            cipher = tls_socket.cipher()
            cipher_name = cipher[0] if cipher else ""
            cipher_bits = int(cipher[2]) if cipher else 0
            leaf = tls_socket.getpeercert(binary_form=True)
            chain = _presented_chain(tls_socket, leaf)
    except (ssl.SSLError, ssl.CertificateError, OSError, ValueError) as exc:
        detail, kind = describe_exception(exc)
        return TlsProbeResult(error=detail, error_kind=kind)

    if not chain:
        return TlsProbeResult(
            error="TLS handshake succeeded but no certificate was presented",
            error_kind="tls",
        )

    return TlsProbeResult(
        protocol_version=version,
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        certificate_chain=chain,
    )


def _legacy_context(version: ssl.TLSVersion) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # Python 3.14 deprecates the TLS 1.0/1.1 enum members themselves.  They
        # are exactly what this opt-in legacy probe needs to request.
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = version
        context.maximum_version = version
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    legacy_connect = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    if legacy_connect:
        context.options |= legacy_connect
    return context


def probe_legacy(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    ip: str | None = None,
) -> tuple[ProtocolProbeResult, ...]:
    """Attempt a handshake with TLS 1.0 and TLS 1.1 separately."""

    outcomes: list[ProtocolProbeResult] = []
    protocols = (
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    )
    for label, version in protocols:
        try:
            context = _legacy_context(version)
        except (ssl.SSLError, ValueError) as exc:
            detail, _ = describe_exception(exc)
            outcomes.append(
                ProtocolProbeResult(
                    version=label,
                    supported=None,
                    detail=f"client cannot offer {label}: {detail}",
                )
            )
            continue

        try:
            with _open_tls_socket(host, port, timeout, ip, context):
                pass
        except ssl.SSLError as exc:
            detail, _ = describe_exception(exc)
            if _client_cannot_offer_protocol(exc):
                outcomes.append(
                    ProtocolProbeResult(
                        version=label,
                        supported=None,
                        detail=f"local OpenSSL cannot offer {label}: {detail}",
                    )
                )
            else:
                outcomes.append(
                    ProtocolProbeResult(
                        version=label, supported=False, detail=detail
                    )
                )
        except (OSError, ValueError) as exc:
            detail, _ = describe_exception(exc)
            outcomes.append(
                ProtocolProbeResult(version=label, supported=None, detail=detail)
            )
        else:
            outcomes.append(
                ProtocolProbeResult(version=label, supported=True, detail=None)
            )

    return tuple(outcomes)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to a fixed address while keeping SNI/Host.

    ``http.client`` has no public way to override the address it dials, which is
    needed for ``--ip``.  This subclass performs the same steps as the stdlib
    implementation but uses an explicit connect address.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        connect_host: str,
        context: ssl.SSLContext,
        timeout: float,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._connect_host = _strip_brackets(connect_host)
        self._tls_context = context

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_host, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._tls_context.wrap_socket(
            self.sock, server_hostname=self.host
        )


def _http_failure(exc: BaseException) -> HttpProbeResult:
    detail, kind = describe_exception(exc)
    return HttpProbeResult(error=detail, error_kind=kind)


def _wire_host(host: str) -> str:
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def probe_http_hsts(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    ip: str | None = None,
) -> HttpProbeResult:
    """Fetch response headers over HTTPS with a HEAD request."""

    connection = _PinnedHTTPSConnection(
        _wire_host(host),
        port,
        connect_host=_wire_host(ip or host),
        context=_https_context(),
        timeout=timeout,
    )
    try:
        connection.request("HEAD", "/", headers=_REQUEST_HEADERS)
        response = connection.getresponse()
        return HttpProbeResult(
            status=response.status,
            headers=tuple((name, value) for name, value in response.getheaders()),
        )
    except (ssl.SSLError, OSError, http.client.HTTPException, ValueError) as exc:
        return _http_failure(exc)
    finally:
        try:
            connection.close()
        except OSError:
            pass


def probe_http_redirect(
    host: str,
    timeout: float = 5.0,
    ip: str | None = None,
) -> HttpProbeResult:
    """Fetch the port-80 response without following redirects."""

    connect_host = _strip_brackets(ip or _wire_host(host))
    connection = http.client.HTTPConnection(connect_host, 80, timeout=timeout)
    headers = dict(_REQUEST_HEADERS)
    headers["Host"] = _wire_host(host)
    try:
        connection.request("HEAD", "/", headers=headers)
        response = connection.getresponse()
        return HttpProbeResult(
            status=response.status,
            headers=tuple((name, value) for name, value in response.getheaders()),
        )
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return _http_failure(exc)
    finally:
        try:
            connection.close()
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class Probes:
    """Injectable set of probe callables used by the CLI."""

    tls: Callable[..., TlsProbeResult] = probe_tls
    legacy: Callable[..., tuple[ProtocolProbeResult, ...]] = probe_legacy
    hsts: Callable[..., HttpProbeResult] = probe_http_hsts
    redirect: Callable[..., HttpProbeResult] = probe_http_redirect


DEFAULT_PROBES = Probes()
