"""Pure rule functions that turn observations into findings.

Nothing in this module opens sockets or reads the clock unless a caller asks for
it.  The network layer lives in :mod:`tls_doctor.probes`; keeping the rules pure
makes the interesting edge cases (wildcards, expiry boundaries, HSTS parsing)
easy to test offline.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence
from urllib.parse import urlsplit

from .certs import CertificateInfo, days_until, format_timestamp

__all__ = [
    "CipherAssessment",
    "Finding",
    "HSTS_MIN_MAX_AGE",
    "HstsPolicy",
    "assess_cipher",
    "certificate_matches_host",
    "check_chain",
    "check_cipher",
    "check_expiry",
    "check_hostname",
    "check_hsts",
    "check_redirect",
    "check_tls_legacy",
    "check_tls_version",
    "hostname_matches_san",
    "is_https_redirect",
    "parse_hsts",
    "unreachable",
    "version_rank",
]

SEVERITIES = ("ok", "info", "warning", "error")
SEVERITY_RANK = {"ok": 0, "info": 1, "warning": 2, "error": 3}

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
TLS_MIN_RANK = 0x0303  # TLS 1.2

_PROTOCOL_RANKS = {
    "SSLv2": 0x0200,
    "SSLv3": 0x0300,
    "TLSv1": 0x0301,
    "TLSv1.0": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
    "TLSv1.4": 0x0305,
}

LegacyObservation = tuple[str, bool | None, str | None]


@dataclass(frozen=True, slots=True)
class Finding:
    """One diagnostic result.

    ``severity`` is one of ``ok``, ``info``, ``warning`` or ``error``.  The
    first two do not affect the exit code; the latter two can, depending on
    ``--fail-on``.
    """

    id: str
    severity: str
    title: str
    detail: str
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid finding severity: {self.severity!r}")
        if not self.id:
            raise ValueError("finding id must not be empty")

    def to_dict(self) -> dict[str, str]:
        """Return the stable JSON representation of this finding."""

        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural or singular + 's'}"


def _clean_sentence(text: str) -> str:
    value = " ".join(str(text).split())
    if value and not value.endswith((".", "!", "?")):
        value += "."
    return value


def _normalize_ip(value: str) -> str | None:
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _normalize_dns(value: str) -> str:
    """Lowercase, strip a trailing root dot, and IDNA-encode labels."""

    candidate = value.strip().rstrip(".").lower()
    labels: list[str] = []
    for label in candidate.split("."):
        if any(ord(character) > 127 for character in label) and label != "*":
            try:
                label = label.encode("idna").decode("ascii").lower()
            except UnicodeError:
                return candidate
        labels.append(label)
    return ".".join(labels)


def hostname_matches_san(host: str, san: str) -> bool:
    """Return whether ``host`` is covered by the DNS SAN ``san``.

    Wildcards are supported only as the complete left-most label and match
    exactly one label.  ``*.example.com`` therefore matches
    ``a.example.com`` but not ``a.b.example.com`` or ``example.com``.  A
    wildcard with a single-label suffix (for example ``*.com``) is rejected;
    public-suffix rules are outside this module's scope.
    """

    hostname = _normalize_dns(host)
    pattern = _normalize_dns(san)
    if not hostname or not pattern or "*" in hostname:
        return False
    host_labels = hostname.split(".")
    if any(not label for label in host_labels):
        return False

    if not pattern.startswith("*."):
        pattern_labels = pattern.split(".")
        return (
            "*" not in pattern
            and not any(not label for label in pattern_labels)
            and hostname == pattern
        )

    suffix = pattern[2:]
    if not suffix or "*" in suffix:
        return False
    suffix_labels = suffix.split(".")
    if len(suffix_labels) < 2 or any(not label for label in suffix_labels):
        return False

    if len(host_labels) != len(suffix_labels) + 1:
        return False
    return host_labels[1:] == suffix_labels


def certificate_matches_host(
    certificate: CertificateInfo, host: str
) -> tuple[bool, str | None, str]:
    """Match ``host`` against the certificate SANs.

    Returns ``(matched, matched_value, explanation)``.  IP literals are matched
    only against iPAddress SANs, mirroring modern browser behaviour.  The
    legacy commonName fallback is intentionally not implemented.
    """

    address = _normalize_ip(host)
    if address is not None:
        for candidate in certificate.ip_addresses:
            if _normalize_ip(candidate) == address:
                return True, f"IP:{candidate}", "iPAddress SAN"
        return (
            False,
            None,
            "the host is an IP address and no matching iPAddress SAN is present",
        )

    for name in certificate.dns_names:
        if hostname_matches_san(host, name):
            return True, f"DNS:{name}", "DNS SAN"
    return False, None, "no DNS SAN matches the hostname"


def check_hostname(certificate: CertificateInfo, host: str) -> Finding:
    """Check a certificate against a hostname, including wildcard semantics."""

    matched, value, explanation = certificate_matches_host(certificate, host)
    if matched:
        return Finding(
            id="cert.hostname",
            severity="ok",
            title="Certificate matches hostname",
            detail=f"{host} matches the certificate's {value}.",
            remediation="",
        )

    address = _normalize_ip(host)
    if address is not None:
        remediation = (
            f"Reissue the certificate with IP:{address} in the subjectAltName "
            "extension."
        )
    else:
        remediation = (
            f"Reissue the certificate with a DNS:{host} subjectAltName (or a "
            "wildcard that covers exactly one label)."
        )
    return Finding(
        id="cert.hostname",
        severity="error",
        title="Certificate does not match hostname",
        detail=(
            f"{host} is not covered by the certificate's subjectAltName "
            f"({certificate.san_display}); {explanation}."
        ),
        remediation=remediation,
    )


def check_expiry(
    certificate: CertificateInfo,
    min_days: int = 14,
    now: datetime | None = None,
) -> Finding:
    """Check certificate expiry against ``min_days``.

    ``error`` when the certificate is already expired (fewer than zero whole
    days left), ``warning`` when it expires in fewer than ``min_days``, and
    ``ok`` otherwise.
    """

    remaining = days_until(certificate.not_after, now=now)
    expires = format_timestamp(certificate.not_after)

    if remaining < 0:
        return Finding(
            id="cert.expiry",
            severity="error",
            title="Certificate has expired",
            detail=(
                f"Expired {_plural(abs(remaining), 'day')} ago "
                f"(notAfter {expires})."
            ),
            remediation=(
                "Renew the certificate now and deploy it before running this "
                "check again."
            ),
        )

    if remaining < min_days:
        return Finding(
            id="cert.expiry",
            severity="warning",
            title="Certificate expires soon",
            detail=(
                f"{_plural(remaining, 'day')} left (notAfter {expires}); "
                f"the configured minimum is {_plural(min_days, 'day')}."
            ),
            remediation=(
                "Renew the certificate and deploy it before it expires; verify "
                "that automated rotation is working."
            ),
        )

    return Finding(
        id="cert.expiry",
        severity="ok",
        title="Certificate is valid",
        detail=(
            f"{_plural(remaining, 'day')} left (notAfter {expires}); "
            f"the configured minimum is {_plural(min_days, 'day')}."
        ),
        remediation="",
    )


def check_chain(
    chain: Sequence[CertificateInfo], now: datetime | None = None
) -> Finding:
    """Inspect the server-presented certificate chain.

    This is a structural check: chain length, self-signed leaf/root, and
    expired non-leaf certificates.  It does not validate signatures against a
    trust store.  A self-signed root included by the server is reported but is
    not itself treated as a failure.
    """

    reference = now
    if reference is None:
        reference = datetime.now(timezone.utc)
    elif reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    else:
        reference = reference.astimezone(timezone.utc)

    if not chain:
        return Finding(
            id="cert.chain",
            severity="error",
            title="Certificate chain unavailable",
            detail="The server did not present a certificate chain that could be parsed.",
            remediation=(
                "Confirm the service is configured with a certificate and chain, "
                "then rerun the check."
            ),
        )

    leaf = chain[0]
    issues: list[str] = []
    notes: list[str] = []
    remediation: list[str] = []
    severity = "ok"

    if leaf.is_self_signed:
        issues.append("the leaf certificate is self-signed (subject equals issuer)")
        severity = "warning"
        remediation.append(
            "Use a certificate issued by a publicly trusted CA, or install the "
            "internal CA in the clients that must trust this service."
        )

    if len(chain) == 1 and not leaf.is_self_signed:
        issues.append(
            "the server presented only the leaf certificate, so intermediates may "
            "be missing"
        )
        severity = "warning"
        remediation.append(
            "Configure the server to send the full intermediate chain (leaf first, "
            "root omitted)."
        )

    expired: list[str] = []
    for position, certificate in enumerate(chain[1:], start=2):
        if certificate.not_after <= reference:
            expired.append(
                f"certificate {position} expired at "
                f"{format_timestamp(certificate.not_after)}"
            )
        if certificate.is_self_signed:
            notes.append(f"certificate {position} is a self-signed root")

    if expired:
        issues.extend(expired)
        severity = "error"
        remediation.append(
            "Replace the expired intermediate certificate and deploy the corrected "
            "chain."
        )

    details = [f"The server presented {_plural(len(chain), 'certificate')}."]
    if issues:
        details.append("Issues: " + "; ".join(issues) + ".")
    if notes:
        details.append("Notes: " + "; ".join(notes) + ".")
    if severity == "ok":
        details.append("No structural problems were detected.")

    if severity == "error":
        title = "Certificate chain contains an expired certificate"
    elif severity == "warning":
        title = "Certificate chain has issues"
    else:
        title = "Certificate chain is structurally valid"

    return Finding(
        id="cert.chain",
        severity=severity,
        title=title,
        detail=" ".join(details),
        remediation=" ".join(remediation),
    )


def version_rank(version: str) -> int | None:
    """Map a negotiated TLS version string to a comparable rank."""

    return _PROTOCOL_RANKS.get(version.strip())


def check_tls_version(version: str) -> Finding:
    """Require TLS 1.2 or newer."""

    rank = version_rank(version)
    if rank is None:
        return Finding(
            id="tls.version",
            severity="warning",
            title="Unknown TLS version",
            detail=(
                f"The server negotiated an unrecognized protocol version ({version!r}); "
                "TLS 1.2 or newer is required."
            ),
            remediation="Verify the negotiated protocol with another TLS client.",
        )
    if rank < TLS_MIN_RANK:
        return Finding(
            id="tls.version",
            severity="error",
            title="Obsolete TLS version negotiated",
            detail=(
                f"The server negotiated {version}; TLS 1.2 or newer is required."
            ),
            remediation=(
                "Disable TLS 1.0 and TLS 1.1 in the server configuration and enable "
                "TLS 1.2 and TLS 1.3."
            ),
        )
    return Finding(
        id="tls.version",
        severity="ok",
        title="TLS version is acceptable",
        detail=f"The server negotiated {version}; the minimum is TLS 1.2.",
        remediation="",
    )


def check_tls_legacy(results: Sequence[LegacyObservation]) -> Finding:
    """Check whether TLS 1.0 or TLS 1.1 is still accepted.

    ``results`` contains ``(version, supported, error)`` triples.  ``supported``
    is ``None`` when the local client could not complete the test, which is
    reported as informational rather than as a false positive.
    """

    if not results:
        return Finding(
            id="tls.legacy",
            severity="info",
            title="Legacy TLS support was not probed",
            detail="No legacy-protocol probe results were supplied.",
            remediation="",
        )

    accepted = [version for version, supported, _ in results if supported is True]
    refused = [version for version, supported, _ in results if supported is False]
    unknown = [
        (version, error)
        for version, supported, error in results
        if supported is None
    ]

    pieces: list[str] = []
    if refused:
        pieces.append("Refused: " + ", ".join(refused) + ".")
    if unknown:
        unknown_text = ", ".join(version for version, _ in unknown)
        pieces.append("Could not test: " + unknown_text + ".")
        first_reason = next((error for _, error in unknown if error), None)
        if first_reason:
            pieces.append(f"First client error: {first_reason}.")

    if accepted:
        detail = "The server still accepts " + ", ".join(accepted) + "."
        if pieces:
            detail += " " + " ".join(pieces)
        return Finding(
            id="tls.legacy",
            severity="warning",
            title="Legacy TLS protocols are accepted",
            detail=detail,
            remediation=(
                "Disable TLS 1.0 and TLS 1.1; keep only TLS 1.2 and TLS 1.3 with "
                "modern cipher suites."
            ),
        )

    if unknown and not refused:
        return Finding(
            id="tls.legacy",
            severity="info",
            title="Could not test legacy TLS",
            detail=" ".join(pieces),
            remediation=(
                "Check legacy protocol support with a client built against an "
                "OpenSSL configuration that allows TLS 1.0/1.1."
            ),
        )

    if unknown:
        return Finding(
            id="tls.legacy",
            severity="info",
            title="Legacy TLS probe was incomplete",
            detail=" ".join(pieces),
            remediation=(
                "Verify the untested protocol version manually with a compatible "
                "legacy client."
            ),
        )

    return Finding(
        id="tls.legacy",
        severity="ok",
        title="Legacy TLS protocols are disabled",
        detail=" ".join(pieces),
        remediation="",
    )


@dataclass(frozen=True, slots=True)
class CipherAssessment:
    """The result of checking a negotiated cipher suite."""

    weak: bool
    reasons: tuple[str, ...]


def assess_cipher(name: str, bits: int) -> CipherAssessment:
    """Classify a cipher name and effective key strength.

    Flags NULL/EXPORT/RC4/DES/3DES suites and anything below 128 bits.
    """

    upper = name.upper()
    reasons: list[str] = []

    if "NULL" in upper:
        reasons.append("NULL encryption")
    if re.search(r"(?:^|[_-])(?:EXP|EXPORT)(?:[_-]|$)", upper):
        reasons.append("export-grade cipher")
    if "RC4" in upper:
        reasons.append("RC4 stream cipher")
    if "3DES" in upper or "DES-CBC3" in upper:
        reasons.append("3DES")
    elif re.search(r"(?:^|[_-])DES(?:40)?(?:[_-]|$)", upper):
        reasons.append("single DES")
    if bits < 128:
        reasons.append(f"effective key strength is only {bits} bits")

    return CipherAssessment(weak=bool(reasons), reasons=tuple(reasons))


def check_cipher(name: str, bits: int) -> Finding:
    """Check the negotiated cipher suite for known-weak algorithms."""

    assessment = assess_cipher(name, bits)
    if assessment.weak:
        return Finding(
            id="tls.cipher",
            severity="error",
            title="Weak cipher suite negotiated",
            detail=(
                f"The server negotiated {name or 'an unknown cipher'} "
                f"({bits}-bit): " + ", ".join(assessment.reasons) + "."
            ),
            remediation=(
                "Disable NULL, EXPORT, RC4, DES and 3DES suites, and require "
                "AEAD suites with at least 128-bit keys (AES-GCM or "
                "ChaCha20-Poly1305)."
            ),
        )
    return Finding(
        id="tls.cipher",
        severity="ok",
        title="Cipher suite is acceptable",
        detail=(
            f"The server negotiated {name} with "
            f"{bits}-bit symmetric encryption."
        ),
        remediation="",
    )


@dataclass(frozen=True, slots=True)
class HstsPolicy:
    """Parsed Strict-Transport-Security header directives."""

    present: bool
    raw: str
    max_age: int | None
    include_subdomains: bool
    preload: bool
    directives: tuple[tuple[str, str | None], ...] = ()


def _split_hsts_directives(value: str) -> list[str]:
    """Split on semicolons/commas that are outside quoted strings."""

    parts: list[str] = []
    buffer: list[str] = []
    quote: str | None = None
    escaped = False
    for character in value:
        if escaped:
            buffer.append(character)
            escaped = False
            continue
        if quote is not None:
            buffer.append(character)
            if character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
            buffer.append(character)
        elif character in ";,":
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(character)
    parts.append("".join(buffer))
    return parts


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_hsts(value: str | None) -> HstsPolicy:
    """Parse an STS header value.

    Handles quoted values, multiple directives, absent or invalid ``max-age``,
    and repeated directives (the first occurrence wins, matching the RFC 6797
    single-header processing model).
    """

    if value is None or not value.strip():
        return HstsPolicy(
            present=False,
            raw="",
            max_age=None,
            include_subdomains=False,
            preload=False,
        )

    raw = value.strip()
    directives: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for part in _split_hsts_directives(raw):
        if not part.strip():
            continue
        name, separator, directive_value = part.partition("=")
        name = name.strip().lower()
        if not name or name in seen:
            continue
        parsed_value = (
            _unquote(directive_value.strip()) if separator else None
        )
        seen.add(name)
        directives.append((name, parsed_value))

    values = dict(directives)
    raw_max_age = values.get("max-age")
    max_age: int | None = None
    if raw_max_age is not None and re.fullmatch(r"\d+", raw_max_age):
        max_age = int(raw_max_age)

    return HstsPolicy(
        present=True,
        raw=raw,
        max_age=max_age,
        include_subdomains="includesubdomains" in values,
        preload="preload" in values,
        directives=tuple(directives),
    )


def check_hsts(
    header_value: str | None, *, error: str | None = None
) -> list[Finding]:
    """Check the HSTS header.

    Returns a warning/ok finding for the policy itself and, when present, an
    informational finding for ``includeSubDomains``/``preload``.
    """

    if error:
        return [
            Finding(
                id="http.hsts",
                severity="info",
                title="HSTS could not be checked",
                detail=_clean_sentence(
                    f"The HTTPS header probe failed: {error}"
                ),
                remediation=(
                    "Confirm the HTTPS endpoint answers HEAD requests, then rerun "
                    "the check."
                ),
            )
        ]

    policy = parse_hsts(header_value)
    if not policy.present:
        primary = Finding(
            id="http.hsts",
            severity="warning",
            title="HSTS header is missing",
            detail="The HTTPS response did not include a Strict-Transport-Security header.",
            remediation=(
                "Add 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains' to all HTTPS responses."
            ),
        )
    elif policy.max_age is None:
        primary = Finding(
            id="http.hsts",
            severity="warning",
            title="HSTS max-age is missing or invalid",
            detail=(
                "The Strict-Transport-Security header is present but does not "
                "contain a valid max-age directive."
            ),
            remediation=(
                "Use a positive max-age of at least 15552000 seconds (180 days), "
                "for example: max-age=31536000; includeSubDomains."
            ),
        )
    elif policy.max_age < HSTS_MIN_MAX_AGE:
        days = policy.max_age // 86_400
        primary = Finding(
            id="http.hsts",
            severity="warning",
            title="HSTS max-age is too short",
            detail=(
                f"max-age is {policy.max_age} seconds (~{days} days), below the "
                "15552000-second (180-day) minimum."
            ),
            remediation=(
                "Raise max-age to at least 15552000 seconds; 31536000 seconds "
                "(one year) is a common choice."
            ),
        )
    else:
        days = policy.max_age // 86_400
        primary = Finding(
            id="http.hsts",
            severity="ok",
            title="HSTS policy is present",
            detail=(
                f"max-age is {policy.max_age} seconds (~{days} days), meeting the "
                "180-day minimum."
            ),
            remediation="",
        )

    findings = [primary]
    scope_flags: list[str] = []
    if policy.include_subdomains:
        scope_flags.append("includeSubDomains")
    if policy.preload:
        scope_flags.append("preload")
    if policy.present and scope_flags:
        note = ""
        if policy.preload:
            note = (
                " The preload directive is reported, not verified against "
                "browser preload lists."
            )
        findings.append(
            Finding(
                id="http.hsts.scope",
                severity="info",
                title="HSTS scope directives are present",
                detail=(
                    "The header sets " + " and ".join(scope_flags) + "." + note
                ),
                remediation="",
            )
        )
    return findings


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def is_https_redirect(status: int | None, location: str | None) -> bool:
    """Return whether a status/location pair redirects to an absolute HTTPS URL."""

    if status not in _REDIRECT_STATUSES or not location:
        return False
    target = location.strip()
    if any(character.isspace() for character in target):
        return False
    try:
        parts = urlsplit(target)
    except ValueError:
        return False
    return parts.scheme.lower() == "https" and bool(parts.netloc)


def check_redirect(
    status: int | None,
    location: str | None,
    *,
    error: str | None = None,
    error_kind: str | None = None,
) -> Finding:
    """Check that plain HTTP on port 80 redirects to HTTPS.

    A refused connection is treated as acceptable: the host does not expose a
    plaintext HTTP endpoint on port 80.  Other probe failures are warnings
    because the redirect could not be verified.
    """

    if error:
        if error_kind == "refused":
            return Finding(
                id="http.redirect",
                severity="ok",
                title="No plain HTTP listener",
                detail=(
                    "Connecting to port 80 was refused; there is no plaintext HTTP "
                    "endpoint to redirect."
                ),
                remediation="",
            )
        return Finding(
            id="http.redirect",
            severity="warning",
            title="HTTP redirect could not be verified",
            detail=_clean_sentence(
                f"The plain-HTTP probe to port 80 failed: {error}"
            ),
            remediation=(
                "Verify that port 80 redirects to HTTPS, or rerun with "
                "--no-network-probe to skip supplemental network checks."
            ),
        )

    if is_https_redirect(status, location):
        target = (location or "").strip()
        return Finding(
            id="http.redirect",
            severity="ok",
            title="HTTP redirects to HTTPS",
            detail=f"Port 80 returns HTTP {status} with Location {target}.",
            remediation="",
        )

    if status in _REDIRECT_STATUSES and location:
        return Finding(
            id="http.redirect",
            severity="warning",
            title="HTTP redirect does not target HTTPS",
            detail=(
                f"Port 80 returns HTTP {status} with Location {location!r}, which "
                "is not an absolute HTTPS URL."
            ),
            remediation=(
                "Redirect plain HTTP to the https:// URL with a 301 or 308 status."
            ),
        )

    status_text = f"HTTP {status}" if status is not None else "no HTTP status"
    return Finding(
        id="http.redirect",
        severity="warning",
        title="HTTP does not redirect to HTTPS",
        detail=(
            f"Port 80 returned {status_text} without an HTTPS redirect."
        ),
        remediation=(
            "Serve a 301 or 308 redirect from port 80 to the equivalent https:// "
            "URL, then enable HSTS."
        ),
    )


def unreachable(
    host: str,
    port: int,
    detail: str,
    error_kind: str | None = None,
) -> Finding:
    """Create the clean error finding used for connectivity/handshake failures."""

    title = "Host is unreachable"
    if error_kind in {"tls", "certificate"}:
        title = "TLS handshake failed"
    elif error_kind == "timeout":
        title = "TLS connection timed out"
    elif error_kind == "dns":
        title = "Host name could not be resolved"

    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return Finding(
        id="unreachable",
        severity="error",
        title=title,
        detail=_clean_sentence(
            f"Could not establish a TLS session with {target}: {detail}"
        ),
        remediation=(
            f"Check DNS, the network path and firewall rules, and confirm the "
            f"service listens on port {port}. Increase --timeout for slow hosts."
        ),
    )
