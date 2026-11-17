"""Small, dependency-free X.509 helpers used by tls-doctor.

The standard library can convert PEM to DER and can decode a certificate when
it is written to a file, but it does not expose a public in-memory parser.
Writing certificates to disk just to inspect them is awkward and unnecessary,
so this module implements the narrow slice of ASN.1/DER needed for the checks:
the validity period, subject, issuer, serial number and subjectAltName
extension.  It is not a general-purpose X.509 library.
"""

from __future__ import annotations

import ipaddress
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final

__all__ = [
    "CertificateError",
    "CertificateInfo",
    "days_until",
    "format_timestamp",
    "parse_certificate",
    "parse_certificate_pem",
    "pem_to_der",
]

# ASN.1 tags used below.
_SEQUENCE: Final = 0x30
_SET: Final = 0x31
_INTEGER: Final = 0x02
_BOOLEAN: Final = 0x01
_OID: Final = 0x06
_OCTET_STRING: Final = 0x04
_UTC_TIME: Final = 0x17
_GENERALIZED_TIME: Final = 0x18
_VERSION_WRAPPER: Final = 0xA0
_EXTENSIONS_WRAPPER: Final = 0xA3

_SUBJECT_ALT_NAME_OID: Final = "2.5.29.17"

_OID_LABELS: Final = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
}


class CertificateError(ValueError):
    """Raised when a certificate cannot be decoded."""


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """The certificate fields tls-doctor reasons about."""

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial: int
    dns_names: tuple[str, ...] = ()
    ip_addresses: tuple[str, ...] = ()

    @property
    def is_self_signed(self) -> bool:
        """True when the subject and issuer distinguished names are equal."""

        return bool(self.subject) and self.subject.casefold() == self.issuer.casefold()

    @property
    def san_display(self) -> str:
        """Human-readable summary of the certificate's subjectAltName values."""

        entries = [f"DNS:{name}" for name in self.dns_names]
        entries.extend(f"IP:{address}" for address in self.ip_addresses)
        return ", ".join(entries) if entries else "none"


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value triple.

    Returns ``(tag, value, next_offset)``.  Only definite lengths are accepted,
    which is what DER requires and what real certificates use.
    """

    if offset < 0 or offset >= len(data):
        raise CertificateError("unexpected end of DER data while reading a tag")

    tag = data[offset]
    offset += 1

    if tag & 0x1F == 0x1F:
        raise CertificateError("high-tag-number DER encoding is not supported")

    if offset >= len(data):
        raise CertificateError("unexpected end of DER data while reading a length")

    first_length = data[offset]
    offset += 1
    if first_length < 0x80:
        length = first_length
    else:
        length_octets = first_length & 0x7F
        if length_octets == 0:
            raise CertificateError("indefinite DER lengths are not supported")
        if length_octets > 4:
            raise CertificateError("DER length is unreasonably large")
        if offset + length_octets > len(data):
            raise CertificateError("truncated DER length")
        length = int.from_bytes(data[offset : offset + length_octets], "big")
        offset += length_octets

    end = offset + length
    if end > len(data):
        raise CertificateError("truncated DER value")
    return tag, data[offset:end], end


def _expect(
    data: bytes, offset: int, expected_tag: int, description: str
) -> tuple[bytes, int]:
    tag, value, next_offset = _read_tlv(data, offset)
    if tag != expected_tag:
        raise CertificateError(
            f"expected {description} (tag 0x{expected_tag:02x}), got tag 0x{tag:02x}"
        )
    return value, next_offset


def _decode_oid(raw: bytes) -> str:
    if not raw:
        raise CertificateError("empty object identifier")

    first = raw[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]

    current = 0
    pending = False
    for octet in raw[1:]:
        pending = True
        current = (current << 7) | (octet & 0x7F)
        if not octet & 0x80:
            parts.append(current)
            current = 0
            pending = False
    if pending:
        raise CertificateError("truncated object identifier")

    return ".".join(str(part) for part in parts)


def _decode_directory_string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        encoding = "utf-16-be"
    elif tag == 0x1C:  # UniversalString
        encoding = "utf-32-be"
    elif tag == 0x14:  # TeletexString
        encoding = "latin-1"
    else:
        # UTF8String, PrintableString, IA5String, NumericString, ...
        encoding = "utf-8"
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError:
        return raw.decode(encoding, errors="replace")


def _parse_name(body: bytes) -> tuple[tuple[str, str], ...]:
    """Decode an X.501 Name into a flat sequence of ``(oid, value)`` pairs."""

    attributes: list[tuple[str, str]] = []
    offset = 0
    while offset < len(body):
        rdn, offset = _expect(body, offset, _SET, "relative distinguished name")
        inner = 0
        while inner < len(rdn):
            attribute, inner = _expect(rdn, inner, _SEQUENCE, "attribute")
            oid_raw, attribute_offset = _expect(
                attribute, 0, _OID, "attribute type object identifier"
            )
            value_tag, value_raw, _ = _read_tlv(attribute, attribute_offset)
            attributes.append(
                (_decode_oid(oid_raw), _decode_directory_string(value_tag, value_raw))
            )
    return tuple(attributes)


def _format_name(attributes: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(
        f"{_OID_LABELS.get(oid, oid)}={value}" for oid, value in attributes
    )


def _parse_asn1_time(tag: int, raw: bytes) -> datetime:
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise CertificateError("certificate time is not ASCII") from exc

    if tag == _UTC_TIME:
        match = re.fullmatch(
            r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})", text
        )
        if match is None:
            raise CertificateError(f"invalid UTCTime value: {text!r}")
        year = int(match.group(1))
        year += 2000 if year < 50 else 1900
        month, day, hour, minute = (int(match.group(i)) for i in range(2, 6))
        second = int(match.group(6) or 0)
        zone = match.group(7)
    elif tag == _GENERALIZED_TIME:
        match = re.fullmatch(
            r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?"
            r"(Z|[+-]\d{4})",
            text,
        )
        if match is None:
            raise CertificateError(f"invalid GeneralizedTime value: {text!r}")
        year, month, day, hour, minute, second = (
            int(match.group(i)) for i in range(1, 7)
        )
        zone = match.group(7)
    else:
        raise CertificateError(f"unsupported certificate time tag: 0x{tag:02x}")

    if zone == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        offset_hours = int(zone[1:3])
        offset_minutes = int(zone[3:5])
        if offset_minutes >= 60:
            raise CertificateError(f"invalid UTC offset: {zone!r}")
        tzinfo = timezone(sign * timedelta(hours=offset_hours, minutes=offset_minutes))

    try:
        value = datetime(
            year, month, day, hour, minute, second, tzinfo=tzinfo
        )
    except ValueError as exc:
        raise CertificateError(f"invalid certificate time: {text!r}") from exc
    return value.astimezone(timezone.utc)


def _parse_validity(body: bytes) -> tuple[datetime, datetime]:
    first_tag, first_value, offset = _read_tlv(body, 0)
    second_tag, second_value, end = _read_tlv(body, offset)
    if end != len(body):
        raise CertificateError("trailing data in certificate validity")
    return (
        _parse_asn1_time(first_tag, first_value),
        _parse_asn1_time(second_tag, second_value),
    )


def _parse_san_extension(value: bytes) -> tuple[list[str], list[str]]:
    seq, offset = _expect(value, 0, _SEQUENCE, "subjectAltName sequence")
    if offset != len(value):
        raise CertificateError("trailing data in subjectAltName extension")

    dns_names: list[str] = []
    ip_addresses: list[str] = []
    inner = 0
    while inner < len(seq):
        tag, raw, inner = _read_tlv(seq, inner)
        if tag == 0x82:  # dNSName, context-specific [2], IA5String
            dns_names.append(raw.decode("ascii", errors="replace"))
        elif tag == 0x87:  # iPAddress, context-specific [7]
            if len(raw) not in (4, 16):
                continue
            try:
                ip_addresses.append(str(ipaddress.ip_address(raw)))
            except ValueError:
                continue
    return dns_names, ip_addresses


def _parse_extensions(wrapper: bytes) -> tuple[list[str], list[str]]:
    extensions, offset = _expect(
        wrapper, 0, _SEQUENCE, "extensions sequence"
    )
    if offset != len(wrapper):
        raise CertificateError("trailing data in extensions wrapper")

    dns_names: list[str] = []
    ip_addresses: list[str] = []
    inner = 0
    while inner < len(extensions):
        extension, inner = _expect(
            extensions, inner, _SEQUENCE, "certificate extension"
        )
        offset_in_extension = 0
        oid_raw, offset_in_extension = _expect(
            extension, offset_in_extension, _OID, "extension object identifier"
        )
        oid = _decode_oid(oid_raw)

        tag, value_or_flag, offset_in_extension = _read_tlv(
            extension, offset_in_extension
        )
        if tag == _BOOLEAN:
            # Critical flag; not needed for parsing the value.
            tag, value, offset_in_extension = _read_tlv(
                extension, offset_in_extension
            )
        else:
            value = value_or_flag
        if tag != _OCTET_STRING:
            raise CertificateError(f"extension {oid} does not use an OCTET STRING")
        if offset_in_extension != len(extension):
            raise CertificateError(f"trailing data in certificate extension {oid}")

        if oid == _SUBJECT_ALT_NAME_OID:
            names, addresses = _parse_san_extension(value)
            dns_names.extend(names)
            ip_addresses.extend(addresses)

    return dns_names, ip_addresses


def parse_certificate(der: bytes) -> CertificateInfo:
    """Parse a DER-encoded X.509 certificate.

    Raises :class:`CertificateError` if the input is not a certificate this
    parser understands.
    """

    if not isinstance(der, (bytes, bytearray)):
        raise TypeError("der must be bytes")
    data = bytes(der)
    if not data:
        raise CertificateError("empty certificate data")

    certificate, offset = _expect(data, 0, _SEQUENCE, "certificate")
    if offset != len(data):
        raise CertificateError("trailing data after certificate")

    tbs, offset = _expect(certificate, 0, _SEQUENCE, "TBSCertificate")
    # The signature algorithm and signature value are not needed here.  We only
    # require them to be present and structurally sequenced.
    _expect(certificate, offset, _SEQUENCE, "signature algorithm")

    cursor = 0
    tag, version_value, cursor = _read_tlv(tbs, cursor)
    if tag == _VERSION_WRAPPER:
        _expect(version_value, 0, _INTEGER, "certificate version")
        tag, serial_value, cursor = _read_tlv(tbs, cursor)
    else:
        serial_value = version_value
    if tag != _INTEGER:
        raise CertificateError("missing certificate serial number")

    try:
        serial = int.from_bytes(serial_value, "big")
    except ValueError as exc:  # pragma: no cover - int.from_bytes does not raise here
        raise CertificateError("invalid certificate serial number") from exc

    _, cursor = _expect(tbs, cursor, _SEQUENCE, "signature algorithm")
    issuer_body, cursor = _expect(tbs, cursor, _SEQUENCE, "issuer")
    validity_body, cursor = _expect(tbs, cursor, _SEQUENCE, "validity")
    subject_body, cursor = _expect(tbs, cursor, _SEQUENCE, "subject")
    _, cursor = _expect(
        tbs, cursor, _SEQUENCE, "subject public key information"
    )

    not_before, not_after = _parse_validity(validity_body)

    dns_names: list[str] = []
    ip_addresses: list[str] = []
    while cursor < len(tbs):
        tag, value, cursor = _read_tlv(tbs, cursor)
        if tag == _EXTENSIONS_WRAPPER:
            names, addresses = _parse_extensions(value)
            dns_names.extend(names)
            ip_addresses.extend(addresses)
        # [1] issuerUniqueID and [2] subjectUniqueID are intentionally skipped.

    issuer_attributes = _parse_name(issuer_body)
    subject_attributes = _parse_name(subject_body)

    return CertificateInfo(
        subject=_format_name(subject_attributes),
        issuer=_format_name(issuer_attributes),
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        dns_names=tuple(dict.fromkeys(dns_names)),
        ip_addresses=tuple(dict.fromkeys(ip_addresses)),
    )


def pem_to_der(pem: str | bytes) -> bytes:
    """Convert one PEM certificate to DER using the standard library helper."""

    if isinstance(pem, bytes):
        try:
            pem_text = pem.decode("ascii")
        except UnicodeDecodeError as exc:
            raise CertificateError("PEM certificate is not ASCII") from exc
    elif isinstance(pem, str):
        pem_text = pem
    else:
        raise TypeError("pem must be str or bytes")

    if "-----BEGIN CERTIFICATE-----" not in pem_text:
        raise CertificateError("input does not contain a PEM certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem_text)
    except ValueError as exc:
        raise CertificateError(f"invalid PEM certificate: {exc}") from exc
    if not der:
        raise CertificateError("PEM certificate decoded to empty DER")
    return der


def parse_certificate_pem(pem: str | bytes) -> CertificateInfo:
    """Parse a PEM-encoded X.509 certificate."""

    return parse_certificate(pem_to_der(pem))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def days_until(when: datetime, now: datetime | None = None) -> int:
    """Return whole days between ``now`` and ``when``, rounded down.

    Rounding down is deliberate: a certificate with 13 days and 23 hours left
    has 13 whole days left, while a certificate that expired one second ago has
    -1 whole days left.  Naive datetimes are interpreted as UTC.
    """

    reference = _as_utc(now) if now is not None else datetime.now(timezone.utc)
    target = _as_utc(when)
    return (target - reference).days


def format_timestamp(value: datetime) -> str:
    """Format a datetime in UTC for findings."""

    return _as_utc(value).strftime("%Y-%m-%d %H:%M:%S UTC")
