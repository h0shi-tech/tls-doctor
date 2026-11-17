# tls-doctor

[![CI](https://img.shields.io/github/actions/workflow/status/h0shi-tech/tls-doctor/ci.yml?branch=main&label=CI)](https://github.com/h0shi-tech/tls-doctor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)](pyproject.toml)

`tls-doctor` inspects the TLS and HTTPS configuration of one or more hostnames
and reports findings you can read, pipe to `jq`, or gate a deployment on. It is
a single Python package with no runtime dependencies.

Certificate expiry, hostname mismatches, obsolete protocols, weak ciphers,
missing HSTS and plain-HTTP endpoints are common deployment mistakes. Manual
checks catch them late, if at all. `tls-doctor` packages those checks into one
command with a stable output schema and a small exit-code contract.

## Quick start

Requires Python 3.11 or newer. There is nothing to install for a checkout-based
run:

```console
$ git clone https://github.com/h0shi-tech/tls-doctor.git
$ cd tls-doctor
$ python3 -m tls_doctor example.com
```

To install the console script instead:

```console
$ python3 -m pip install .
$ tls-doctor example.com
```

The output below is a real capture from 2026-11-17. Certificate dates and the
target's configuration will change over time; this is not an illustration.

```text
HOST         CHECK          SEVERITY  FINDING                                  DETAIL
-----------  -------------  --------  ---------------------------------------  -----------------------------------------------------------------------------------
example.com  cert.expiry    OK        Certificate is valid                     38 days left (notAfter 2026-12-25 22:56:35 UTC); the configured minimum is 14 days.
example.com  cert.hostname  OK        Certificate matches hostname             example.com matches the certificate's DNS:example.com.
example.com  cert.chain     OK        Certificate chain is structurally valid  The server presented 4 certificates. No structural problems were detected.
example.com  tls.version    OK        TLS version is acceptable                The server negotiated TLSv1.3; the minimum is TLS 1.2.
example.com  tls.legacy     WARNING   Legacy TLS protocols are accepted        The server still accepts TLSv1.0, TLSv1.1.
example.com  tls.cipher     OK        Cipher suite is acceptable               The server negotiated TLS_AES_256_GCM_SHA384 with 256-bit symmetric encryption.
example.com  http.hsts      WARNING   HSTS header is missing                   The HTTPS response did not include a Strict-Transport-Security header.
example.com  http.redirect  WARNING   HTTP does not redirect to HTTPS          Port 80 returned HTTP 200 without an HTTPS redirect.

5 ok, 3 warnings, 0 errors
```

The process exit code for that run was `0`: the default failure threshold is
`error`, and the three findings above are warnings. Use `--fail-on warning` when
warnings should fail a pipeline as well.

## Usage

```text
tls-doctor HOST [HOST ...] [options]
```

| Option | Default | Description |
| --- | --- | --- |
| `--port PORT` | `443` | TLS port to connect to. |
| `--timeout SECONDS` | `5` | Per-connection timeout. |
| `--min-days DAYS` | `14` | Warn when the certificate expires in fewer than `DAYS` days. |
| `--format {table,json,md}` | `table` | Output format. |
| `--fail-on {warning,error,never}` | `error` | Lowest severity that produces a non-zero exit. |
| `--ip ADDRESS` | — | Connect to this address while keeping the hostname for SNI and checks. Only valid with a single host. |
| `--no-network-probe` | off | Skip the supplemental legacy-TLS and HTTP probes. The primary TLS handshake still runs, so certificate, protocol and cipher checks remain available. |
| `--version` | — | Print the version and exit. |

Multiple hosts are checked concurrently with a bounded thread pool (at most
eight workers). Results are always rendered in the order the hosts were given.

```console
$ tls-doctor example.com www.example.com --min-days 30 --fail-on warning
$ tls-doctor internal.example.com --port 8443 --ip 10.0.0.12
$ tls-doctor example.com --format json > tls.json
$ tls-doctor example.com --format md >> "$GITHUB_STEP_SUMMARY"
```

## Exit code contract

The exit code is a process status, not a count of findings. Errors take
precedence over warnings.

| Exit code | Meaning |
| --- | --- |
| `0` | No finding reached the selected failure threshold. With the default `--fail-on error`, warning findings still exit `0`. `--fail-on never` always exits `0` after a completed diagnosis. |
| `1` | At least one warning and no errors, when `--fail-on warning` is selected. |
| `2` | At least one error, under `--fail-on error` (default) or `--fail-on warning`. Unreachable hosts, timeouts and TLS handshake failures are error findings. |
| `3` | Usage error: invalid options or hostnames, or `--ip` used with more than one host. Argparse exits with `3` before any checks run. |

## What it checks

| Finding ID | Severity when actionable | Check | Remediation |
| --- | --- | --- | --- |
| `cert.expiry` | error if expired, warning if below `--min-days` | Whole days until the leaf certificate's `notAfter`. A certificate with 13 days and 23 hours left reports 13 days. | Renew the certificate and verify automated rotation. |
| `cert.hostname` | error | The hostname must match a `dNSName` SAN using case-insensitive, label-aware wildcard rules; IP literals must match an `iPAddress` SAN. `*.example.com` matches `a.example.com` but not `a.b.example.com` or the bare `example.com`. | Reissue the certificate with a SAN that covers the hostname. |
| `cert.chain` | error for an expired non-leaf certificate; warning for a self-signed leaf or an incomplete chain | Chain length from the handshake, self-signed leaf detection (subject equals issuer), and expiry of intermediates. An included self-signed root is noted but is not itself a failure. | Deploy the correct intermediate chain or use a trusted certificate. |
| `tls.version` | error | The negotiated protocol must be TLS 1.2 or newer. | Disable TLS 1.0/1.1 and enable TLS 1.2/1.3. |
| `tls.legacy` | warning | Separate handshake attempts for TLS 1.0 and TLS 1.1. Accepted versions are reported. | Disable TLS 1.0 and TLS 1.1. |
| `tls.cipher` | error | The negotiated cipher is flagged for NULL, EXPORT, RC4, DES, 3DES, or an effective key strength below 128 bits. | Disable weak suites and require AEAD suites with at least 128-bit keys. |
| `http.hsts` | warning | `Strict-Transport-Security` is fetched with a HEAD request over HTTPS. A missing header, missing/invalid `max-age`, or `max-age` below 15552000 seconds (180 days) warns. | Add or lengthen HSTS, for example `max-age=31536000; includeSubDomains`. |
| `http.hsts.scope` | info only | Reports whether `includeSubDomains` and/or `preload` are present. Preload declaration is not verified against browser lists. | No action required. |
| `http.redirect` | warning | A HEAD request to plain HTTP port 80 must return a 301/302/303/307/308 redirect to an absolute `https://` URL. A refused port 80 connection is accepted as "no plaintext listener"; other probe failures warn. | Redirect HTTP to HTTPS with a 301 or 308. |
| `unreachable` | error | DNS, TCP or TLS handshake failure, including timeouts and connection refusals. Reported as a normal finding without a traceback. | Check DNS, firewall, listening port and timeout. |

Successful checks produce `ok` findings, and the `http.hsts.scope` check
produces `info` findings. Neither affects the exit code.

## Output formats

`--format table` prints the aligned text table and summary line shown in the
quick start. When there are info findings, their count is appended to the
summary line. `--format md` prints one Markdown section per host, with a table
that includes remediation text, and is suitable for a pull-request comment or
`$GITHUB_STEP_SUMMARY`.

`--format json` has a stable per-host schema:

- `host`: the target as displayed (`host` or `host:port` when `--port` is not 443).
- `findings`: an array of objects with exactly `id`, `severity`, `title`,
  `detail` and `remediation` string fields.
- `summary`: counts with keys `ok`, `info`, `warning`, `error` and `total`.

For a single host, JSON is one host object. For multiple hosts, JSON is an array
of those objects in input order. The per-host object shape is identical in both
cases, with no extra wrapper:

```json
{
  "host": "example.com",
  "findings": [
    {"id": "cert.expiry", "severity": "ok", "title": "...", "detail": "...", "remediation": ""}
  ],
  "summary": {"ok": 1, "info": 0, "warning": 0, "error": 0, "total": 1}
}
```

Values are illustrative; the field names and types are the contract. Example
`jq` expressions:

```console
# Errors for a single host
$ tls-doctor example.com --format json | jq -r '.findings[] | select(.severity == "error") | "\(.id): \(.detail)"'

# Errors across several hosts
$ tls-doctor example.com www.example.com --format json \
    | jq -r '.[] | .host as $host | .findings[] | select(.severity == "error") | "\($host) \(.id): \(.detail)"'
```

## Use in CI

The exit code makes the command usable as a deploy gate. This workflow checks
two production hostnames on a schedule, fails on warnings, and still writes the
Markdown report to the job summary:

```yaml
name: TLS check

on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * *"

jobs:
  diagnose:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install tls-doctor
        run: python -m pip install .

      - name: Diagnose TLS
        shell: bash
        run: |
          set -o pipefail
          tls-doctor example.com www.example.com \
            --min-days 21 \
            --fail-on warning \
            --format md \
            | tee -a "$GITHUB_STEP_SUMMARY"
```

## Tests

```console
$ python3 -m unittest discover -s tests -v
$ make check          # byte-compile plus the full suite
```

The suite runs offline. It includes pure-function tests for hostname matching
(including wildcard edge cases), expiry boundaries, cipher classification, HSTS
parsing and rendering, plus an integration test that starts a temporary local
TLS server with an `openssl`-generated self-signed certificate. That integration
test is skipped cleanly when the `openssl` executable is unavailable. No public
internet access is required.

CI runs the suite on Python 3.11, 3.12, 3.13 and 3.14.

## Limitations

- Certificate trust is not validated against the system CA store, and chain
  signatures are not cryptographically verified. `cert.chain` is a structural
  check. A chain signed by an untrusted, non-self-signed CA can pass it.
- There is no OCSP, OCSP-stapling, CRL, certificate-transparency, CAA or DANE
  validation.
- Each check samples a single connection. Load-balanced endpoints, CDNs and
  path-dependent configurations can behave differently; use multiple hosts or
  `--ip` to target a specific address.
- Chain length depends on the Python/OpenSSL build exposing the server-presented
  chain. If that API is unavailable, only the leaf certificate is inspected and
  a single-certificate chain is reported as potentially incomplete.
- HSTS is read from one HEAD response on the tested TLS port. `http.redirect`
  uses HEAD on port 80 and does not follow redirect chains or inspect bodies.
- Legacy-TLS probing depends on the local OpenSSL build. The client deliberately
  lowers its security level to offer TLS 1.0/1.1; if the local library cannot
  offer a version, the result is reported as info rather than as a failure.
- Wildcard matching is intentionally limited to a complete left-most label and
  does not consult a public suffix list. The legacy commonName fallback is not
  used, matching modern browser behaviour.
- No SNI-name enumeration or multi-IP sweep is performed; one hostname and one
  connection per probe are used.
- Certificate key size, signature algorithm and curve are not evaluated. The
  tool is not a full TLS scanner or a replacement for a browser trust check.
- Expiry findings use the local clock; keep CI clocks synchronized.
- `--no-network-probe` still performs the primary TLS handshake. It skips the
  supplemental TLS 1.0/1.1 and HTTP probes only.

## License

MIT. Copyright (c) 2026 Vlad Nikishin. See [LICENSE](LICENSE).
