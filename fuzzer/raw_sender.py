"""Raw socket HTTP sender — bypasses client-side header validation.

Manually constructs HTTP/1.1 requests over TCP (or TLS) so that payloads
containing \\r\\n, \\x00, and other normally-rejected bytes actually reach
the server.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import time
from urllib.parse import urlparse

from .config import Baseline, FuzzConfig, FuzzResult

# Regex to pull status code and body from a raw HTTP response
_STATUS_RE = re.compile(rb"HTTP/\d\.\d\s+(\d{3})")


def _parse_url(url: str) -> tuple[str, str, int, str, bool]:
    """Return (host, host_header, port, path, use_tls)."""
    parsed = urlparse(url)
    use_tls = parsed.scheme == "https"
    host = parsed.hostname or "localhost"
    default_port = 443 if use_tls else 80
    port = parsed.port or default_port
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    # Host header includes port only when non-default
    if port != default_port:
        host_header = f"{host}:{port}"
    else:
        host_header = host
    return host, host_header, port, path, use_tls


def _build_request(
    method: str,
    path: str,
    host_header: str,
    headers: dict[str, str],
) -> bytes:
    """Build a raw HTTP/1.1 request as bytes.

    No validation is performed — values are written verbatim so that
    injected \\r\\n, \\x00, etc. pass through to the wire.
    """
    # Request line
    lines: list[str] = [f"{method} {path} HTTP/1.1"]

    # Host is required, but we let the caller override it via headers
    has_host = any(k.lower() == "host" for k in headers)
    if not has_host:
        lines.append(f"Host: {host_header}")

    for name, value in headers.items():
        lines.append(f"{name}: {value}")

    # Connection: close so we can read until EOF
    if not any(k.lower() == "connection" for k in headers):
        lines.append("Connection: close")

    # Join with raw \r\n — NOT escaped, actual bytes
    request_str = "\r\n".join(lines) + "\r\n\r\n"

    # Encode to bytes — try latin-1 first (preserves 0x00-0xff verbatim),
    # fall back to utf-8, and as a last resort replace unencodable chars
    # (e.g. lone surrogates like \ud800) with their raw byte representation.
    for encoding, errors in [("latin-1", "strict"), ("utf-8", "strict"), ("utf-8", "replace")]:
        try:
            return request_str.encode(encoding, errors=errors)
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
    return request_str.encode("ascii", errors="replace")  # absolute fallback


def _parse_response(raw: bytes) -> tuple[int | None, str, float]:
    """Parse status code, body text, and body length from raw response bytes."""
    status_code: int | None = None
    match = _STATUS_RE.search(raw)
    if match:
        status_code = int(match.group(1))

    # Split headers from body at \r\n\r\n
    body = b""
    sep = raw.find(b"\r\n\r\n")
    if sep != -1:
        body = raw[sep + 4:]
    else:
        # Try \n\n as fallback
        sep = raw.find(b"\n\n")
        if sep != -1:
            body = raw[sep + 2:]

    body_text = body.decode("utf-8", errors="replace")
    return status_code, body_text, len(body_text)


async def _raw_exchange(
    host: str,
    port: int,
    request: bytes,
    use_tls: bool,
    skip_verify: bool,
    timeout: float,
) -> bytes:
    """Open a TCP (or TLS) connection, send request, read full response."""
    ssl_ctx: ssl.SSLContext | None = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        if skip_verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx),
        timeout=timeout,
    )

    try:
        writer.write(request)
        await writer.drain()

        # Read until the server closes the connection (Connection: close)
        chunks: list[bytes] = []
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def send_baseline_raw(config: FuzzConfig) -> Baseline:
    """Send an unfuzzed raw request to establish baseline metrics."""
    host, host_header, port, path, use_tls = _parse_url(config.url)

    headers: dict[str, str] = {}
    if config.headers:
        headers.update(config.headers)

    request = _build_request(config.method, path, host_header, headers)

    start = time.monotonic()
    raw_resp = await _raw_exchange(
        host, port, request, use_tls, config.skip_verify, config.timeout,
    )
    elapsed = time.monotonic() - start

    status_code, body_text, body_length = _parse_response(raw_resp)

    return Baseline(
        status_code=status_code or 0,
        body_length=body_length,
        response_time=elapsed,
        body=body_text,
    )


async def send_fuzzed_raw(
    config: FuzzConfig,
    header_name: str,
    strategy: str,
    payload: str,
    semaphore: asyncio.Semaphore,
) -> FuzzResult:
    """Send a single raw fuzzed request and return a FuzzResult."""
    result = FuzzResult(header_name=header_name, strategy=strategy, payload=payload)
    host, host_header, port, path, use_tls = _parse_url(config.url)

    fuzzed_headers: dict[str, str] = {}
    if config.headers:
        fuzzed_headers.update(config.headers)
    fuzzed_headers[header_name] = payload

    try:
        request = _build_request(config.method, path, host_header, fuzzed_headers)
    except Exception as exc:
        result.error = f"failed to build request: {exc}"
        return result

    for attempt in range(1, config.retries + 1):
        try:
            async with semaphore:
                if config.delay:
                    await asyncio.sleep(config.delay)
                start = time.monotonic()
                raw_resp = await _raw_exchange(
                    host, port, request, use_tls,
                    config.skip_verify, config.timeout,
                )
                result.response_time = time.monotonic() - start

            status_code, body_text, body_length = _parse_response(raw_resp)
            result.status_code = status_code
            result.body_length = body_length

            # Reflection check
            safe_payload = payload[:200]
            if safe_payload and safe_payload in body_text:
                result.reflected = True

            return result

        except (asyncio.TimeoutError, OSError, ConnectionError) as exc:
            if attempt == config.retries:
                result.error = f"{type(exc).__name__}: {exc}"
                return result
            await asyncio.sleep(0.5 * attempt)

    return result
