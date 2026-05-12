from __future__ import annotations

import asyncio
import ssl
import time

import aiohttp

from .config import Baseline, FuzzConfig, FuzzResult


async def send_baseline(
    config: FuzzConfig,
    session: aiohttp.ClientSession,
) -> Baseline:
    """Send an unfuzzed request to establish baseline metrics."""
    start = time.monotonic()
    async with session.request(
        config.method,
        config.url,
        headers=config.headers or None,
        proxy=config.proxy,
        timeout=aiohttp.ClientTimeout(total=config.timeout),
    ) as resp:
        body = await resp.text()
        elapsed = time.monotonic() - start
        return Baseline(
            status_code=resp.status,
            body_length=len(body),
            response_time=elapsed,
            body=body,
        )


async def send_fuzzed(
    config: FuzzConfig,
    session: aiohttp.ClientSession,
    header_name: str,
    strategy: str,
    payload: str,
    semaphore: asyncio.Semaphore,
) -> FuzzResult:
    """Send a single fuzzed request and return a FuzzResult."""
    result = FuzzResult(header_name=header_name, strategy=strategy, payload=payload)

    fuzzed_headers = dict(config.headers) if config.headers else {}
    fuzzed_headers[header_name] = payload

    for attempt in range(1, config.retries + 1):
        try:
            async with semaphore:
                if config.delay:
                    await asyncio.sleep(config.delay)
                start = time.monotonic()
                async with session.request(
                    config.method,
                    config.url,
                    headers=fuzzed_headers,
                    proxy=config.proxy,
                    timeout=aiohttp.ClientTimeout(total=config.timeout),
                ) as resp:
                    body = await resp.text()
                    result.response_time = time.monotonic() - start
                    result.status_code = resp.status
                    result.body_length = len(body)
                    # Check if the payload is reflected in the response body
                    safe_payload = payload[:200]  # truncate for matching
                    if safe_payload and safe_payload in body:
                        result.reflected = True
                    return result
        except ValueError as exc:
            # aiohttp rejects headers with \r, \n, \x00 - not retryable
            result.error = f"rejected by client: {exc}"
            return result
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            if attempt == config.retries:
                result.error = f"{type(exc).__name__}: {exc}"
                return result
            await asyncio.sleep(0.5 * attempt)

    return result  # shouldn't reach here, but just in case


def build_ssl_context(skip_verify: bool) -> ssl.SSLContext | bool:
    """Return an SSL context (or False to disable verification)."""
    if skip_verify:
        return False  # aiohttp interprets False as "don't verify"
    return None  # use default
