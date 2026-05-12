from __future__ import annotations

import re

from .config import Baseline, FuzzConfig, FuzzResult

# Patterns that suggest the server leaked an error / stack trace
_ERROR_SIGNATURES: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(sql|mysql|ora-\d+|pg::|sqlite)",
        r"stack\s*trace",
        r"traceback\s*\(most recent",
        r"internal server error",
        r"exception in thread",
        r"fatal error",
        r"segmentation fault",
        r"core dumped",
        r"syntax error",
        r"undefined (function|variable|index)",
        r"warning:.*\bline\b.*\d+",
        r"<b>Warning</b>:",           # PHP-style
        r"Microsoft OLE DB Provider",
        r"ODBC SQL Server Driver",
        r"at [\w.$]+\([\w]+\.java:\d+\)",  # Java stacktrace
        r"at .+\.cs:line \d+",             # .NET stacktrace
    ]
]


def analyze(
    result: FuzzResult,
    baseline: Baseline,
    config: FuzzConfig,
) -> FuzzResult:
    """Flag a FuzzResult as interesting if it deviates from the baseline.

    Mutates and returns the same ``result`` object.
    """
    reasons: list[str] = []

    # 1. Connection / network error
    if result.error:
        reasons.append(f"error: {result.error}")
        result.interesting = True
        result.reasons = reasons
        return result

    # 2. Status code change
    if result.status_code != baseline.status_code:
        reasons.append(
            f"status {result.status_code} (baseline {baseline.status_code})"
        )

    # 3. Body-length deviation
    if result.body_length is not None and baseline.body_length:
        ratio = abs(result.body_length - baseline.body_length) / baseline.body_length
        if ratio > config.body_deviation_threshold:
            reasons.append(
                f"body length {result.body_length} "
                f"(baseline {baseline.body_length}, Δ{ratio:.0%})"
            )

    # 4. Response-time anomaly
    if result.response_time is not None and baseline.response_time:
        if result.response_time > baseline.response_time * config.time_multiplier:
            reasons.append(
                f"slow response {result.response_time:.2f}s "
                f"(baseline {baseline.response_time:.2f}s)"
            )

    # 5. Reflection (already set by sender)
    if result.reflected:
        reasons.append("payload reflected in response")

    # 6. Error-signature matching (we re-check status-5xx bodies)
    if result.status_code and result.status_code >= 500:
        reasons.append(f"server error {result.status_code}")

    if reasons:
        result.interesting = True
    result.reasons = reasons
    return result


def scan_error_signatures(body: str) -> list[str]:
    """Return list of error-signature names found in a response body.

    This is an optional deeper-scan utility; the main ``analyze`` path uses
    status codes and size heuristics for speed.
    """
    found: list[str] = []
    for pattern in _ERROR_SIGNATURES:
        if pattern.search(body):
            found.append(pattern.pattern)
    return found
