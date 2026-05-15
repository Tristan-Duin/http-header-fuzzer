from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

STRATEGIES = [
    "overflow",
    "sql_injection",
    "xss",
    "crlf_injection",
    "format_string",
    "null_byte",
    "unicode",
    "integer",
    "command_injection",
]


@dataclass(frozen=True)
class FuzzConfig:
    """Immutable run configuration built from CLI args."""

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    header_names: list[str] = field(default_factory=list)
    strategies: list[str] = field(default_factory=lambda: list(STRATEGIES))
    custom_payloads_file: str | None = None
    concurrency: int = 10
    timeout: float = 10.0
    retries: int = 2
    delay: float = 0.0
    proxy: str | None = None
    skip_verify: bool = False
    raw: bool = False
    output_format: Literal["console", "json", "csv"] = "console"
    output_file: str | None = None
    show_all: bool = False
    exploitable_only: bool = False
    body_deviation_threshold: float = 0.3
    time_multiplier: float = 3.0


@dataclass
class FuzzResult:
    """Outcome of a single fuzzed request."""

    header_name: str
    strategy: str
    payload: str
    status_code: int | None = None
    body_length: int | None = None
    response_time: float | None = None
    error: str | None = None
    reflected: bool = False
    interesting: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class Baseline:
    """Baseline (unfuzzed) response metrics."""

    status_code: int
    body_length: int
    response_time: float
    body: str = ""
