from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .config import STRATEGIES, FuzzConfig
from .core import run


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="httpfuzz",
        description="HTTP Header Fuzzer - probe web servers by injecting "
        "malformed / malicious header values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  httpfuzz --url https://example.com\n"
            "  httpfuzz --url https://example.com --strategies sql_injection xss\n"
            "  httpfuzz --url https://example.com --header-names Host Cookie "
            "--output json -o results.json\n"
            "  httpfuzz --url https://example.com --concurrency 20 --timeout 5\n"
            "  httpfuzz --url https://example.com --custom-payloads my_payloads.txt\n"
        ),
    )

    # Target
    p.add_argument("--url", "-u", required=True, help="Target URL")
    p.add_argument(
        "--method", "-m", default="GET",
        help="HTTP method (default: GET)",
    )
    p.add_argument(
        "--headers", "-H", nargs="*", metavar="K:V", default=[],
        help="Extra static headers (format: 'Name: Value')",
    )

    # Scope
    p.add_argument(
        "--header-names", nargs="*", metavar="NAME",
        help="Specific header names to fuzz (default: bundled wordlist)",
    )
    p.add_argument(
        "--header-wordlist", metavar="FILE",
        help="File with header names to fuzz (one per line)",
    )
    p.add_argument(
        "--strategies", "-s", nargs="*", metavar="NAME",
        choices=STRATEGIES, default=None,
        help=f"Strategies to use (default: all). Choices: {', '.join(STRATEGIES)}",
    )
    p.add_argument(
        "--custom-payloads", metavar="FILE",
        help="File with additional custom payloads (one per line)",
    )

    # Tuning
    p.add_argument(
        "--concurrency", "-c", type=int, default=10,
        help="Max concurrent requests (default: 10)",
    )
    p.add_argument(
        "--timeout", "-t", type=float, default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--retries", type=int, default=2,
        help="Retry count on failure (default: 2)",
    )
    p.add_argument(
        "--delay", type=float, default=0.0,
        help="Delay between requests in seconds (default: 0)",
    )

    # Network
    p.add_argument("--proxy", help="HTTP/SOCKS proxy URL")
    p.add_argument(
        "--skip-verify", action="store_true",
        help="Skip TLS certificate verification",
    )

    # Output
    p.add_argument(
        "--output", choices=["console", "json", "csv"], default="console",
        help="Output format (default: console)",
    )
    p.add_argument(
        "--output-file", "-o", metavar="FILE",
        help="Write output to file instead of stdout",
    )
    p.add_argument(
        "--all", "-a", action="store_true", dest="show_all",
        help="Show all results, not just interesting ones",
    )
    p.add_argument(
        "--exploitable", "-e", action="store_true",
        help="Only show the most exploitable findings (CRIT/HIGH severity)",
    )

    # Meta
    p.add_argument(
        "--version", "-V", action="version", version=f"%(prog)s {__version__}",
    )

    return p


def _parse_headers(raw: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw:
        if ":" not in item:
            print(f"Warning: ignoring malformed header '{item}' (expected 'Name: Value')", file=sys.stderr)
            continue
        key, _, value = item.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def _load_header_names_from_file(filepath: str) -> list[str]:
    with open(filepath, encoding="utf-8") as f:
        return [
            line.strip() for line in f
            if line.strip() and not line.startswith("#")
        ]


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Resolve header names
    header_names: list[str] = []
    if args.header_names:
        header_names = args.header_names
    elif args.header_wordlist:
        header_names = _load_header_names_from_file(args.header_wordlist)

    config = FuzzConfig(
        url=args.url,
        method=args.method.upper(),
        headers=_parse_headers(args.headers),
        header_names=header_names,
        strategies=args.strategies if args.strategies else list(STRATEGIES),
        custom_payloads_file=args.custom_payloads,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        proxy=args.proxy,
        skip_verify=args.skip_verify,
        output_format=args.output,
        output_file=args.output_file,
        show_all=args.show_all,
        exploitable_only=args.exploitable,
    )

    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
