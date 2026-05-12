from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from . import payloads
from .analyzer import analyze
from .config import FuzzConfig
from .reporter import Reporter
from .sender import build_ssl_context, send_baseline, send_fuzzed

_DEFAULT_HEADERS_FILE = Path(__file__).parent.parent / "wordlists" / "headers.txt"

_BANNER = """[bold cyan]
 ╦ ╦╔╦╗╔╦╗╔═╗  ╦ ╦╔═╗╔═╗═╦╗╔═╗╦═╗  ╔═╗╦ ╦╔═╗╔═╗╔═╗╦═╗
 ╠═╣ ║  ║ ╠═╝  ╠═╣║╣ ╠═╣ ║║║╣ ╠╦╝  ╠╣ ║ ║╔═╝╔═╝║╣ ╠╦╝
 ╩ ╩ ╩  ╩ ╩    ╩ ╩╚═╝╩ ╩═╩╝╚═╝╩╚═  ╚  ╚═╝╚═╝╚═╝╚═╝╩╚═[/]
"""


def _load_header_names(config: FuzzConfig) -> list[str]:
    """Resolve which header names to fuzz."""
    if config.header_names:
        return list(config.header_names)
    # Fall back to bundled wordlist
    if _DEFAULT_HEADERS_FILE.is_file():
        lines = _DEFAULT_HEADERS_FILE.read_text(encoding="utf-8").splitlines()
        return [h.strip() for h in lines if h.strip() and not h.startswith("#")]
    # Minimal fallback
    return [
        "User-Agent", "Referer", "X-Forwarded-For", "Accept",
        "Cookie", "Host", "Origin", "Authorization",
    ]


def _print_config_summary(
    console: Console,
    config: FuzzConfig,
    header_names: list[str],
    total_payloads: int,
    total_requests: int,
) -> None:
    """Print a configuration overview panel before fuzzing starts."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", min_width=14)
    grid.add_column(style="white")

    grid.add_row("Target", f"[underline]{config.url}[/]")
    grid.add_row("Method", config.method)
    grid.add_row("Headers", f"{len(header_names)} header names")
    grid.add_row("Strategies", f"{len(config.strategies)}  [dim]({', '.join(config.strategies)})[/]")
    grid.add_row("Payloads", f"{total_payloads} per header")
    grid.add_row("Total", f"[bold]{total_requests:,}[/] requests")
    grid.add_row("Concurrency", str(config.concurrency))
    grid.add_row("Timeout", f"{config.timeout}s")
    if config.proxy:
        grid.add_row("Proxy", config.proxy)
    if config.delay:
        grid.add_row("Delay", f"{config.delay}s")
    if config.skip_verify:
        grid.add_row("TLS Verify", "[yellow]disabled[/]")

    console.print(Panel(grid, title="[bold cyan]Scan Configuration[/]", border_style="cyan", expand=False))


async def run(config: FuzzConfig) -> None:
    """Execute a full fuzz run."""
    console = Console(stderr=True)
    console.print(_BANNER)

    header_names = _load_header_names(config)

    ssl_ctx = build_ssl_context(config.skip_verify)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)

    async with aiohttp.ClientSession(connector=connector) as session:
        # 1. Baseline
        console.print("[dim]Sending baseline request…[/]")
        try:
            baseline = await send_baseline(config, session)
        except Exception as exc:
            console.print(f"\n[bold red]✗ Baseline request failed:[/] {exc}")
            sys.exit(1)

        baseline_grid = Table.grid(padding=(0, 3))
        baseline_grid.add_column(style="bold white")
        baseline_grid.add_column()
        baseline_grid.add_row("Status", f"[green]{baseline.status_code}[/]")
        baseline_grid.add_row("Body", f"{baseline.body_length:,} bytes")
        baseline_grid.add_row("Time", f"{baseline.response_time:.3f}s")
        console.print(Panel(
            baseline_grid,
            title="[bold green]✓ Baseline Response[/]",
            border_style="green",
            expand=False,
        ))

        # 2. Build payload list (materialised so we can show a progress bar)
        payload_list = list(payloads.generate(config.strategies, config.custom_payloads_file))
        total_requests = len(header_names) * len(payload_list)

        _print_config_summary(console, config, header_names, len(payload_list), total_requests)
        console.print()

        # 3. Reporter
        reporter = Reporter(
            fmt=config.output_format,
            dest=config.output_file,
            show_all=config.show_all,
            exploitable_only=config.exploitable_only,
        )

        # 4. Fan out
        semaphore = asyncio.Semaphore(config.concurrency)
        interesting_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[bold]{task.completed}/{task.total}[/]"),
            TextColumn("[dim]│[/]"),
            TimeElapsedColumn(),
            TextColumn("[dim]│[/]"),
            TextColumn("[bold yellow]⚑ {task.fields[hits]}[/]"),
            console=console,
        ) as progress:
            task_id = progress.add_task("Fuzzing", total=total_requests, hits=0)

            async def _fuzz_one(hdr: str, strategy: str, payload: str) -> None:
                nonlocal interesting_count
                result = await send_fuzzed(
                    config, session, hdr, strategy, payload, semaphore,
                )
                analyze(result, baseline, config)
                reporter.record(result)
                if result.interesting:
                    interesting_count += 1
                progress.update(task_id, advance=1, hits=interesting_count)

            tasks = [
                _fuzz_one(hdr, strategy, payload)
                for hdr in header_names
                for strategy, payload in payload_list
            ]

            # Process in chunks to avoid overwhelming memory for huge runs
            chunk_size = max(config.concurrency * 10, 200)
            for i in range(0, len(tasks), chunk_size):
                await asyncio.gather(*tasks[i : i + chunk_size])

        console.print()

        # 5. Report
        reporter.write_summary(baseline)
