from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from dataclasses import asdict
from itertools import groupby
from operator import attrgetter
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .config import Baseline, FuzzResult

# Map reason keywords to severity for visual priority
_SEVERITY_ORDER = {"error": 0, "server error": 0, "reflected": 1, "status": 2, "slow": 3, "body length": 4}


def _severity(result: FuzzResult) -> int:
    """Lower = more severe.  Used for sorting within groups."""
    if result.error:
        return 0
    if result.reflected:
        return 1
    for reason in result.reasons:
        r_lower = reason.lower()
        if "server error" in r_lower:
            return 0
        if "status" in r_lower:
            return 2
        if "slow" in r_lower:
            return 3
    return 4


def _severity_badge(result: FuzzResult) -> str:
    """Return a coloured severity label."""
    sev = _severity(result)
    if sev == 0:
        return "[bold white on red] CRIT [/]"
    if sev == 1:
        return "[bold white on #d35400] HIGH [/]"
    if sev == 2:
        return "[bold black on yellow] MED  [/]"
    if sev == 3:
        return "[bold white on blue] LOW  [/]"
    return "[dim] INFO [/]"


def _format_payload(payload: str, max_len: int = 52) -> str:
    """Truncate, escape control chars, and return a display-safe string."""
    display = repr(payload[:max_len])[1:-1]  # strip outer quotes from repr
    if len(payload) > max_len:
        display += "[dim]…[/]"
    return display


def _format_reasons(reasons: list[str]) -> str:
    """Pretty-print reason flags with colour-coded bullets."""
    parts: list[str] = []
    for reason in reasons:
        rl = reason.lower()
        if "error" in rl or "server error" in rl:
            parts.append(f"[red]●[/] {reason}")
        elif "reflected" in rl:
            parts.append(f"[#d35400]●[/] {reason}")
        elif "status" in rl:
            parts.append(f"[yellow]●[/] {reason}")
        elif "slow" in rl:
            parts.append(f"[blue]●[/] {reason}")
        elif "body" in rl:
            parts.append(f"[cyan]●[/] {reason}")
        else:
            parts.append(f"[dim]●[/] {reason}")
    return "\n".join(parts)


class Reporter:
    """Collects FuzzResults and writes them to the chosen destination."""

    def __init__(
        self,
        fmt: str = "console",
        dest: str | None = None,
        show_all: bool = False,
        exploitable_only: bool = False,
    ) -> None:
        self.fmt = fmt
        self.show_all = show_all
        self.exploitable_only = exploitable_only
        self._results: list[FuzzResult] = []
        self._dest = dest
        self._interesting_count = 0
        self._total_count = 0

    # -- streaming interface ---------------------------------------------------

    def record(self, result: FuzzResult) -> None:
        """Record one result (called per-request during the fuzz run)."""
        self._total_count += 1
        if result.interesting:
            self._interesting_count += 1
        if self.show_all or result.interesting:
            self._results.append(result)

    # -- final output ----------------------------------------------------------

    def write_summary(self, baseline: Baseline) -> None:
        """Write the final report after all requests are done."""
        sink: TextIO
        if self._dest:
            sink = open(self._dest, "w", encoding="utf-8", newline="")
        else:
            sink = sys.stdout

        try:
            if self.fmt == "json":
                self._write_json(sink, baseline)
            elif self.fmt == "csv":
                self._write_csv(sink)
            else:
                self._write_console(baseline)
        finally:
            if sink is not sys.stdout:
                sink.close()

    # -- filtering -------------------------------------------------------------

    def _filtered_results(self) -> list[FuzzResult]:
        """Return results after applying the exploitable-only filter."""
        if not self.exploitable_only:
            return list(self._results)

        # Keep only CRIT (0) and HIGH (1) severity
        high_sev = [r for r in self._results if r.interesting and _severity(r) <= 1]

        # Deduplicate: keep the single best (lowest severity, then first seen)
        # hit per (header_name, strategy) pair
        seen: dict[tuple[str, str], FuzzResult] = {}
        for r in high_sev:
            key = (r.header_name, r.strategy)
            existing = seen.get(key)
            if existing is None or _severity(r) < _severity(existing):
                seen[key] = r
        return sorted(seen.values(), key=lambda r: (r.header_name, _severity(r)))

    # -- console formatter -----------------------------------------------------

    def _write_console(self, baseline: Baseline) -> None:
        console = Console()
        display_results = self._filtered_results()

        if not display_results:
            label = "No exploitable findings." if self.exploitable_only else "No interesting results found."
            console.print(
                Panel(
                    f"[green]{label}[/]\n"
                    f"Tested [bold]{self._total_count:,}[/] requests with no anomalies.",
                    title="[bold green]✓ Clean[/]",
                    border_style="green",
                    expand=False,
                )
            )
            return

        if self.exploitable_only:
            console.print(Panel(
                f"Showing [bold]{len(display_results)}[/] most exploitable finding(s) "
                f"out of [bold]{self._interesting_count:,}[/] total interesting results.\n"
                "Filtered to [bold white on red] CRIT [/] and [bold white on #d35400] HIGH [/] severity, "
                "deduplicated per header + strategy.",
                title="[bold red]Exploitable Findings[/]",
                border_style="red",
                expand=False,
            ))

        # --- Results grouped by header name ---
        sorted_results = sorted(
            display_results, key=lambda r: (r.header_name, _severity(r))
        )

        for header_name, group in groupby(sorted_results, key=attrgetter("header_name")):
            items = list(group)

            table = Table(
                show_lines=True,
                border_style="dim",
                pad_edge=True,
                expand=True,
            )
            table.add_column("Sev", width=6, justify="center")
            table.add_column("Strategy", style="yellow", max_width=18)
            table.add_column("Payload", max_width=54)
            table.add_column("Status", justify="center", width=7)
            table.add_column("Size", justify="right", width=10)
            table.add_column("Time", justify="right", width=8)
            table.add_column("Findings", min_width=30)

            for r in items:
                status_str = str(r.status_code) if r.status_code else "ERR"
                if r.status_code and r.status_code >= 500:
                    status_str = f"[bold red]{status_str}[/]"
                elif r.status_code and r.status_code != baseline.status_code:
                    status_str = f"[yellow]{status_str}[/]"
                else:
                    status_str = f"[green]{status_str}[/]"

                size_str = f"{r.body_length:,}" if r.body_length is not None else "-"
                time_str = f"{r.response_time:.3f}s" if r.response_time else "-"

                table.add_row(
                    _severity_badge(r),
                    r.strategy,
                    _format_payload(r.payload),
                    status_str,
                    size_str,
                    time_str,
                    _format_reasons(r.reasons),
                )

            console.print(Panel(
                table,
                title=f"[bold cyan]{header_name}[/]  [dim]({len(items)} finding{'s' if len(items) != 1 else ''})[/]",
                border_style="cyan",
            ))

        # --- Summary panel ---
        self._print_summary(console, baseline)

    def _print_summary(self, console: Console, baseline: Baseline) -> None:
        """Print a final stats panel with strategy breakdown."""
        interesting = [r for r in self._results if r.interesting]

        # Count by strategy
        strat_counts = Counter(r.strategy for r in interesting)
        # Count by severity
        sev_counts: Counter[str] = Counter()
        for r in interesting:
            s = _severity(r)
            if s == 0:
                sev_counts["CRIT"] += 1
            elif s == 1:
                sev_counts["HIGH"] += 1
            elif s == 2:
                sev_counts["MED"] += 1
            elif s == 3:
                sev_counts["LOW"] += 1
            else:
                sev_counts["INFO"] += 1

        # Unique affected headers
        affected_headers = len({r.header_name for r in interesting})

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold white", min_width=18)
        grid.add_column()

        grid.add_row("Total Requests", f"{self._total_count:,}")
        grid.add_row("Interesting", f"[bold yellow]{self._interesting_count:,}[/]")
        grid.add_row("Affected Headers", f"{affected_headers}")

        # Severity breakdown
        sev_parts: list[str] = []
        for label, color in [("CRIT", "red"), ("HIGH", "#d35400"), ("MED", "yellow"), ("LOW", "blue"), ("INFO", "dim")]:
            count = sev_counts.get(label, 0)
            if count:
                sev_parts.append(f"[{color}]{label}: {count}[/]")
        if sev_parts:
            grid.add_row("Severity", "  ".join(sev_parts))

        # Top strategies
        if strat_counts:
            top = strat_counts.most_common(5)
            strat_str = "  ".join(f"[yellow]{name}[/]: {c}" for name, c in top)
            grid.add_row("Top Strategies", strat_str)

        # Reflected payloads
        reflected_count = sum(1 for r in interesting if r.reflected)
        if reflected_count:
            grid.add_row("Reflections", f"[bold #d35400]{reflected_count}[/] payload(s) echoed back")

        border = "red" if sev_counts.get("CRIT", 0) else "yellow" if self._interesting_count else "green"
        console.print()
        console.print(Panel(
            grid,
            title="[bold]Scan Summary[/]",
            border_style=border,
            expand=False,
        ))

    # -- JSON / CSV formatters (unchanged) -------------------------------------

    def _write_json(self, sink: TextIO, baseline: Baseline) -> None:
        display_results = self._filtered_results()
        data = {
            "baseline": asdict(baseline),
            "stats": {
                "total": self._total_count,
                "interesting": self._interesting_count,
                "exploitable_filter": self.exploitable_only,
                "displayed": len(display_results),
            },
            "results": [asdict(r) for r in display_results],
        }
        # Remove large baseline body from JSON output
        data["baseline"].pop("body", None)
        json.dump(data, sink, indent=2, default=str, ensure_ascii=False)
        sink.write("\n")

    def _write_csv(self, sink: TextIO) -> None:
        display_results = self._filtered_results()
        writer = csv.writer(sink)
        writer.writerow([
            "header_name", "strategy", "payload",
            "status_code", "body_length", "response_time",
            "reflected", "interesting", "reasons", "error",
        ])
        for r in display_results:
            writer.writerow([
                r.header_name,
                r.strategy,
                r.payload[:200],
                r.status_code,
                r.body_length,
                f"{r.response_time:.4f}" if r.response_time else "",
                r.reflected,
                r.interesting,
                "; ".join(r.reasons),
                r.error or "",
            ])
