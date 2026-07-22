"""
cli/client.py

Command-line interface for the URL threat scanner.
Talks to the FastAPI server via httpx. Handles polling,
report generation, and all admin commands.

Usage:
    python -m cli.client scan <url> [options]
    python -m cli.client status <scan_id>
    python -m cli.client report <scan_id> [options]
    python -m cli.client admin reload
    python -m cli.client admin stats
    python -m cli.client admin label <scan_id> <malicious|benign>
    python -m cli.client batch <file_path> [options]

Run `python -m cli.client --help` or any subcommand with --help for details.
"""

import asyncio
import csv as _csv
import json
import sys
import time
from pathlib import Path
from typing import Optional
import os

import argparse
import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

from report.generator import generate_report

console = Console()

DEFAULT_SERVER = "http://127.0.0.1:8000"
POLL_INTERVAL  = 1.5
POLL_TIMEOUT   = 120


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _server_url(args) -> str:
    return getattr(args, "server", DEFAULT_SERVER).rstrip("/")


async def _get(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def _post(url: str, payload: dict, timeout: float = 300.0) -> dict:
    """
    POST with a generous default timeout (120s).
    Large batch submissions can take several seconds just for
    the server to chunk-insert thousands of rows — 10s was too short.
    """
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


def _check_server(base: str):
    try:
        import httpx as _httpx
        _httpx.get(f"{base}/docs", timeout=3.0)
    except Exception:
        console.print(
            f"[red]Cannot reach server at {base}[/red]\n"
            "Make sure you started it with:\n"
            "  [bold]uvicorn server.main:app --port 8000[/bold]"
        )
        sys.exit(1)


# ── Poll until complete ────────────────────────────────────────────────────────

async def _poll_scan(base: str, scan_id: str) -> Optional[dict]:
    deadline = time.time() + POLL_TIMEOUT
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=None)
        while time.time() < deadline:
            data = await _get(f"{base}/scan/{scan_id}")
            status = data.get("status", "")
            progress.update(task, description=f"Status: [bold]{status}[/bold]  ({scan_id[:8]}…)")
            if status == "completed":
                return data
            if status == "failed":
                console.print(f"[red]Scan failed:[/red] {data.get('error', 'unknown error')}")
                return None
            await asyncio.sleep(POLL_INTERVAL)
    console.print(f"[yellow]Timed out after {POLL_TIMEOUT}s waiting for scan {scan_id}[/yellow]")
    return None


# ── Command: scan ──────────────────────────────────────────────────────────────

async def cmd_scan(args):
    base = _server_url(args)
    _check_server(base)
    url = args.url
    use_llm = args.llm
    formats = args.formats if args.formats else ["md", "txt", "pdf", "docx"]

    console.print(f"\n[bold]Submitting scan:[/bold] {url}")
    if use_llm:
        console.print("[dim]  LLM enhancement enabled (requires Ollama)[/dim]")

    data = await _post(f"{base}/scan", {"url": url, "use_llm": use_llm})
    scan_id = data["scan_id"]
    console.print(f"[dim]  Scan ID: {scan_id}[/dim]")

    if args.async_mode:
        console.print(
            f"\nScan queued. Check status with:\n"
            f"  [bold]python -m cli.client status {scan_id}[/bold]"
        )
        return

    result_data = await _poll_scan(base, scan_id)
    if not result_data:
        sys.exit(1)

    result = result_data.get("result")
    if not result:
        console.print("[red]Scan completed but result was empty.[/red]")
        sys.exit(1)

    await generate_report(
        scan_id=scan_id,
        result=result,
        formats=formats,
        show_terminal=not args.no_terminal,
    )


# ── Command: status ────────────────────────────────────────────────────────────

async def cmd_status(args):
    base = _server_url(args)
    data = await _get(f"{base}/scan/{args.scan_id}")
    status = data.get("status", "?")
    color = {"completed": "green", "failed": "red", "scanning": "yellow", "queued": "dim"}.get(status, "white")
    console.print(f"\n[bold]Scan:[/bold] {args.scan_id}")
    console.print(f"  Status  : [{color}]{status}[/{color}]")
    console.print(f"  URL     : {data.get('url')}")
    console.print(f"  Created : {data.get('created_at')}")
    if data.get("completed_at"):
        console.print(f"  Done    : {data.get('completed_at')}")
    if data.get("error"):
        console.print(f"  [red]Error   : {data['error']}[/red]")
    if status == "completed":
        verdict = data.get("result", {}).get("verdict", {})
        v = verdict.get("verdict", "?")
        c = verdict.get("confidence", "?")
        vc = {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}.get(v, "white")
        console.print(f"  Verdict : [{vc}]{v}[/{vc}] ({c})")
        console.print(f"\n  [dim]python -m cli.client report {args.scan_id}[/dim]")


# ── Command: report ────────────────────────────────────────────────────────────

async def cmd_report(args):
    base = _server_url(args)
    data = await _get(f"{base}/scan/{args.scan_id}")
    if data.get("status") != "completed":
        console.print(f"[yellow]Scan not completed yet (status: {data.get('status')})[/yellow]")
        sys.exit(1)
    result = data.get("result")
    if not result:
        console.print("[red]No result data found.[/red]")
        sys.exit(1)
    if args.llm:
        result["use_llm"] = True
    formats = args.formats if args.formats else ["md", "txt", "pdf", "docx"]
    await generate_report(
        scan_id=args.scan_id,
        result=result,
        formats=formats,
        show_terminal=not args.no_terminal,
    )


# ── CSV / TXT URL loaders ──────────────────────────────────────────────────────

def _load_urls_from_txt(path: Path) -> list[str]:
    """One URL per line. Lines starting with # are comments."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]


def _resolve_csv_column(header: list[str], column: str) -> int:
    """Resolve --column to a 0-based index. Accepts int string or column name."""
    if column.isdigit():
        idx = int(column)
        if idx >= len(header):
            console.print(
                f"[red]Column index {idx} out of range — "
                f"CSV has {len(header)} columns (0-based).[/red]\n"
                f"  Columns: {', '.join(f'{i}={h}' for i, h in enumerate(header))}"
            )
            sys.exit(1)
        return idx
    lower = [h.strip().lower() for h in header]
    if column.lower() in lower:
        return lower.index(column.lower())
    console.print(
        f"[red]Column '{column}' not found in CSV header.[/red]\n"
        f"  Columns found: {', '.join(header)}\n"
        f"  Use a column name or 0-based index with --column."
    )
    sys.exit(1)


def _load_urls_from_csv(
    path: Path,
    column: str,
    delimiter: str,
    no_header: bool,
) -> tuple[list[str], list[dict]]:
    """
    Parse a CSV and extract URLs from the specified column.

    Returns:
        urls      : list of URL strings (blank rows skipped)
        full_rows : list of header->value dicts (empty if no_header=True)
    """
    with open(path, newline="", encoding="utf-8") as f:
        reader = _csv.reader(f, delimiter=delimiter)
        rows = list(reader)

    if not rows:
        return [], []

    if not no_header:
        header = [h.strip() for h in rows[0]]
        data_rows = rows[1:]
        col_idx = _resolve_csv_column(header, column)
        urls, full_rows = [], []
        for row in data_rows:
            if not row:
                continue
            url = row[col_idx].strip() if col_idx < len(row) else ""
            if url:
                urls.append(url)
                full_rows.append(dict(zip(header, row)))
        return urls, full_rows
    else:
        # No header — column must be a numeric index
        if not column.isdigit():
            console.print(
                "[red]--column must be a numeric index when --no-header is set.[/red]"
            )
            sys.exit(1)
        col_idx = int(column)
        urls = []
        for row in rows:
            if not row or col_idx >= len(row):
                continue
            url = row[col_idx].strip()
            if url:
                urls.append(url)
        return urls, []


def _preview_csv(path: Path, delimiter: str, n: int = 5):
    """Print first N rows of a CSV so the user can confirm column selection."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = _csv.reader(f, delimiter=delimiter)
        rows = list(reader)[:n]
    if not rows:
        console.print("[yellow]CSV appears empty.[/yellow]")
        return
    header = rows[0]
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    for i, h in enumerate(header):
        tbl.add_column(f"[{i}] {h}", max_width=30, no_wrap=True)
    for row in rows[1:]:
        tbl.add_row(*[r[:28] for r in row])
    console.print(tbl)


def _save_csv_summary(summary_rows: list[tuple], out_path: Path):
    """Write batch results to a CSV summary file."""
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = _csv.writer(f)
        writer.writerow(["url", "scan_id", "verdict", "confidence"])
        for url, scan_id, verdict, confidence in summary_rows:
            writer.writerow([url, scan_id, verdict, confidence])
    console.print(f"[dim]  CSV summary → {out_path}[/dim]")


# ── Command: batch ─────────────────────────────────────────────────────────────

async def cmd_batch(args):
    """
    Scan all URLs from a .txt or .csv file as a SINGLE batch.
    → One batch_id  → one consolidated report.
    """
    path = Path(args.file)
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)

    is_csv    = path.suffix.lower() == ".csv" or getattr(args, "csv", False)
    delimiter = getattr(args, "delimiter", ",") or ","
    no_header = getattr(args, "no_header", False)
    column    = getattr(args, "column", "url") or "url"
    preview   = getattr(args, "preview", False)

    # Preview — no server needed
    if preview and is_csv:
        console.print(f"\n[bold]CSV Preview:[/bold] {path.name}")
        _preview_csv(path, delimiter)
        console.print(f"\n[dim]Use --column <name or index> to select the URL column.[/dim]")
        return

    base = _server_url(args)
    _check_server(base)

    # Load URLs
    if is_csv:
        console.print(f"\n[bold]Batch scan (CSV)[/bold] — {path.name}  column: [cyan]{column}[/cyan]")
        urls, _ = _load_urls_from_csv(path, column=column, delimiter=delimiter, no_header=no_header)
    else:
        console.print(f"\n[bold]Batch scan (TXT)[/bold] — {path.name}")
        urls = _load_urls_from_txt(path)

    if not urls:
        console.print("[yellow]No URLs found. Check your file or --column setting.[/yellow]")
        sys.exit(0)

    # Deduplicate preserving order
    seen, unique_urls, dupes = set(), [], 0
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)
        else:
            dupes += 1

    console.print(
        f"  Found [bold]{len(unique_urls)}[/bold] unique URL(s)"
        + (f"  [dim]({dupes} duplicate(s) skipped)[/dim]" if dupes else "")
    )

    # ── Submit — server chunks DB inserts internally, so no size limit ─────────
    console.print()
    use_llm = getattr(args, "llm", False)
    if use_llm:
        console.print("  [dim]LLM enhancement enabled (requires Ollama)[/dim]")

    console.print(f"  [dim]Submitting {len(unique_urls)} URL(s) to server…[/dim]")

    try:
        data = await _post(f"{base}/batch", {"urls": unique_urls, "use_llm": use_llm})
    except Exception as e:
        console.print(f"[red]Submission failed: {e}[/red]")
        sys.exit(1)

    batch_id = data["batch_id"]
    total    = data["total_urls"]
    console.print(f"  [dim]Batch ID : {batch_id}[/dim]")
    console.print(f"  [dim]URLs     : {total}[/dim]\n")

    # ── Poll (progress counters only — no full scan list during poll) ──────────
    deadline = time.time() + (POLL_TIMEOUT * max(total, 1))
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=total)
        prev_done = 0
        while time.time() < deadline:
            # Poll with page_size=1 so the response is tiny regardless of batch size
            st = await _get(f"{base}/batch/{batch_id}?page_size=1")
            done = st.get("completed", 0) + st.get("failed", 0)
            progress.update(
                task,
                description=(
                    f"[bold]{done}/{total}[/bold] done "
                    f"({st.get('progress_pct', 0)}%)"
                ),
                advance=done - prev_done,
            )
            prev_done = done
            if st.get("status") in ("completed", "failed", "cancelled"):
                break
            await asyncio.sleep(POLL_INTERVAL)

    # ── Fetch all pages for the final summary table ─────────────────────────
    PAGE_SIZE = 200
    all_scans: list[dict] = []
    page = 1
    while True:
        page_data = await _get(f"{base}/batch/{batch_id}?page={page}&page_size={PAGE_SIZE}")
        all_scans.extend(page_data.get("scans", []))
        if page >= page_data.get("total_pages", 1):
            break
        page += 1

    final_status   = page_data.get("status", "?")
    final_report   = page_data.get("report_path")

    # ── Summary table ─────────────────────────────────────────────────────────
    console.print()
    COLOR = {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}

    # For very large batches only show first 500 rows in terminal to avoid wall of text
    display_scans  = all_scans[:500]
    truncated      = len(all_scans) > 500

    tbl = Table(
        title=f"Batch Results — {batch_id[:8]}… ({len(all_scans)} URLs)",
        box=box.ROUNDED, show_lines=False,
    )
    tbl.add_column("#",       width=6,  justify="right")
    tbl.add_column("URL",     max_width=55, no_wrap=True)
    tbl.add_column("Verdict", width=13)
    tbl.add_column("Status",  width=11)
    for i, s in enumerate(display_scans, 1):
        v   = s.get("verdict") or "—"
        col = COLOR.get(v, "dim")
        tbl.add_row(str(i), s["url"], f"[{col}]{v}[/{col}]", s["status"])
    if truncated:
        tbl.add_row("[dim]…[/dim]",
                    f"[dim]… {len(all_scans)-500} more rows in report file[/dim]",
                    "", "")
    console.print(tbl)

    counts: dict[str, int] = {}
    for s in all_scans:
        v = s.get("verdict") or "UNKNOWN"
        counts[v] = counts.get(v, 0) + 1

    console.print(
        "\n  " + "  ".join(
            f"[{COLOR.get(k,'white')}]{k}: {v}[/{COLOR.get(k,'white')}]"
            for k, v in counts.items()
        )
    )
    console.print(f"\n  Batch ID   : [bold]{batch_id}[/bold]")
    console.print(f"  Status     : {final_status}")
    console.print(f"  URLs       : {len(all_scans)}")
    console.print(f"  Reports    → [bold]{Path(__file__).resolve().parent.parent / 'reports'}[/bold]")
    if final_report:
        console.print(f"  Main file  → [bold]{final_report}[/bold]")
    console.print(
        f"\n  Cancel     : [dim]python -m cli.client cancel-batch {batch_id}[/dim]"
    )


async def cmd_cancel_scan(args):
    """Cancel a single running or queued scan."""
    base = _server_url(args)
    data = await _post(f"{base}/scan/{args.scan_id}/cancel", {})
    console.print(f"\n[yellow]Cancel requested[/yellow] — {data.get('message')}")


async def cmd_cancel_batch(args):
    """Cancel all scans in a batch."""
    base = _server_url(args)
    data = await _post(f"{base}/batch/{args.batch_id}/cancel", {})
    console.print(
        f"\n[yellow]Batch cancelled[/yellow] — "
        f"{data.get('cancelled_scans', 0)} scan(s) stopped."
    )


# ── Command: admin ─────────────────────────────────────────────────────────────

async def cmd_admin_reload(args):
    base = _server_url(args)
    data = await _post(f"{base}/admin/reload-model", {})
    console.print(f"\n[green]Model reloaded.[/green]")
    console.print(f"  Version    : {data.get('version')}")
    console.print(f"  Trained at : {data.get('trained_at')}")
    console.print(f"  Samples    : {data.get('n_samples')}")


async def cmd_admin_stats(args):
    base = _server_url(args)
    data = await _get(f"{base}/admin/stats")
    console.print(f"\n[bold]Server Stats[/bold]")
    console.print(f"  Total scans    : {data.get('total_scans', 0)}")
    console.print(f"  Active model   : {data.get('active_model_version', 'none')}")
    statuses = data.get("statuses", {})
    if statuses:
        console.print(f"\n  [bold]By status:[/bold]")
        for s, count in statuses.items():
            console.print(f"    {s:<12}: {count}")
    verdicts = data.get("verdicts", {})
    if verdicts:
        console.print(f"\n  [bold]By verdict:[/bold]")
        COLOR = {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}
        for v, count in verdicts.items():
            col = COLOR.get(v, "white")
            console.print(f"    [{col}]{v:<12}[/{col}]: {count}")


async def cmd_admin_label(args):
    base = _server_url(args)
    data = await _post(
        f"{base}/admin/label/{args.scan_id}",
        {"label": args.label},
    )
    console.print(f"\n[green]Label saved.[/green] scan_id={data['scan_id']} label={data['label']}")


# ── Command: check-ollama ─────────────────────────────────────────────────────

async def cmd_check_ollama(args):
    """
    Diagnose Ollama: reachability, installed models, env var resolution,
    and an optional live test prompt to confirm both API endpoints work.
    Run this before using --llm to confirm everything is wired up correctly.
    """
    base = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    console.print(f"\n[bold]Ollama diagnostics[/bold]  ({base})\n")

    # 1. Reachability + model list
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{base}/api/tags")

        if r.status_code != 200:
            console.print(f"[red]✗ /api/tags returned HTTP {r.status_code}[/red]")
            console.print(f"  Response: {r.text[:300]}")
            return

        models = r.json().get("models", [])
        console.print("[green]✓ Ollama is reachable[/green]")

    except httpx.ConnectError:
        console.print("[red]✗ Cannot connect to Ollama.[/red]")
        console.print("  Start it with:  [bold]ollama serve[/bold]")
        console.print("  Install from:   https://ollama.com")
        return
    except Exception as e:
        console.print(f"[red]✗ Unexpected error: {e}[/red]")
        return

    # 2. Installed models
    if not models:
        console.print("[yellow]⚠ No models installed.[/yellow]")
        console.print("  Pull one:  [bold]ollama pull llama3[/bold]  or  ollama pull mistral")
        return

    console.print(f"[green]✓ {len(models)} model(s) installed:[/green]")
    for m in models:
        size_gb = m.get("size", 0) / 1e9
        console.print(f"  [cyan]{m['name']:<35}[/cyan] {size_gb:.1f} GB")

    # 3. OLLAMA_MODEL resolution
    env_model = os.getenv("OLLAMA_MODEL", "")
    model_names = [m["name"] for m in models]

    if env_model:
        exact  = env_model in model_names
        prefix = any(m.startswith(env_model.split(":")[0]) for m in model_names)
        if exact or prefix:
            resolved = env_model if exact else next(
                m for m in model_names if m.startswith(env_model.split(":")[0]))
            console.print(f"\n[green]✓ OLLAMA_MODEL={env_model!r} → resolved to {resolved!r}[/green]")
        else:
            console.print(f"\n[yellow]⚠ OLLAMA_MODEL={env_model!r} not found in installed models.[/yellow]")
            console.print(f"  Will fall back to: [cyan]{model_names[0]}[/cyan]")
    else:
        console.print(f"\n[dim]OLLAMA_MODEL not set → will auto-use: [cyan]{model_names[0]}[/cyan][/dim]")
        console.print(f"  Pin it with:  export OLLAMA_MODEL={model_names[0]!r}")

    # 4. Live test prompt
    if getattr(args, "test", False):
        target = env_model or model_names[0]
        # Resolve prefix
        for m in model_names:
            if m == target or m.startswith(target.split(":")[0]):
                target = m
                break

        console.print(f"\n[dim]Sending test prompt to [cyan]{target}[/cyan]…[/dim]")
        prompt_body_chat = {
            "model": target,
            "messages": [{"role": "user", "content": "Reply with exactly the word: OLLAMA_OK"}],
            "stream": False,
        }
        prompt_body_gen = {
            "model": target,
            "prompt": "Reply with exactly the word: OLLAMA_OK",
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            # Try /api/chat
            resp = await client.post(f"{base}/api/chat", json=prompt_body_chat)
            if resp.status_code == 200:
                reply = resp.json().get("message", {}).get("content", "").strip()
                console.print(f"[green]✓ /api/chat works[/green] → {reply[:120]!r}")
                console.print("\n[bold green]All checks passed. --llm is ready to use.[/bold green]")
                return
            else:
                console.print(f"[yellow]  /api/chat → {resp.status_code}: {resp.text[:200]}[/yellow]")

            # Try /api/generate
            resp2 = await client.post(f"{base}/api/generate", json=prompt_body_gen)
            if resp2.status_code == 200:
                reply = resp2.json().get("response", "").strip()
                console.print(f"[green]✓ /api/generate works[/green] → {reply[:120]!r}")
                console.print("\n[bold green]All checks passed. --llm is ready to use.[/bold green]")
            else:
                console.print(f"[red]✗ /api/generate → {resp2.status_code}: {resp2.text[:200]}[/red]")
                console.print("\n[bold red]Both endpoints failed. Check your Ollama version.[/bold red]")
    else:
        console.print("\n[dim]Run with --test to send a live prompt and verify both endpoints.[/dim]")
        console.print("[dim]Example:  python -m cli.client check-ollama --test[/dim]")


# ── Argument parser ────────────────────────────────────────────────────────────

def _fmt_list(s: str) -> list[str]:
    allowed = {"md", "txt", "pdf", "docx"}
    parts = [p.strip().lower() for p in s.split(",")]
    bad = [p for p in parts if p not in allowed]
    if bad:
        raise argparse.ArgumentTypeError(f"Unknown formats: {bad}. Choose from {allowed}")
    return parts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urlscan",
        description="URL threat scanner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single scan
  python -m cli.client scan https://suspicious-site.tk
  python -m cli.client scan https://example.com --llm --formats md,pdf

  # TXT batch (one URL per line)
  python -m cli.client batch urls.txt
  python -m cli.client batch urls.txt --formats pdf --save-csv

  # CSV batch — preview columns first, then scan
  python -m cli.client batch urls.csv --preview
  python -m cli.client batch urls.csv --column url
  python -m cli.client batch urls.csv --column 2
  python -m cli.client batch urls.csv --column link --delimiter ";"
  python -m cli.client batch urls.csv --column 0 --no-header

  # Admin
  python -m cli.client admin stats
  python -m cli.client admin reload
  python -m cli.client admin label <scan_id> malicious
        """,
    )
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help=f"Server base URL (default: {DEFAULT_SERVER})")

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Submit a URL for scanning")
    p_scan.add_argument("url", help="URL to scan")
    p_scan.add_argument("--llm", action="store_true",
                        help="Enhance report with local LLM (requires Ollama)")
    p_scan.add_argument("--formats", type=_fmt_list, metavar="FMT",
                        help="Comma-separated output formats: md,txt,pdf,docx (default: all)")
    p_scan.add_argument("--no-terminal", action="store_true",
                        help="Skip terminal report output")
    p_scan.add_argument("--async", dest="async_mode", action="store_true",
                        help="Return immediately without polling")

    # status
    p_status = sub.add_parser("status", help="Check scan status")
    p_status.add_argument("scan_id", help="Scan ID returned by `scan`")

    # report
    p_report = sub.add_parser("report", help="Regenerate report for a completed scan")
    p_report.add_argument("scan_id")
    p_report.add_argument("--llm", action="store_true")
    p_report.add_argument("--formats", type=_fmt_list, metavar="FMT")
    p_report.add_argument("--no-terminal", action="store_true")

    # batch
    p_batch = sub.add_parser(
        "batch",
        help="Scan URLs from a .txt or .csv file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Scan multiple URLs from a file.

TXT file  : one URL per line, lines starting with # are ignored.
CSV file  : use --column to specify which column holds the URL.
            Run with --preview first to see column names and indices.
        """,
    )
    p_batch.add_argument("file", help="Path to .txt or .csv file")
    p_batch.add_argument("--formats", type=_fmt_list, metavar="FMT",
                         help="Output formats for the consolidated report (default: md,txt,pdf,docx)")
    p_batch.add_argument("--llm", action="store_true",
                         help="Enhance the batch report with local LLM summary (requires Ollama)")
    p_batch.add_argument("--save-csv", dest="save_csv", action="store_true",
                         help="Save a CSV summary of all results to the reports folder")

    # CSV-specific options
    csv_group = p_batch.add_argument_group("CSV options")
    csv_group.add_argument("--csv", action="store_true",
                           help="Force CSV parsing even for non-.csv extensions")
    csv_group.add_argument("--column", default="url", metavar="COL",
                           help="Column name or 0-based index containing URLs (default: 'url')")
    csv_group.add_argument("--delimiter", default=",", metavar="CHAR",
                           help="CSV field delimiter (default: ','). Use ';' for semicolon-delimited files")
    csv_group.add_argument("--no-header", dest="no_header", action="store_true",
                           help="CSV has no header row — --column must be a numeric index")
    csv_group.add_argument("--preview", action="store_true",
                           help="Print the first 5 rows with column indices then exit (no scanning)")

    # cancel-scan
    p_cscan = sub.add_parser("cancel", help="Cancel a queued or running scan")
    p_cscan.add_argument("scan_id", help="Scan ID to cancel")

    # cancel-batch
    p_cbatch = sub.add_parser("cancel-batch", help="Cancel all scans in a batch")
    p_cbatch.add_argument("batch_id", help="Batch ID to cancel")

    # check-ollama
    p_ollama = sub.add_parser("check-ollama", help="Diagnose Ollama connectivity and models")
    p_ollama.add_argument("--test", action="store_true",
                          help="Send a live test prompt to confirm both endpoints work")

    # admin
    p_admin = sub.add_parser("admin", help="Admin commands")
    admin_sub = p_admin.add_subparsers(dest="admin_command", required=True)
    admin_sub.add_parser("reload", help="Hot-reload ML model artifacts")
    admin_sub.add_parser("stats",  help="Show server scan statistics")
    p_label = admin_sub.add_parser("label", help="Label a scan result for training feedback")
    p_label.add_argument("scan_id")
    p_label.add_argument("label", choices=["malicious", "benign"])

    return parser


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    parser = build_parser()
    args = parser.parse_args()

    handlers = {
        ("scan",         None):     cmd_scan,
        ("status",       None):     cmd_status,
        ("report",       None):     cmd_report,
        ("batch",        None):     cmd_batch,
        ("cancel",       None):     cmd_cancel_scan,
        ("cancel-batch",  None):     cmd_cancel_batch,
        ("check-ollama",  None):     cmd_check_ollama,
        ("admin",         "reload"): cmd_admin_reload,
        ("admin",        "stats"):  cmd_admin_stats,
        ("admin",        "label"):  cmd_admin_label,
    }

    key = (args.command, getattr(args, "admin_command", None))
    handler = handlers.get(key)
    if not handler:
        parser.print_help()
        sys.exit(1)

    try:
        await handler(args)
    except httpx.ConnectError:
        console.print(f"[red]Connection refused.[/red] Is the server running at {_server_url(args)}?")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        console.print(f"[red]Server error {e.response.status_code}:[/red] {e.response.text}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
