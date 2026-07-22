"""
cli/menu.py

PhishGuard — interactive option-based terminal menu.
Arrow-key or numbered selection, rich-coloured output.

Run:
    python -m cli.menu
    python -m cli.menu --server http://localhost:8000
"""

import asyncio
import csv
import json
import random
import sys
import time
from pathlib import Path

import httpx
import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

# ── Config ─────────────────────────────────────────────────────────────────────
DEFAULT_SERVER = "http://127.0.0.1:8000"
POLL_INTERVAL  = 2.0
POLL_TIMEOUT   = 120

console = Console()

# questionary style — matches dark theme
Q_STYLE = Style([
    ("qmark",        "fg:#2f81f7 bold"),
    ("question",     "fg:#e6edf3 bold"),
    ("answer",       "fg:#3fb950 bold"),
    ("pointer",      "fg:#2f81f7 bold"),
    ("highlighted",  "fg:#e6edf3 bg:#1c2d3f bold"),
    ("selected",     "fg:#3fb950"),
    ("separator",    "fg:#30363d"),
    ("instruction",  "fg:#7d8590"),
])

SERVER_URL = DEFAULT_SERVER   # mutable at runtime via Settings


# ── HTTP helpers ───────────────────────────────────────────────────────────────

async def _get(path: str, timeout: float = 10.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(f"{SERVER_URL}{path}")
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict, timeout: float = 120.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(f"{SERVER_URL}{path}", json=body)
        r.raise_for_status()
        return r.json()


async def _server_ok() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{SERVER_URL}/health")
            return r.status_code == 200
    except Exception:
        return False


# ── Display helpers ────────────────────────────────────────────────────────────

VERDICT_COLOR = {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}
VERDICT_EMOJI = {"SAFE": "✅", "SUSPICIOUS": "⚠️",  "MALICIOUS": "🚨"}


def _verdict_tag(v: str) -> str:
    c = VERDICT_COLOR.get(v, "dim")
    e = VERDICT_EMOJI.get(v, "❓")
    return f"[{c}]{e} {v}[/{c}]"


# ── Banners ────────────────────────────────────────────────────────────────────
# A rotating cast of ASCII banners for PHISHGUARD — one is picked at random
# each time the CLI starts, so the splash screen looks a little different
# every run.

_BANNER_BLOCKS = r"""
   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                  🛡  U R L   T H R E A T   S C A N N E R  🛡
""".strip("\n")

_BANNER_HACKER = r"""
   ┌──────────────────────────────────────────────────┐
   │  01001000 01000001 01000011 01001011  //  >_       │
   │                                                    │
   │        P H I S H G U A R D                         │
   │        ───────────────────                         │
   │        [ scanning URLs for threats... ]            │
   │                                                    │
   │  0x1F  0x00  0x97  0xFF  //  status: ARMED          │
   └──────────────────────────────────────────────────┘
""".strip("\n")

_BANNER_SHIELD = r"""
                  .--''''''--.
                .'            '.
               /   .--------.   \
              |   /   ◈  ◈   \   |
              |  |    GUARD   |  |
              |   \          /   |
               \   '--------'   /
                '.            .'
                  '---.  .---'
                       \/
        P H I S H G U A R D  —  URL Threat Scanner
""".strip("\n")

_BANNER_HOOK = r"""
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        __
       /  \        P H I S H G U A R D
       \  /        ------------------------
        )(         Catching bad links before
       /  \        they catch you.
      (    )___
       \__/    `--.___.--'
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
""".strip("\n")

_BANNER_RETRO = r"""
   *  .  *  .  *  .  *  .  *  .  *  .  *  .  *  .  *  .  *
        ★  P H I S H G U A R D  ★
        ══════════════════════════
        >>  Scan.  Detect.  Defend.  <<
   *  .  *  .  *  .  *  .  *  .  *  .  *  .  *  .  *  .  *
""".strip("\n")

_BANNER_DOOM = r"""
 ______ _   _ _____ _____ _   _ _____ _   _  ___  ____________ 
 | ___ \ | | |_   _/  ___| | | |  __ \ | | |/ _ \ | ___ \  _  \
 | |_/ / |_| | | | \ `--.| |_| | |  \/ | | / /_\ \| |_/ / | | |
 |  __/|  _  | | |  `--. \  _  | | __| | | |  _  ||    /| | | |
 | |   | | | |_| |_/\__/ / | | | |_\ \ |_| | | | || |\ \| |/ / 
 \_|   \_| |_/\___/\____/\_| |_/\____/\___/\_| |_/\_| \_|___/  
              🛡  U R L   T H R E A T   S C A N N E R  🛡
""".strip("\n")

_BANNER_SLANT = r"""
     ____  __  ___________ __  __________  _____    ____  ____ 
    / __ \/ / / /  _/ ___// / / / ____/ / / /   |  / __ \/ __ \
   / /_/ / /_/ // / \__ \/ /_/ / / __/ / / / /| | / /_/ / / / /
  / ____/ __  // / ___/ / __  / /_/ / /_/ / ___ |/ _, _/ /_/ / 
 /_/   /_/ /_/___//____/_/ /_/\____/\____/_/  |_/_/ |_/_____/  
              🛡  U R L   T H R E A T   S C A N N E R  🛡
""".strip("\n")

_BANNER_EYE = r"""
                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                  ▄▄██████████████████████████▄▄
              ▄▄██████████████████████████████████▄▄
           ▄██████████████                ██████████████▄
         ▄████████████       ╔════════════╗       ████████████▄
        ██████████           ║  ●  ●  ●   ║           ██████████
       █████████             ║    ◉◉◉◉◉   ║             █████████
       █████████             ║   ◉ ▓▓▓ ◉  ║             █████████
       █████████             ║    ◉◉◉◉◉   ║             █████████
        ██████████           ║  ●  ●  ●   ║           ██████████
         ▀████████████       ╚════════════╝       ████████████▀
           ▀██████████████                ██████████████▀
              ▀▀██████████████████████████████████▀▀
                  ▀▀██████████████████████████▀▀
                       ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

     [ TARGET : incoming URL ]        [ STATUS : SCANNING... ]
     [ ENGINE : PHISHGUARD   ]        [ THREAT : ANALYZING…  ]

   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
""".strip("\n")

_BANNER_RADIAL = r"""
                                  .   .   .
                              .   .   .   .   .
                           .   .   .   .   .   .
                        .    . .  ●●●●●  . .    .
                      .   .  . ●●●●●●●●●●● .  .   .
                     .  .  ●●●●●●     ●●●●●●  .  .
                    .  . ●●●●●    ◯◯◯    ●●●●● .  .
                    .  . ●●●●●    ◯◯◯    ●●●●● .  .
                     .  .  ●●●●●●     ●●●●●●  .  .
                      .   .  . ●●●●●●●●●●● .  .   .
                        .    . .  ●●●●●  . .    .
                           .   .   .   .   .   .
                              .   .   .   .   .
                                  .   .   .

   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                        N O . 0 0 1  ·  U R L   S C A N   S E R I E S
""".strip("\n")

BANNERS = [
    (_BANNER_BLOCKS,  "bold #2f81f7"),
    (_BANNER_HACKER,  "bold #2f81f7"),
    (_BANNER_SHIELD,  "bold #2f81f7"),
    (_BANNER_HOOK,    "bold #2f81f7"),
    (_BANNER_RETRO,   "bold #2f81f7"),
    (_BANNER_DOOM,    "bold #2f81f7"),
    (_BANNER_SLANT,   "bold #2f81f7"),
    (_BANNER_EYE,     "bold #39ff14"),
    (_BANNER_RADIAL,  "bold #c9d1d9"),
]


def _header():
    console.print()
    text, style = random.choice(BANNERS)
    console.print(Text(text, style=style))
    console.print(Panel(
        f"[dim]Server: {SERVER_URL}[/dim]",
        border_style="#30363d",
        padding=(0, 2),
    ))


def _section(title: str):
    console.print(f"\n[bold #2f81f7]── {title} ──[/bold #2f81f7]\n")


def _ok(msg: str):    console.print(f"[green]✓[/green]  {msg}")
def _err(msg: str):   console.print(f"[red]✗[/red]  {msg}")
def _info(msg: str):  console.print(f"[dim]•[/dim]  {msg}")
def _warn(msg: str):  console.print(f"[yellow]⚠[/yellow]  {msg}")


def _divider():
    console.print("[dim]" + "─" * 60 + "[/dim]")


# ── Polling spinner ────────────────────────────────────────────────────────────

async def _poll_scan(scan_id: str) -> dict | None:
    from rich.live import Live
    from rich.spinner import Spinner

    deadline = time.time() + POLL_TIMEOUT
    with Live(console=console, refresh_per_second=4) as live:
        while time.time() < deadline:
            await asyncio.sleep(POLL_INTERVAL)
            try:
                data = await _get(f"/scan/{scan_id}")
                status = data.get("status", "")
                live.update(
                    f"[dim]  [/dim][yellow]{status}[/yellow][dim] …  scan {scan_id[:8]}[/dim]"
                )
                if status == "completed":
                    return data
                if status in ("failed", "cancelled"):
                    return data
            except Exception as e:
                live.update(f"[dim]  polling…  ({e})[/dim]")

    _warn("Timed out. Use 'Check Status' to poll later.")
    return None


async def _poll_batch(batch_id: str, total: int) -> dict | None:
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    deadline = time.time() + POLL_TIMEOUT * max(1, total // 10 + 1)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as progress:
        task = progress.add_task(f"Batch scanning {total} URLs…", total=total)
        prev = 0
        while time.time() < deadline:
            await asyncio.sleep(2.5)
            try:
                st = await _get(f"/batch/{batch_id}?page_size=1")
                done = st.get("completed", 0) + st.get("failed", 0)
                progress.update(
                    task,
                    description=f"[bold]{done}/{total}[/bold] done ({st.get('progress_pct',0)}%)",
                    advance=done - prev,
                )
                prev = done
                if st.get("status") in ("completed", "failed", "cancelled"):
                    return st
            except Exception:
                pass
    return None


# ── Scan result display ────────────────────────────────────────────────────────

def _show_scan_result(data: dict):
    result  = data.get("result") or {}
    verdict = result.get("verdict", {})
    v       = verdict.get("verdict", "UNKNOWN")
    conf    = verdict.get("confidence", "?")
    color   = VERDICT_COLOR.get(v, "dim")
    emoji   = VERDICT_EMOJI.get(v, "❓")

    console.print()
    console.print(Panel(
        f"[bold {color}]{emoji}  {v}[/bold {color}]   [dim]confidence: {conf}[/dim]\n"
        f"[dim]{data.get('url','')}[/dim]",
        border_style=color,
        padding=(0, 2),
    ))

    # Signals
    reasons = verdict.get("reasons", [])
    if reasons:
        console.print("[bold]Signals:[/bold]")
        for r in reasons:
            console.print(f"  • {r}")

    # ML
    ml = result.get("ml", {})
    if ml.get("available"):
        console.print(
            f"\n[bold]ML:[/bold]  K-means [cyan]{ml.get('kmeans',{}).get('anomaly_score',0):.3f}[/cyan]  "
            f"SOM [cyan]{ml.get('som',{}).get('anomaly_score',0):.3f}[/cyan]  "
            f"Combined [cyan]{ml.get('combined_score',0):.3f}[/cyan]  "
            f"{'[green]agree[/green]' if ml.get('models_agree') else '[yellow]disagree[/yellow]'}"
        )

    # External APIs in a table
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    tbl.add_column("Source",  width=18)
    tbl.add_column("Result")
    tbl.add_column("Detail",  max_width=44)

    vt = result.get("virustotal", {})
    if vt.get("available"):
        mal = vt.get("malicious", 0)
        tbl.add_row(
            "VirusTotal",
            f"[red]{mal} malicious[/red]" if mal else "[green]clean[/green]",
            f"{vt.get('suspicious',0)} suspicious  {vt.get('harmless',0)} harmless",
        )

    gsb = result.get("safe_browsing", {})
    if gsb.get("available"):
        tbl.add_row(
            "Safe Browsing",
            f"[red]THREAT[/red]" if gsb.get("is_threat") else "[green]clean[/green]",
            ", ".join(gsb.get("threat_types", [])) or "—",
        )

    uh_url = result.get("urlhaus", {}).get("url_lookup", {})
    if uh_url.get("available"):
        if uh_url.get("found"):
            tbl.add_row(
                "URLhaus",
                f"[red]LISTED ({uh_url.get('url_status','?')})[/red]",
                f"{uh_url.get('threat','?')}  tags: {', '.join(uh_url.get('tags',[])[:3])}",
            )
        else:
            tbl.add_row("URLhaus", "[green]clean[/green]", "not in database")

    w = result.get("whois", {})
    if w.get("available") and not w.get("is_ip_host"):
        age = w.get("age_days")
        age_str = f"{age}d" if age is not None else "?"
        flag = " [red]⚑ NEW[/red]" if w.get("is_new_domain") else ""
        tbl.add_row(
            "WHOIS",
            f"age: {age_str}{flag}",
            f"{w.get('registrar','?')}  {w.get('country','?')}",
        )

    console.print()
    console.print(tbl)
    console.print(f"\n[dim]Scan ID: {data.get('scan_id','?')}[/dim]")


# ════════════════════════════════════════════════════════════════════════════════
# ── Menu handlers ──────────────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════════════

# ── 1. Scan URL ────────────────────────────────────────────────────────────────

async def menu_scan():
    _section("Scan URL")

    url = await questionary.text(
        "URL to scan:",
        validate=lambda v: True if v.strip() else "Enter a URL",
        style=Q_STYLE,
    ).ask_async()
    if not url:
        return

    use_llm = await questionary.confirm(
        "Enable LLM enhancement? (requires Ollama)",
        default=False,
        style=Q_STYLE,
    ).ask_async()

    wait = await questionary.confirm(
        "Wait for result now?",
        default=True,
        style=Q_STYLE,
    ).ask_async()

    console.print()
    try:
        sub = await _post("/scan", {"url": url.strip(), "use_llm": bool(use_llm)})
        scan_id = sub["scan_id"]
        _ok(f"Queued  [dim]{scan_id}[/dim]")
    except Exception as e:
        _err(f"Submit failed: {e}")
        return

    if not wait:
        _info(f"Check status later with scan ID: [cyan]{scan_id}[/cyan]")
        return

    result_data = await _poll_scan(scan_id)
    if result_data:
        status = result_data.get("status")
        if status == "completed":
            _show_scan_result({**result_data, "url": url})
        elif status == "failed":
            _err(f"Scan failed: {result_data.get('error','?')}")
        elif status == "cancelled":
            _warn("Scan was cancelled.")


# ── 2. Check Status ────────────────────────────────────────────────────────────

async def menu_status():
    _section("Check Scan Status")

    scan_id = await questionary.text(
        "Scan ID:",
        validate=lambda v: True if v.strip() else "Enter a scan ID",
        style=Q_STYLE,
    ).ask_async()
    if not scan_id:
        return

    try:
        data = await _get(f"/scan/{scan_id.strip()}")
    except Exception as e:
        _err(f"Error: {e}")
        return

    status = data.get("status", "?")
    status_color = {
        "completed": "green", "failed": "red",
        "scanning": "yellow", "queued": "dim",
    }.get(status, "white")

    console.print(f"\n  Status  : [{status_color}]{status}[/{status_color}]")
    console.print(f"  URL     : {data.get('url','?')}")
    console.print(f"  Created : {data.get('created_at','?')}")

    if status == "completed" and data.get("result"):
        show_full = await questionary.confirm(
            "Show full result?", default=True, style=Q_STYLE
        ).ask_async()
        if show_full:
            _show_scan_result({**data, "url": data.get("url", "")})
    elif status == "failed":
        _err(f"Error: {data.get('error','?')}")

    if status in ("queued", "scanning"):
        wait = await questionary.confirm(
            "Wait for completion?", default=False, style=Q_STYLE
        ).ask_async()
        if wait:
            result_data = await _poll_scan(scan_id.strip())
            if result_data and result_data.get("status") == "completed":
                _show_scan_result({**result_data, "url": data.get("url","")})


# ── 3. Cancel Scan ────────────────────────────────────────────────────────────

async def menu_cancel():
    _section("Cancel Scan")

    choice = await questionary.select(
        "Cancel what?",
        choices=[
            "Single scan (by scan ID)",
            "Entire batch (by batch ID)",
            "← Back",
        ],
        style=Q_STYLE,
    ).ask_async()

    if not choice or choice == "← Back":
        return

    if "Single" in choice:
        scan_id = await questionary.text("Scan ID to cancel:", style=Q_STYLE).ask_async()
        if not scan_id:
            return
        try:
            r = await _post(f"/scan/{scan_id.strip()}/cancel", {})
            _ok(r.get("message", "Cancelled"))
        except Exception as e:
            _err(str(e))

    elif "batch" in choice:
        batch_id = await questionary.text("Batch ID to cancel:", style=Q_STYLE).ask_async()
        if not batch_id:
            return
        try:
            r = await _post(f"/batch/{batch_id.strip()}/cancel", {})
            _ok(f"Cancelled {r.get('cancelled_scans', 0)} scan(s)")
        except Exception as e:
            _err(str(e))


# ── 4. Batch Scan ─────────────────────────────────────────────────────────────

async def menu_batch():
    _section("Batch Scan")

    file_path = await questionary.path(
        "File path (.txt or .csv):",
        validate=lambda v: Path(v).exists() or "File not found",
        style=Q_STYLE,
    ).ask_async()
    if not file_path:
        return

    p = Path(file_path)
    column, delimiter = "url", ","

    if p.suffix.lower() == ".csv":
        # Peek at headers
        try:
            with open(p, newline="", encoding="utf-8") as f:
                headers = next(csv.reader(f))
            _info(f"CSV headers: {headers}")
        except Exception:
            headers = []

        column = await questionary.text(
            "URL column name:",
            default="url",
            style=Q_STYLE,
        ).ask_async() or "url"

        delimiter = await questionary.select(
            "Delimiter:",
            choices=[("Comma  ( , )", ","), ("Semicolon  ( ; )", ";"), ("Tab", "\t")],
            style=Q_STYLE,
        ).ask_async() or ","

    use_llm = await questionary.confirm(
        "Enable LLM enhancement?", default=False, style=Q_STYLE
    ).ask_async()

    # Read + deduplicate
    console.print()
    _info(f"Reading {p.name}…")
    urls: list[str] = []
    try:
        if p.suffix.lower() == ".csv":
            with open(p, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                if column not in (reader.fieldnames or []):
                    _err(f"Column '{column}' not found. Headers: {reader.fieldnames}")
                    return
                for row in reader:
                    v = row.get(column, "").strip()
                    if v:
                        urls.append(v)
        else:
            urls = [
                l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")
            ]
    except Exception as e:
        _err(f"Read error: {e}")
        return

    seen, unique, dupes = set(), [], 0
    for u in urls:
        if u not in seen:
            seen.add(u); unique.append(u)
        else:
            dupes += 1

    _ok(f"{len(unique)} unique URLs loaded" + (f"  ({dupes} dupes skipped)" if dupes else ""))

    if not await questionary.confirm(f"Submit {len(unique)} URLs as one batch?", style=Q_STYLE).ask_async():
        return

    console.print()
    try:
        data = await _post("/batch", {"urls": unique, "use_llm": bool(use_llm)})
        batch_id = data["batch_id"]
        total    = data["total_urls"]
        _ok(f"Batch submitted  [dim]{batch_id}[/dim]  ({total} URLs)")
    except Exception as e:
        _err(f"Submit failed: {e}")
        return

    wait = await questionary.confirm("Wait for completion?", default=True, style=Q_STYLE).ask_async()
    if not wait:
        _info(f"Batch ID: [cyan]{batch_id}[/cyan]")
        return

    st = await _poll_batch(batch_id, total)
    if st:
        _ok(f"Batch complete — status: [bold]{st.get('status')}[/bold]")
        console.print(
            f"  Completed: [green]{st.get('completed',0)}[/green]  "
            f"Failed: [red]{st.get('failed',0)}[/red]"
        )
        console.print(f"  [dim]Report → reports/batch_{batch_id[:8]}…[/dim]")


# ── 5. Scan History ────────────────────────────────────────────────────────────

async def menu_history():
    _section("Scan History")

    # Filters
    limit = await questionary.select(
        "Show last:",
        choices=["20", "50", "100", "200"],
        default="50",
        style=Q_STYLE,
    ).ask_async() or "50"

    verdict_filter = await questionary.select(
        "Filter by verdict:",
        choices=["All", "SAFE", "SUSPICIOUS", "MALICIOUS"],
        default="All",
        style=Q_STYLE,
    ).ask_async() or "All"

    search = await questionary.text(
        "Filter by URL (leave empty for all):",
        default="",
        style=Q_STYLE,
    ).ask_async() or ""

    try:
        data = await _get(f"/admin/scans?limit={limit}")
        scans = data.get("scans", [])
    except Exception as e:
        _err(f"Failed to load history: {e}")
        return

    # Filter
    if verdict_filter != "All":
        scans = [s for s in scans if s.get("verdict") == verdict_filter]
    if search:
        scans = [s for s in scans if search.lower() in s.get("url", "").lower()]

    if not scans:
        _warn("No scans match your filters.")
        return

    # Display table
    console.print()
    tbl = Table(box=box.ROUNDED, show_lines=False, header_style="bold dim")
    tbl.add_column("#",          width=4,  justify="right")
    tbl.add_column("URL",        max_width=50, no_wrap=True)
    tbl.add_column("Verdict",    width=13)
    tbl.add_column("Confidence", width=10)
    tbl.add_column("Status",     width=10)
    tbl.add_column("When",       width=12)

    for i, s in enumerate(scans, 1):
        v   = s.get("verdict") or "—"
        col = VERDICT_COLOR.get(v, "dim")
        tbl.add_row(
            str(i),
            s.get("url", "")[:50],
            f"[{col}]{VERDICT_EMOJI.get(v,'❓')} {v}[/{col}]",
            s.get("confidence") or "—",
            s.get("status") or "—",
            (s.get("created_at") or "")[:16],
        )

    console.print(tbl)
    console.print(f"[dim]  Showing {len(scans)} scan(s)[/dim]")

    # Drill into a scan
    if await questionary.confirm("View detail for a scan?", default=False, style=Q_STYLE).ask_async():
        num = await questionary.text(
            f"Enter row number (1–{len(scans)}):",
            validate=lambda v: v.isdigit() and 1 <= int(v) <= len(scans) or "Invalid",
            style=Q_STYLE,
        ).ask_async()
        if num:
            chosen = scans[int(num) - 1]
            try:
                detail = await _get(f"/scan/{chosen['scan_id']}")
                _show_scan_result({**detail, "url": chosen.get("url","")})
            except Exception as e:
                _err(str(e))


# ── 6. Generate Report ─────────────────────────────────────────────────────────

async def menu_report():
    _section("Generate Report")

    scan_id = await questionary.text(
        "Scan ID:",
        validate=lambda v: True if v.strip() else "Enter a scan ID",
        style=Q_STYLE,
    ).ask_async()
    if not scan_id:
        return

    fmt = await questionary.checkbox(
        "Report formats:",
        choices=[
            questionary.Choice("md", checked=True),
            questionary.Choice("txt", checked=True),
            questionary.Choice("pdf"),
            questionary.Choice("docx"),
        ],
        style=Q_STYLE,
    ).ask_async() or ["md", "txt"]

    use_llm = await questionary.confirm(
        "Add LLM summary?", default=False, style=Q_STYLE
    ).ask_async()

    try:
        detail = await _get(f"/scan/{scan_id.strip()}")
    except Exception as e:
        _err(str(e))
        return

    if detail.get("status") != "completed":
        _warn(f"Scan status is '{detail.get('status')}' — not completed yet.")
        return

    # Import report generator
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from report.generator import generate_report

    result = detail.get("result") or {}
    if use_llm:
        result["use_llm"] = True

    console.print()
    saved = await generate_report(
        scan_id=scan_id.strip(),
        result=result,
        formats=fmt,
        show_terminal=True,
    )
    if saved:
        _ok("Report saved:")
        for f, p in saved.items():
            console.print(f"  [dim]{f.upper()}[/dim] → {p}")


# ── 7. Train Model ─────────────────────────────────────────────────────────────

async def menu_train():
    _section("Train Model")

    source = await questionary.select(
        "Training data source:",
        choices=[
            "DB — use accumulated scan vectors",
            "CSV — URL column (features extracted automatically)",
            "CSV — pre-computed feature columns",
            "TXT — batch URL list (one URL per line)",
        ],
        style=Q_STYLE,
    ).ask_async()

    if not source:
        return

    cmd = [sys.executable, "-m", "training.train"]

    if source.startswith("TXT"):
        txt_path = await questionary.path(
            "TXT file path (one URL per line):",
            validate=lambda v: Path(v).exists() or "File not found",
            style=Q_STYLE,
        ).ask_async()
        if not txt_path:
            return

        txt_file = Path(txt_path)
        try:
            raw_text = txt_file.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            # Fall back for files saved by Excel/Notepad in a Windows codepage
            # instead of UTF-8, which is the common source of codec errors.
            raw_text = txt_file.read_text(encoding="cp1252", errors="replace")
            _warn("File wasn't UTF-8 — re-read using Windows-1252 (cp1252) fallback. "
                  "Some characters may have been replaced.")

        urls = list(dict.fromkeys(
            line.strip() for line in raw_text.splitlines() if line.strip()
        ))
        if not urls:
            _err("No URLs found in file.")
            return
        _info(f"Found {len(urls)} unique URL(s).")

        # Reuse the existing CSV + URL-column training path by writing the
        # URL list out to a temporary single-column CSV.
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8", newline=""
        )
        writer = csv.writer(tmp)
        writer.writerow(["url"])
        for u in urls:
            writer.writerow([u])
        tmp.close()

        cmd += ["--csv", tmp.name, "--url-column", "url"]
        if await questionary.confirm("Save extracted vectors to DB (--save-to-db)?",
                               default=True, style=Q_STYLE).ask_async():
            cmd.append("--save-to-db")

    elif "CSV" in source:
        csv_path = await questionary.path(
            "CSV file path:",
            validate=lambda v: Path(v).exists() or "File not found",
            style=Q_STYLE,
        ).ask_async()
        if not csv_path:
            return

        if "URL column" in source:
            col = await questionary.text("URL column name:", default="url", style=Q_STYLE).ask_async() or "url"
            cmd += ["--csv", csv_path, "--url-column", col]
            if await questionary.confirm("Save extracted vectors to DB (--save-to-db)?",
                                   default=True, style=Q_STYLE).ask_async():
                cmd.append("--save-to-db")
        else:
            cmd += ["--csv", csv_path, "--all-features"]

    min_samples = await questionary.text(
        "Minimum samples required:", default="10", style=Q_STYLE
    ).ask_async() or "10"
    cmd += ["--min-samples", min_samples]

    console.print(f"\n[dim]Command: {' '.join(cmd)}[/dim]\n")
    if not await questionary.confirm("Start training?", default=True, style=Q_STYLE).ask_async():
        return

    # Run training as subprocess (streams output live)
    import asyncio as _asyncio
    import os as _os
    # Force the child process to emit UTF-8 on stdout regardless of the
    # Windows console codepage (cp1252 etc.), which is what caused the
    # 'utf-8' codec can't decode byte ... crash — the child was printing
    # characters (e.g. an em dash) that aren't valid UTF-8 in its native
    # codepage, and we were decoding strictly as UTF-8 on the read side.
    train_env = _os.environ.copy()
    train_env["PYTHONIOENCODING"] = "utf-8"
    proc = await _asyncio.create_subprocess_exec(
        *cmd,
        stdout=_asyncio.subprocess.PIPE,
        stderr=_asyncio.subprocess.STDOUT,
        env=train_env,
    )
    async for line in proc.stdout:
        console.print(line.decode("utf-8", errors="replace").rstrip())
    await proc.wait()

    if proc.returncode == 0:
        _ok("Training complete!")
        if await questionary.confirm("Hot-reload the new model now?", default=True, style=Q_STYLE).ask_async():
            try:
                r = await _post("/admin/reload-model", {})
                _ok(f"Model reloaded — version [cyan]{r.get('version')}[/cyan]  "
                    f"({r.get('n_samples')} samples)")
            except Exception as e:
                _err(f"Reload failed: {e}")
    else:
        _err(f"Training failed with exit code {proc.returncode}")


# ── 8. Admin ───────────────────────────────────────────────────────────────────

async def menu_admin():
    while True:
        _section("Admin")

        action = await questionary.select(
            "Choose action:",
            choices=[
                "📊  Server stats",
                "↺   Reload ML model",
                "🏷   Label a scan (malicious / benign)",
                "✅  Check Ollama (LLM diagnostics)",
                "← Back",
            ],
            style=Q_STYLE,
        ).ask_async()

        if not action or "Back" in action:
            break

        elif "stats" in action:
            try:
                d = await _get("/admin/stats")
                v = d.get("verdicts", {})
                console.print()
                tbl = Table(box=box.SIMPLE, show_header=False)
                tbl.add_column("Field", style="bold dim", width=20)
                tbl.add_column("Value")
                tbl.add_row("Total scans",    str(d.get("total_scans", 0)))
                tbl.add_row("Active model",   str(d.get("active_model_version", "none")))
                tbl.add_row("Safe",           f"[green]{v.get('SAFE',0)}[/green]")
                tbl.add_row("Suspicious",     f"[yellow]{v.get('SUSPICIOUS',0)}[/yellow]")
                tbl.add_row("Malicious",      f"[red]{v.get('MALICIOUS',0)}[/red]")
                for s, cnt in d.get("statuses", {}).items():
                    tbl.add_row(f"  [{s}]", str(cnt))
                console.print(tbl)
            except Exception as e:
                _err(str(e))

        elif "Reload" in action:
            try:
                r = await _post("/admin/reload-model", {})
                _ok(f"Reloaded — version [cyan]{r.get('version')}[/cyan]  "
                    f"({r.get('n_samples')} samples, trained {r.get('trained_at','')})")
            except Exception as e:
                _err(f"Reload failed: {e}")

        elif "Label" in action:
            scan_id = await questionary.text("Scan ID to label:", style=Q_STYLE).ask_async()
            if not scan_id:
                continue
            label = await questionary.select(
                "Label:",
                choices=["malicious", "benign"],
                style=Q_STYLE,
            ).ask_async()
            if not label:
                continue
            try:
                await _post(f"/admin/label/{scan_id.strip()}", {"label": label})
                _ok(f"Labelled [cyan]{scan_id[:12]}[/cyan] as [bold]{label}[/bold]")
            except Exception as e:
                _err(str(e))

        elif "Ollama" in action:
            await _check_ollama()

        _divider()


async def _check_ollama():
    base = "http://localhost:11434"
    _info(f"Checking Ollama at {base}…")
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{base}/api/tags")
        if r.status_code != 200:
            _err(f"/api/tags returned HTTP {r.status_code}")
            return
        models = r.json().get("models", [])
        _ok(f"Ollama reachable — {len(models)} model(s) installed")
        for m in models:
            size_gb = m.get("size", 0) / 1e9
            console.print(f"  [cyan]{m['name']:<35}[/cyan] {size_gb:.1f} GB")

        if not models:
            _warn("No models. Pull one:  ollama pull llama3")
            return

        test = await questionary.confirm("Send a test prompt?", default=False, style=Q_STYLE).ask_async()
        if test:
            model = models[0]["name"]
            _info(f"Testing {model}…")
            async with httpx.AsyncClient(timeout=30) as c:
                r2 = await c.post(f"{base}/api/chat", json={
                    "model": model,
                    "messages": [{"role":"user","content":"Reply with: OLLAMA_OK"}],
                    "stream": False,
                })
            if r2.status_code == 200:
                reply = r2.json().get("message",{}).get("content","").strip()
                _ok(f"/api/chat works → {reply[:80]!r}")
            else:
                _err(f"/api/chat returned {r2.status_code}: {r2.text[:150]}")
    except httpx.ConnectError:
        _err("Cannot connect. Start Ollama:  ollama serve")


# ── 9. Settings ────────────────────────────────────────────────────────────────

async def menu_settings():
    global SERVER_URL
    _section("Settings")

    new_url = await questionary.text(
        "Server URL:",
        default=SERVER_URL,
        style=Q_STYLE,
    ).ask_async()

    if new_url and new_url.strip():
        old = SERVER_URL
        SERVER_URL = new_url.strip().rstrip("/")
        ok = await _server_ok()
        if ok:
            _ok(f"Connected to {SERVER_URL}")
        else:
            _warn(f"Server at {SERVER_URL} not reachable (set anyway)")


# ════════════════════════════════════════════════════════════════════════════════
# ── Main menu loop ─────────────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════════════

MENU_CHOICES = [
    ("🔍  Scan URL",             menu_scan),
    ("📋  Check Scan Status",    menu_status),
    ("✕   Cancel Scan / Batch",  menu_cancel),
    ("📦  Batch Scan",           menu_batch),
    ("🕑  Scan History",         menu_history),
    ("📄  Generate Report",      menu_report),
    ("🧠  Train Model",          menu_train),
    ("⚙️   Admin",               menu_admin),
    ("🔧  Settings",             menu_settings),
    ("❌  Exit",                 None),
]


async def run(server: str = DEFAULT_SERVER):
    global SERVER_URL
    SERVER_URL = server

    # Check server on start
    _header()
    ok = await _server_ok()
    if ok:
        _ok(f"Connected to [cyan]{SERVER_URL}[/cyan]")
    else:
        _warn(f"Server not reachable at [cyan]{SERVER_URL}[/cyan]")
        _info("Start the server:  uvicorn server.main:app --port 8000")

    while True:
        console.print()
        _divider()

        choice = await questionary.select(
            "Main Menu — choose an option:",
            choices=[label for label, _ in MENU_CHOICES],
            style=Q_STYLE,
            use_shortcuts=False,
        ).ask_async()

        if not choice:
            break

        handler = next((h for label, h in MENU_CHOICES if label == choice), None)

        if handler is None:   # Exit
            console.print("\n[dim]Goodbye.[/dim]\n")
            break

        if not await _server_ok() and choice not in (
            "🧠  Train Model", "🔧  Settings", "📄  Generate Report"
        ):
            _err("Server not reachable. Start with:  uvicorn server.main:app --port 8000")
            if not await questionary.confirm("Try anyway?", default=False, style=Q_STYLE).ask_async():
                continue

        try:
            await handler()
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted.[/dim]")
        except Exception as e:
            _err(f"Unexpected error: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PhishGuard interactive terminal menu")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help=f"Server URL (default: {DEFAULT_SERVER})")
    args = parser.parse_args()

    try:
        asyncio.run(run(server=args.server))
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/dim]\n")


if __name__ == "__main__":
    main()