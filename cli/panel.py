"""
cli/panel.py

PhishGuard interactive terminal panel.
Full TUI built with Textual — controls everything from one screen.

Run:
    python -m cli.panel
    python -m cli.panel --server http://localhost:8000

Navigation:
    Tab / Shift+Tab  — move between panels
    Arrow keys       — navigate lists
    Enter            — select / confirm
    Escape           — go back / cancel
    Ctrl+C / Q       — quit
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label,
    ListItem, ListView, LoadingIndicator, ProgressBar,
    RichLog, Rule, Select, Static, Switch, TabbedContent,
    TabPane,
)

DEFAULT_SERVER = "http://127.0.0.1:8000"


# ── HTTP helpers ───────────────────────────────────────────────────────────────

async def _get(base: str, path: str, timeout: float = 10.0):
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(f"{base}{path}")
        r.raise_for_status()
        return r.json()


async def _post(base: str, path: str, body: dict, timeout: float = 120.0):
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(f"{base}{path}", json=body)
        r.raise_for_status()
        return r.json()


async def _server_ok(base: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{base}/health")
            return r.status_code == 200
    except Exception:
        return False


# ── Verdict colour helper ──────────────────────────────────────────────────────

def _verdict_color(verdict: str) -> str:
    return {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}.get(verdict or "", "dim")


def _verdict_emoji(verdict: str) -> str:
    return {"SAFE": "✅", "SUSPICIOUS": "⚠️", "MALICIOUS": "🚨"}.get(verdict or "", "❓")


# ── Confirm modal ──────────────────────────────────────────────────────────────

class ConfirmModal(ModalScreen):
    """A simple yes/no confirmation dialog."""
    DEFAULT_CSS = """
    ConfirmModal { align: center middle; }
    ConfirmModal > Container {
        width: 50; height: auto; padding: 2 4;
        background: $surface; border: solid $accent;
    }
    ConfirmModal Label { width: 100%; text-align: center; margin-bottom: 1; }
    ConfirmModal Horizontal { align: center middle; height: 3; }
    ConfirmModal Button { margin: 0 2; }
    """

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Container():
            yield Label(self.message)
            with Horizontal():
                yield Button("Yes", id="yes", variant="error")
                yield Button("No",  id="no",  variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(event.button.id == "yes")


# ── Scan result modal ──────────────────────────────────────────────────────────

class ScanResultModal(ModalScreen):
    DEFAULT_CSS = """
    ScanResultModal { align: center middle; }
    ScanResultModal > ScrollableContainer {
        width: 90; max-height: 40; padding: 2 3;
        background: $surface; border: solid $accent;
    }
    ScanResultModal Button { margin-top: 1; }
    """

    def __init__(self, scan_data: dict):
        super().__init__()
        self.scan_data = scan_data

    def compose(self) -> ComposeResult:
        result = self.scan_data.get("result") or {}
        verdict = result.get("verdict", {})
        v = verdict.get("verdict", "UNKNOWN")
        conf = verdict.get("confidence", "?")
        reasons = verdict.get("reasons", [])
        ml = result.get("ml", {})
        vt = result.get("virustotal", {})
        gsb = result.get("safe_browsing", {})
        uh = result.get("urlhaus", {})
        whois = result.get("whois", {})
        color = _verdict_color(v)
        emoji = _verdict_emoji(v)

        lines = [
            f"[bold]{emoji} {v}[/bold]  [{color}]confidence: {conf}[/{color}]",
            f"[dim]URL: {self.scan_data.get('url', '')}[/dim]",
            "",
            "[bold]Signals:[/bold]",
        ]
        for r in reasons:
            lines.append(f"  • {r}")

        if ml.get("available"):
            lines += [
                "",
                f"[bold]ML Scores:[/bold]  K-means {ml.get('kmeans',{}).get('anomaly_score',0):.3f}  "
                f"SOM {ml.get('som',{}).get('anomaly_score',0):.3f}  "
                f"Combined {ml.get('combined_score',0):.3f}  "
                f"{'[green]agree[/green]' if ml.get('models_agree') else '[yellow]disagree[/yellow]'}",
            ]

        if vt.get("available"):
            lines.append(
                f"[bold]VirusTotal:[/bold]  {vt.get('malicious',0)} malicious  "
                f"{vt.get('suspicious',0)} suspicious  {vt.get('harmless',0)} harmless"
            )

        if gsb.get("available"):
            gsb_str = f"[red]THREAT: {', '.join(gsb.get('threat_types',[]))}[/red]" \
                      if gsb.get("is_threat") else "[green]clean[/green]"
            lines.append(f"[bold]Safe Browsing:[/bold]  {gsb_str}")

        uh_url = (uh or {}).get("url_lookup", {})
        if uh_url.get("available") and uh_url.get("found"):
            lines.append(
                f"[bold]URLhaus:[/bold]  [red]LISTED[/red] — {uh_url.get('threat','?')}  "
                f"status: {uh_url.get('url_status','?')}  "
                f"tags: {', '.join(uh_url.get('tags',[])[:3])}"
            )

        if whois.get("available") and not whois.get("is_ip_host"):
            age = whois.get("age_days")
            age_str = f"{age} days" if age is not None else "unknown"
            age_flag = " [red]⚑ NEW[/red]" if whois.get("is_new_domain") else ""
            lines.append(
                f"[bold]WHOIS:[/bold]  {whois.get('domain','?')}  "
                f"age: {age_str}{age_flag}  "
                f"registrar: {whois.get('registrar','?')}"
            )

        with ScrollableContainer():
            yield Static("\n".join(lines))
            yield Rule()
            with Horizontal():
                yield Button("Close", id="close", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss()


# ── Main App ───────────────────────────────────────────────────────────────────

class PhishGuardPanel(App):
    """PhishGuard interactive terminal control panel."""

    TITLE   = "PhishGuard — URL Threat Scanner"
    SUB_TITLE = "Interactive Control Panel"

    CSS = """
    Screen {
        background: #0d1117;
    }
    Header {
        background: #161b22;
        color: #e6edf3;
        dock: top;
    }
    Footer {
        background: #161b22;
        dock: bottom;
    }

    /* ── Status bar ────────────────────────────────────────────── */
    #status-bar {
        height: 1;
        background: #21262d;
        padding: 0 2;
        dock: bottom;
        color: #7d8590;
        layout: horizontal;
    }
    #status-server { color: #3fb950; }
    #status-model  { margin-left: 4; }
    #status-scans  { margin-left: 4; }

    /* ── Tabs ──────────────────────────────────────────────────── */
    TabbedContent { height: 1fr; }
    TabPane { padding: 1 2; }
    ContentSwitcher { height: 1fr; }

    /* ── Common ────────────────────────────────────────────────── */
    .panel-title {
        color: #2f81f7;
        text-style: bold;
        margin-bottom: 1;
    }
    .field-label {
        color: #7d8590;
        margin-bottom: 0;
        height: 1;
    }
    Input {
        margin-bottom: 1;
        border: tall #30363d;
        background: #21262d;
        color: #e6edf3;
    }
    Input:focus { border: tall #2f81f7; }
    Button { margin-right: 1; }
    DataTable { height: 1fr; }
    DataTable > .datatable--header { background: #21262d; color: #7d8590; }
    DataTable > .datatable--cursor { background: #1c2d3f; }
    RichLog { border: solid #30363d; background: #161b22; height: 1fr; }
    Select { margin-bottom: 1; }
    .hint { color: #7d8590; margin-top: 1; }

    /* ── Scan tab ──────────────────────────────────────────────── */
    #scan-options { height: auto; margin-bottom: 1; }
    #scan-log { height: 1fr; }

    /* ── Batch tab ─────────────────────────────────────────────── */
    #batch-progress { height: auto; margin: 1 0; display: none; }
    #batch-log { height: 1fr; }

    /* ── History tab ───────────────────────────────────────────── */
    #history-filters { height: auto; margin-bottom: 1; layout: horizontal; }
    #history-filters Input { width: 30; margin-right: 1; }
    #history-filters Select { width: 20; }
    #history-table { height: 1fr; }

    /* ── Train tab ─────────────────────────────────────────────── */
    #train-log { height: 1fr; }
    #train-source { height: auto; layout: horizontal; margin-bottom: 1; }

    /* ── Admin tab ─────────────────────────────────────────────── */
    #admin-stats { height: auto; layout: horizontal; margin-bottom: 1; }
    .stat-box {
        border: solid #30363d; padding: 1 2;
        width: 20; margin-right: 1;
        background: #161b22;
    }
    .stat-val { text-style: bold; color: #e6edf3; }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit",    "Quit",    show=True),
        Binding("q",      "quit",    "Quit",    show=False),
        Binding("ctrl+r", "refresh", "Refresh", show=True),
        Binding("f5",     "refresh", "Refresh", show=False),
    ]

    # Reactive state
    server_url   = reactive(DEFAULT_SERVER)
    server_ok    = reactive(False)
    model_version = reactive("none")
    total_scans  = reactive(0)

    def __init__(self, server: str = DEFAULT_SERVER):
        super().__init__()
        self.server_url = server
        self._poll_task: Optional[asyncio.Task] = None
        self._history_data: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent(initial="tab-scan"):

            # ── Scan tab ───────────────────────────────────────────────
            with TabPane("🔍 Scan URL", id="tab-scan"):
                yield Label("Enter URL to scan", classes="panel-title")
                yield Label("URL", classes="field-label")
                yield Input(placeholder="https://example.com", id="scan-url")
                with Horizontal(id="scan-options"):
                    yield Label("  LLM enhancement")
                    yield Switch(id="scan-llm", value=False)
                    yield Label("   Output formats")
                    yield Select(
                        [("All (md txt pdf docx)", "all"), ("MD + PDF", "md-pdf"),
                         ("MD only", "md"), ("TXT only", "txt")],
                        id="scan-formats", value="all",
                    )
                with Horizontal():
                    yield Button("▶  Start Scan", id="scan-start", variant="primary")
                    yield Button("✕  Cancel",     id="scan-cancel", variant="default")
                yield Rule()
                yield RichLog(id="scan-log", highlight=True, markup=True)

            # ── Batch tab ──────────────────────────────────────────────
            with TabPane("📦 Batch Scan", id="tab-batch"):
                yield Label("Batch scan from file", classes="panel-title")
                yield Label("File path (.txt or .csv)", classes="field-label")
                yield Input(placeholder="/path/to/urls.txt", id="batch-file")
                with Horizontal(id="batch-csv-row"):
                    yield Label("CSV column (if .csv)")
                    yield Input(placeholder="url", id="batch-column", value="url")
                    yield Label("   LLM")
                    yield Switch(id="batch-llm", value=False)
                with Horizontal():
                    yield Button("▶  Start Batch", id="batch-start", variant="primary")
                    yield Button("✕  Cancel Batch", id="batch-cancel", variant="default")
                yield Rule()
                yield RichLog(id="batch-log", highlight=True, markup=True)

            # ── History tab ────────────────────────────────────────────
            with TabPane("📋 History", id="tab-history"):
                yield Label("Recent scans", classes="panel-title")
                with Horizontal(id="history-filters"):
                    yield Input(placeholder="Filter by URL…", id="history-search")
                    yield Select(
                        [("All verdicts", ""), ("Safe", "SAFE"),
                         ("Suspicious", "SUSPICIOUS"), ("Malicious", "MALICIOUS")],
                        id="history-verdict", value="",
                    )
                    yield Button("↻ Refresh", id="history-refresh")
                yield DataTable(id="history-table", cursor_type="row")

            # ── Training tab ───────────────────────────────────────────
            with TabPane("🧠 Train Model", id="tab-train"):
                yield Label("Offline model training", classes="panel-title")
                with Horizontal(id="train-source"):
                    yield Label("Source: ")
                    yield Select(
                        [("Scan DB (use collected scans)", "db"),
                         ("CSV — URL column", "csv-url"),
                         ("CSV — feature columns", "csv-feat")],
                        id="train-source-sel", value="db",
                    )
                yield Label("CSV file path (leave empty for DB mode)", classes="field-label")
                yield Input(placeholder="/path/to/urls.csv", id="train-csv")
                yield Label("URL column name (for CSV URL mode)", classes="field-label")
                yield Input(placeholder="url", id="train-col", value="url")
                with Horizontal():
                    yield Switch(id="train-savedb", value=True)
                    yield Label("  Save extracted vectors to DB (--save-to-db)")
                with Horizontal():
                    yield Button("▶  Start Training",       id="train-start",  variant="primary")
                    yield Button("↺  Reload Model (live)",  id="train-reload", variant="default")
                yield Rule()
                yield RichLog(id="train-log", highlight=True, markup=True)

            # ── Admin tab ──────────────────────────────────────────────
            with TabPane("⚙️  Admin", id="tab-admin"):
                yield Label("Server & model overview", classes="panel-title")
                with Horizontal(id="admin-stats"):
                    with Vertical(classes="stat-box"):
                        yield Label("Total Scans", classes="field-label")
                        yield Label("—", id="a-total", classes="stat-val")
                    with Vertical(classes="stat-box"):
                        yield Label("Safe",   classes="field-label")
                        yield Label("—", id="a-safe",  classes="stat-val")
                    with Vertical(classes="stat-box"):
                        yield Label("Suspicious", classes="field-label")
                        yield Label("—", id="a-susp",  classes="stat-val")
                    with Vertical(classes="stat-box"):
                        yield Label("Malicious",  classes="field-label")
                        yield Label("—", id="a-mal",   classes="stat-val")
                    with Vertical(classes="stat-box"):
                        yield Label("Model Version", classes="field-label")
                        yield Label("—", id="a-model", classes="stat-val")
                yield Rule()
                yield Label("Server", classes="panel-title")
                yield Label("Server URL", classes="field-label")
                yield Input(value=self.server_url, id="admin-server")
                with Horizontal():
                    yield Button("⟳ Reconnect",       id="admin-reconnect", variant="default")
                    yield Button("↺ Reload ML Model",  id="admin-reload",    variant="primary")
                yield Rule()
                yield RichLog(id="admin-log", highlight=True, markup=True)

            # ── Settings tab ───────────────────────────────────────────
            with TabPane("⚙  Settings", id="tab-settings"):
                yield Label("Connection", classes="panel-title")
                yield Label("Server URL", classes="field-label")
                yield Input(value=self.server_url, id="settings-server")
                yield Rule()
                yield Label("Keyboard shortcuts", classes="panel-title")
                yield Static(
                    "[dim]Tab / Shift+Tab[/dim]   Move between tabs\n"
                    "[dim]Arrow keys[/dim]         Navigate tables\n"
                    "[dim]Enter[/dim]              Select row / confirm\n"
                    "[dim]Ctrl+R / F5[/dim]        Refresh current view\n"
                    "[dim]Q / Ctrl+C[/dim]         Quit",
                    markup=True,
                )
                yield Rule()
                with Horizontal():
                    yield Button("Apply", id="settings-apply", variant="primary")

        # Status bar
        with Horizontal(id="status-bar"):
            yield Label("●", id="status-server")
            yield Label("model: —", id="status-model")
            yield Label("scans: —", id="status-scans")

        yield Footer()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def on_mount(self):
        self._setup_history_table()
        self._poll_task = asyncio.create_task(self._background_poll())

    async def on_unmount(self):
        if self._poll_task:
            self._poll_task.cancel()

    def _setup_history_table(self):
        tbl = self.query_one("#history-table", DataTable)
        tbl.add_columns("#", "URL", "Verdict", "Confidence", "Status", "When")

    # ── Background poll ────────────────────────────────────────────────────────

    async def _background_poll(self):
        """Poll server every 15s for status bar update. Lightweight /health check."""
        while True:
            await self._refresh_status()
            await asyncio.sleep(15)

    async def _refresh_status(self):
        try:
            ok = await _server_ok(self.server_url)
            self.server_ok = ok
            srv_label = self.query_one("#status-server", Label)
            srv_label.update("● Online" if ok else "● Offline")
            srv_label.styles.color = "#3fb950" if ok else "#f85149"

            if ok:
                stats = await _get(self.server_url, "/admin/stats")
                self.model_version = stats.get("active_model_version", "none")
                self.total_scans   = stats.get("total_scans", 0)
                self.query_one("#status-model", Label).update(f"model: {self.model_version}")
                self.query_one("#status-scans", Label).update(f"scans: {self.total_scans}")
        except Exception:
            pass

    # ── Actions ────────────────────────────────────────────────────────────────

    def action_refresh(self):
        """Refresh whichever tab is currently active."""
        asyncio.create_task(self._refresh_status())
        asyncio.create_task(self._do_refresh_active_tab())

    async def _do_refresh_active_tab(self):
        try:
            tc = self.query_one(TabbedContent)
            active = tc.active
            if active == "tab-history":
                await self._load_history()
            elif active == "tab-admin":
                await self._load_admin_stats()
        except Exception:
            pass

    # ── Scan tab ───────────────────────────────────────────────────────────────

    @on(Button.Pressed, "#scan-start")
    def on_scan_start(self):
        url = self.query_one("#scan-url", Input).value.strip()
        if not url:
            self._scan_log("❌ Enter a URL first.", "red")
            return
        self._scan_log(f"Submitting: [cyan]{url}[/cyan]")
        asyncio.create_task(self._do_scan(url))

    @on(Button.Pressed, "#scan-cancel")
    def on_scan_cancel(self):
        self._scan_log("[yellow]Cancel requested — use scan ID shown above.[/yellow]")

    async def _do_scan(self, url: str):
        log = self._scan_log
        use_llm = self.query_one("#scan-llm", Switch).value

        if not self.server_ok:
            log("❌ Server not reachable. Check connection.", "red")
            return

        try:
            sub = await _post(self.server_url, "/scan", {"url": url, "use_llm": use_llm})
            scan_id = sub["scan_id"]
            log(f"✓ Queued  scan_id=[dim]{scan_id}[/dim]")
        except Exception as e:
            log(f"❌ Submit failed: {e}", "red")
            return

        # Poll
        deadline = time.time() + 120
        while time.time() < deadline:
            await asyncio.sleep(2)
            try:
                data = await _get(self.server_url, f"/scan/{scan_id}")
                status = data.get("status", "")
                log(f"  Status: [bold]{status}[/bold]")
                if status == "completed":
                    result = data.get("result", {})
                    verdict = result.get("verdict", {})
                    v = verdict.get("verdict", "?")
                    conf = verdict.get("confidence", "?")
                    color = _verdict_color(v)
                    emoji = _verdict_emoji(v)
                    log(f"\n{emoji} Verdict: [{color}][bold]{v}[/bold][/{color}]  ({conf})")
                    for reason in verdict.get("reasons", []):
                        log(f"  • {reason}")
                    log(f"\n[dim]Full detail: press Enter on history row or use report command[/dim]")
                    await self._load_history()
                    return
                elif status == "failed":
                    log(f"❌ Scan failed: {data.get('error', '?')}", "red")
                    return
            except Exception as e:
                log(f"  Poll error: {e}")

        log("⏰ Timed out waiting for result.", "yellow")

    def _scan_log(self, msg: str, color: str = ""):
        log = self.query_one("#scan-log", RichLog)
        if color:
            log.write(f"[{color}]{msg}[/{color}]")
        else:
            log.write(msg)

    # ── Batch tab ──────────────────────────────────────────────────────────────

    @on(Button.Pressed, "#batch-start")
    def on_batch_start(self):
        path = self.query_one("#batch-file", Input).value.strip()
        if not path:
            self.query_one("#batch-log", RichLog).write("[red]Enter a file path first.[/red]")
            return
        asyncio.create_task(self._do_batch(path))

    @on(Button.Pressed, "#batch-cancel")
    def on_batch_cancel(self):
        self.query_one("#batch-log", RichLog).write("[yellow]Cancel — enter batch_id to cancel via admin.[/yellow]")

    async def _do_batch(self, path_str: str):
        log = self.query_one("#batch-log", RichLog)
        column  = self.query_one("#batch-column", Input).value.strip() or "url"
        use_llm = self.query_one("#batch-llm", Switch).value
        p = Path(path_str)

        if not p.exists():
            log.write(f"[red]File not found: {p}[/red]")
            return

        log.write(f"Reading [cyan]{p.name}[/cyan]…")

        # Read URLs
        import csv as _csv
        urls = []
        try:
            if p.suffix.lower() == ".csv":
                with open(p, newline="", encoding="utf-8") as f:
                    reader = _csv.DictReader(f)
                    if column not in (reader.fieldnames or []):
                        log.write(f"[red]Column '{column}' not in CSV. Headers: {reader.fieldnames}[/red]")
                        return
                    for row in reader:
                        v = row.get(column, "").strip()
                        if v:
                            urls.append(v)
            else:
                urls = [l.strip() for l in p.read_text().splitlines()
                        if l.strip() and not l.startswith("#")]
        except Exception as e:
            log.write(f"[red]Read error: {e}[/red]")
            return

        # Deduplicate
        seen, unique = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u); unique.append(u)

        log.write(f"Found [bold]{len(unique)}[/bold] unique URLs (removed {len(urls)-len(unique)} dupes)")

        try:
            data = await _post(self.server_url, "/batch", {"urls": unique, "use_llm": use_llm})
            batch_id = data["batch_id"]
            total    = data["total_urls"]
            log.write(f"✓ Batch submitted  batch_id=[dim]{batch_id}[/dim]  total={total}")
        except Exception as e:
            log.write(f"[red]Submit failed: {e}[/red]")
            return

        # Poll
        deadline = time.time() + (120 * max(1, total // 10 + 1))
        prev_done = 0
        while time.time() < deadline:
            await asyncio.sleep(3)
            try:
                st = await _get(self.server_url, f"/batch/{batch_id}?page_size=1")
                done = st.get("completed", 0) + st.get("failed", 0)
                pct  = st.get("progress_pct", 0)
                if done != prev_done:
                    log.write(f"  Progress: [bold]{done}/{total}[/bold] ({pct}%)")
                    prev_done = done
                if st.get("status") in ("completed", "failed", "cancelled"):
                    log.write(f"\n✅ Batch complete — status: [bold]{st.get('status')}[/bold]")
                    log.write(f"  Report → reports/batch_{batch_id[:8]}…")
                    await self._load_history()
                    return
            except Exception as e:
                log.write(f"  Poll error: {e}")

        log.write(f"⏰ Timed out. batch_id=[dim]{batch_id}[/dim]", )

    # ── History tab ────────────────────────────────────────────────────────────

    def on_mount_history(self):
        asyncio.create_task(self._load_history())

    @on(Button.Pressed, "#history-refresh")
    def on_history_refresh(self):
        asyncio.create_task(self._load_history())

    @on(TabbedContent.TabActivated)
    def on_tab_activated(self, event: TabbedContent.TabActivated):
        tab = str(event.tab.id)
        if tab == "tab-history":
            asyncio.create_task(self._load_history())
        elif tab == "tab-admin":
            asyncio.create_task(self._load_admin_stats())

    async def _load_history(self):
        try:
            data = await _get(self.server_url, "/admin/scans?limit=200")
            self._history_data = data.get("scans", [])
            self._render_history()
        except Exception as e:
            pass

    def _render_history(self):
        tbl = self.query_one("#history-table", DataTable)
        tbl.clear()
        search  = self.query_one("#history-search", Input).value.lower()
        verdict_filter = ""
        try:
            verdict_filter = self.query_one("#history-verdict", Select).value or ""
        except Exception:
            pass

        filtered = [
            s for s in self._history_data
            if (not search or search in s.get("url", "").lower()) and
               (not verdict_filter or s.get("verdict") == verdict_filter)
        ]

        for i, s in enumerate(filtered, 1):
            v = s.get("verdict") or "—"
            emoji = _verdict_emoji(v) if v != "—" else "❓"
            tbl.add_row(
                str(i),
                s.get("url", "")[:55],
                f"{emoji} {v}",
                s.get("confidence") or "—",
                s.get("status") or "—",
                s.get("created_at", "")[:16],
                key=s.get("scan_id"),
            )

    @on(Input.Changed, "#history-search")
    def on_history_search(self, event: Input.Changed):
        self._render_history()

    @on(Select.Changed, "#history-verdict")
    def on_history_verdict_filter(self, event: Select.Changed):
        self._render_history()

    @on(DataTable.RowSelected, "#history-table")
    async def on_history_row_selected(self, event: DataTable.RowSelected):
        scan_id = str(event.row_key.value)
        try:
            data = await _get(self.server_url, f"/scan/{scan_id}")
            await self.push_screen(ScanResultModal(data))
        except Exception as e:
            self.notify(f"Error loading scan: {e}", severity="error")

    # ── Training tab ───────────────────────────────────────────────────────────

    @on(Button.Pressed, "#train-start")
    def on_train_start(self):
        asyncio.create_task(self._do_train())

    @on(Button.Pressed, "#train-reload")
    def on_train_reload(self):
        asyncio.create_task(self._do_reload_model(log_id="train-log"))

    async def _do_train(self):
        log = self.query_one("#train-log", RichLog)
        log.write("[bold]Starting training…[/bold]")

        source    = self.query_one("#train-source-sel", Select).value
        csv_path  = self.query_one("#train-csv", Input).value.strip()
        col       = self.query_one("#train-col", Input).value.strip() or "url"
        save_db   = self.query_one("#train-savedb", Switch).value

        # Build command
        cmd = [sys.executable, "-m", "training.train"]
        if source == "csv-url" and csv_path:
            cmd += ["--csv", csv_path, "--url-column", col]
            if save_db:
                cmd.append("--save-to-db")
        elif source == "csv-feat" and csv_path:
            cmd += ["--csv", csv_path, "--all-features"]
        else:
            log.write("[dim]Source: DB (accumulated scan vectors)[/dim]")

        log.write(f"[dim]Command: {' '.join(cmd)}[/dim]")

        # Run as subprocess so it doesn't block the TUI
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            async for line in proc.stdout:
                log.write(line.decode().rstrip())
            await proc.wait()
            if proc.returncode == 0:
                log.write("\n[green]✓ Training complete![/green]")
                log.write("[dim]Click 'Reload Model (live)' to activate without restarting.[/dim]")
            else:
                log.write(f"[red]Training exited with code {proc.returncode}[/red]")
        except Exception as e:
            log.write(f"[red]Error: {e}[/red]")

    async def _do_reload_model(self, log_id: str = "admin-log"):
        log = self.query_one(f"#{log_id}", RichLog)
        try:
            data = await _post(self.server_url, "/admin/reload-model", {})
            log.write(f"[green]✓ Model reloaded — version {data.get('version')}  "
                      f"({data.get('n_samples')} samples)[/green]")
            await self._refresh_status()
        except Exception as e:
            log.write(f"[red]Reload failed: {e}[/red]")

    # ── Admin tab ──────────────────────────────────────────────────────────────

    @on(Button.Pressed, "#admin-reconnect")
    def on_admin_reconnect(self):
        url = self.query_one("#admin-server", Input).value.strip()
        if url:
            self.server_url = url
        asyncio.create_task(self._refresh_status())
        asyncio.create_task(self._load_admin_stats())

    @on(Button.Pressed, "#admin-reload")
    def on_admin_reload(self):
        asyncio.create_task(self._do_reload_model())

    async def _load_admin_stats(self):
        log = self.query_one("#admin-log", RichLog)
        try:
            stats = await _get(self.server_url, "/admin/stats")
            v = stats.get("verdicts", {})
            self.query_one("#a-total", Label).update(str(stats.get("total_scans", 0)))
            self.query_one("#a-safe",  Label).update(str(v.get("SAFE", 0)))
            self.query_one("#a-susp",  Label).update(str(v.get("SUSPICIOUS", 0)))
            self.query_one("#a-mal",   Label).update(str(v.get("MALICIOUS", 0)))
            self.query_one("#a-model", Label).update(stats.get("active_model_version", "none"))
            log.write(f"[green]✓ Stats refreshed[/green]  "
                      f"statuses: {stats.get('statuses', {})}")
        except Exception as e:
            log.write(f"[red]Stats load failed: {e}[/red]")

    # ── Settings tab ───────────────────────────────────────────────────────────

    @on(Button.Pressed, "#settings-apply")
    def on_settings_apply(self):
        url = self.query_one("#settings-server", Input).value.strip()
        if url:
            self.server_url = url
            self.query_one("#admin-server", Input).value = url
            self.notify(f"Server set to {url}", severity="information")
        asyncio.create_task(self._refresh_status())


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="PhishGuard interactive terminal panel")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help=f"Server URL (default: {DEFAULT_SERVER})")
    args = parser.parse_args()
    PhishGuardPanel(server=args.server).run()


if __name__ == "__main__":
    main()
