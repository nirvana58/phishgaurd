"""
server/discord_bot.py

Discord bot exposing a `/scan` slash command for quick, one-off URL
threat scans, directly inside a Discord server.

This is intentionally NOT wired into the job queue or the database:
each /scan runs scanner.scan_url() directly and replies with an embed.
Nothing is persisted — it won't show up in the admin panel or CLI
history. Use this for fast interactive lookups; use the web/CLI flow
for anything you want tracked.

Environment variables:
  DISCORD_BOT_TOKEN   Bot token from the Discord Developer Portal.
                       Different from DISCORD_WEBHOOK_URL — a bot needs
                       its own application + token, not a channel webhook.
  DISCORD_GUILD_ID    Optional. If set, the /scan command syncs instantly
                       to that one server — use this while developing.
                       If unset, the command syncs globally, which can
                       take up to an hour to propagate on first deploy.

One-time setup:
  1. https://discord.com/developers/applications -> New Application
  2. "Bot" tab -> Add Bot -> Reset Token -> copy it -> DISCORD_BOT_TOKEN
     (no privileged intents needed — slash commands don't require them)
  3. "OAuth2 -> URL Generator" tab:
       scopes:      bot, applications.commands
       permissions: Send Messages, Embed Links
     Open the generated URL to invite the bot to your server.
  4. pip install -U discord.py
  5. Run:  python -m server.discord_bot

This process loads its own ModelStore at startup, so it can score URLs
even if server/main.py (the FastAPI app) isn't running.
"""

import os
from pathlib import Path
import traceback
import uuid

from dotenv import load_dotenv
 
# This runs as its own process (python -m server.discord_bot), separate
# from server/main.py — so main.py's load_dotenv() never executes here.
# Load .env ourselves, before reading any env vars below.
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_PATH)

import discord
from discord import app_commands
from discord.ext import commands

from core.models import ModelStore, ModelLoadError
from core.webhook import build_scan_embed
from server.scanner import scan_url

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DISCORD_GUILD_ID  = os.getenv("DISCORD_GUILD_ID", "").strip()

# Per-scan timeout so a hung external API can't leave a user's slash
# command spinning forever (Discord interactions expire after 15 min,
# but nobody wants to wait that long for a reply).
SCAN_TIMEOUT = 45.0

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# Populated in on_ready(). None means "run without ML scoring".
model_store: ModelStore | None = None


@bot.event
async def on_ready():
    global model_store

    try:
        model_store = ModelStore.load()
        print("[bot] ML model loaded.")
    except ModelLoadError as e:
        model_store = None
        print(f"[bot] WARNING: {e}")
        print("[bot] Scans will run without ML scoring (VT/GSB/WHOIS/URLhaus still active).")

    if DISCORD_GUILD_ID:
        guild = discord.Object(id=int(DISCORD_GUILD_ID))
        bot.tree.copy_global_to(guild=guild)
        synced = await bot.tree.sync(guild=guild)
        print(f"[bot] Synced {len(synced)} command(s) to guild {DISCORD_GUILD_ID} (instant).")
    else:
        synced = await bot.tree.sync()
        print(f"[bot] Synced {len(synced)} command(s) globally "
              f"(can take up to 1h to appear on first deploy).")

    print(f"[bot] Logged in as {bot.user} — ready.")


@bot.tree.command(name="scan", description="Scan a URL for phishing/malware threats")
@app_commands.describe(url="The URL to scan (e.g. https://example.com)")
async def scan(interaction: discord.Interaction, url: str):
    # Discord requires an ack within 3s. Scans call several external APIs
    # concurrently and can take a few seconds, so defer immediately —
    # this shows "thinking..." and gives us up to 15 min to follow up.
    await interaction.response.defer(thinking=True)

    url = url.strip()
    if not url:
        await interaction.followup.send("⚠️ Please provide a URL to scan.")
        return

    scan_id = str(uuid.uuid4())  # not persisted — display/reference only

    try:
        import asyncio
        result, _raw_vector = await asyncio.wait_for(
            scan_url(url=url, model_store=model_store, use_llm=False),
            timeout=SCAN_TIMEOUT,
        )
    except asyncio.TimeoutError:
        await interaction.followup.send(
            f"⏱️ Scan timed out after {SCAN_TIMEOUT:.0f}s for `{url[:200]}` — "
            f"the target may be slow or unreachable. Try again in a moment."
        )
        return
    except Exception:
        print(f"[bot] Scan failed for {url!r}:\n{traceback.format_exc()}")
        await interaction.followup.send(
            f"⚠️ Scan failed for `{url[:200]}` — an internal error occurred. "
            f"Try again in a moment."
        )
        return

    embed_dict = build_scan_embed(scan_id, result)
    embed = discord.Embed.from_dict(embed_dict)

    await interaction.followup.send(
        content=f"Scan requested by {interaction.user.mention}",
        embed=embed,
    )


def main():
    if not DISCORD_BOT_TOKEN:
        raise SystemExit(
            "DISCORD_BOT_TOKEN is not set. Create a bot at "
            "https://discord.com/developers/applications, copy its token, "
            "and set DISCORD_BOT_TOKEN in your .env."
        )
    bot.run(DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    main()
