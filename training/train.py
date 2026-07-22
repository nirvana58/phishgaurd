"""
training/train.py

Offline training script. Three data sources:

  1. DB mode (default) — reads feature vectors saved by past scans:
       python -m training.train

  2. CSV / URL mode — extract features from a CSV of URLs (no scanning needed):
       python -m training.train --csv urls.csv --url-column url
       python -m training.train --csv urls.csv --url-column url --save-to-db

  3. Feature CSV mode — CSV already has pre-computed numeric feature columns:
       python -m training.train --csv features.csv --all-features
       python -m training.train --csv features.csv --feature-columns url_length,entropy,...

Large-file support:
  URLs are processed in streaming fashion (line-by-line) so even
  million-row CSV files don't exhaust RAM. A rich progress bar shows
  live extraction speed and ETA.

--save-to-db:
  Extracted feature vectors are saved to the feature_vectors table so
  future `python -m training.train` (DB mode) picks them up automatically
  without re-extracting from the CSV again.

After training:
  Artifacts are saved to training/artifacts/ and latest.json is updated.
  Hot-reload via:  POST /admin/reload-model  (no server restart needed)
"""

import argparse
import csv
import json
import os
import pickle
import sqlite3
import sys
import time
from pathlib import Path

import numpy as np
from minisom import MiniSom
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn,
    BarColumn, MofNCompleteColumn, TimeElapsedColumn, TimeRemainingColumn,
)
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
DB_PATH       = PROJECT_ROOT / "data.db"
ARTIFACTS_DIR = PROJECT_ROOT / "training" / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

console = Console()

# ── Hyperparameters ────────────────────────────────────────────────────────────
KMEANS_CLUSTERS          = 8
KMEANS_INIT              = "k-means++"
KMEANS_N_INIT            = 10
KMEANS_MAX_ITER          = 300
KMEANS_RANDOM_STATE      = 42

SOM_GRID_X                = 10
SOM_GRID_Y                = 10
SOM_SIGMA                 = 1.5
SOM_LEARNING_RATE         = 0.5
SOM_ITERATIONS_MULTIPLIER = 100
SOM_RANDOM_SEED           = 42

STREAM_CHUNK = 5_000   # rows per in-memory chunk during streaming


# ── Source 1: DB ───────────────────────────────────────────────────────────────

def load_vectors_from_db() -> np.ndarray:
    if not DB_PATH.exists():
        console.print(f"[red]DB not found:[/red] {DB_PATH}")
        console.print("Run the server and submit some scans first, or use --csv.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(
            "SELECT vector_json FROM feature_vectors ORDER BY created_at"
        ).fetchall()
    except sqlite3.OperationalError as e:
        console.print(f"[red]DB error:[/red] {e}")
        sys.exit(1)
    finally:
        conn.close()

    if not rows:
        return np.array([])

    return np.array([json.loads(r[0]) for r in rows], dtype=np.float64)


# ── Source 2 & 3: CSV streaming ────────────────────────────────────────────────

def _count_csv_rows(path: Path, delimiter: str) -> int:
    """Quick line count to set the progress bar total."""
    with open(path, "rb") as f:
        return sum(1 for _ in f) - 1   # subtract header


def load_vectors_from_csv(
    csv_path: Path,
    url_column: str | None,
    feature_columns: list[str] | None,
    all_features: bool,
    delimiter: str,
    save_to_db: bool,
) -> np.ndarray:
    from core.features import extract_features, FEATURE_NAMES

    if not csv_path.exists():
        console.print(f"[red]CSV not found:[/red] {csv_path}")
        sys.exit(1)

    # ── Detect column mode ─────────────────────────────────────────────────────
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        header = reader.fieldnames or []

    if not header:
        console.print("[red]CSV has no header row.[/red]")
        sys.exit(1)

    console.print(f"[dim]CSV columns: {header}[/dim]")

    # Determine columns to use
    if url_column:
        col = url_column.strip()
        if col not in header:
            console.print(f"[red]Column '{col}' not in CSV.[/red] Available: {header}")
            sys.exit(1)
        mode = "url"
        cols = [col]
    elif all_features:
        mode = "features"
        cols = FEATURE_NAMES
    elif feature_columns:
        mode = "features"
        cols = feature_columns
        missing = [c for c in cols if c not in header]
        if missing:
            console.print(f"[red]Columns not found:[/red] {missing}")
            sys.exit(1)
    else:
        console.print("[red]Specify --url-column, --all-features, or --feature-columns.[/red]")
        sys.exit(1)

    # ── Count rows for progress bar ────────────────────────────────────────────
    total_rows = _count_csv_rows(csv_path, delimiter)
    console.print(f"[dim]Rows in CSV: ~{total_rows:,}[/dim]")

    vectors:  list[list[float]] = []
    skipped   = 0
    db_conn   = None

    if save_to_db:
        if not DB_PATH.exists():
            console.print("[yellow]DB not found — vectors will not be saved (run server first).[/yellow]")
            save_to_db = False
        else:
            db_conn = sqlite3.connect(DB_PATH)
            db_conn.execute("PRAGMA journal_mode=WAL")
            try:
                db_conn.execute("SELECT 1 FROM feature_vectors LIMIT 1")
            except sqlite3.OperationalError:
                console.print("[yellow]feature_vectors table missing — run server once first.[/yellow]")
                db_conn.close()
                db_conn = None
                save_to_db = False

    db_batch: list[tuple] = []   # buffered rows for --save-to-db

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]ETA:[/dim]"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"Extracting {'features from URLs' if mode == 'url' else 'feature columns'}…",
            total=total_rows,
        )

        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            chunk: list[list[float]] = []

            for i, row in enumerate(reader):
                progress.advance(task)

                if mode == "url":
                    url_val = row.get(col, "").strip()
                    if not url_val:
                        skipped += 1
                        continue
                    try:
                        vec = extract_features(url_val)
                    except Exception:
                        skipped += 1
                        continue
                else:
                    try:
                        vec = [float(row[c]) for c in cols]
                    except (ValueError, KeyError):
                        skipped += 1
                        continue

                chunk.append(vec)

                if save_to_db and db_conn:
                    import uuid as _uuid
                    fake_scan_id = f"train-{_uuid.uuid4()}"
                    db_batch.append((fake_scan_id, json.dumps(vec)))

                # Flush chunk to avoid unbounded RAM growth on huge files
                if len(chunk) >= STREAM_CHUNK:
                    vectors.extend(chunk)
                    chunk = []

                # Flush DB batch every 1000 rows
                if db_conn and len(db_batch) >= 1000:
                    db_conn.executemany(
                        "INSERT OR IGNORE INTO feature_vectors (scan_id, vector_json, created_at) "
                        "VALUES (?, ?, datetime('now'))",
                        db_batch,
                    )
                    db_conn.commit()
                    db_batch = []

            vectors.extend(chunk)

            if db_conn and db_batch:
                db_conn.executemany(
                    "INSERT OR IGNORE INTO feature_vectors (scan_id, vector_json, created_at) "
                    "VALUES (?, ?, datetime('now'))",
                    db_batch,
                )
                db_conn.commit()

    if db_conn:
        db_conn.close()
        console.print(f"[green]✓ Feature vectors saved to DB[/green]")

    if skipped:
        console.print(f"[yellow]Skipped {skipped:,} invalid rows.[/yellow]")
    if not vectors:
        console.print("[red]No valid vectors extracted.[/red]")
        sys.exit(1)

    console.print(
        f"[green]✓[/green] Extracted [bold]{len(vectors):,}[/bold] vectors × "
        f"[bold]{len(vectors[0])}[/bold] features"
    )
    return np.array(vectors, dtype=np.float64)


# ── Training ───────────────────────────────────────────────────────────────────

def train_kmeans(X_scaled: np.ndarray) -> KMeans:
    k = min(KMEANS_CLUSTERS, len(X_scaled))
    console.print(f"[dim]Training K-means (k={k}) on {len(X_scaled):,} samples…[/dim]")
    km = KMeans(
        n_clusters=k, init=KMEANS_INIT, n_init=KMEANS_N_INIT,
        max_iter=KMEANS_MAX_ITER, random_state=KMEANS_RANDOM_STATE,
    )
    km.fit(X_scaled)
    console.print(f"  [dim]K-means inertia: {km.inertia_:.4f}[/dim]")
    return km


def train_som(X_scaled: np.ndarray) -> tuple:
    n_iters = len(X_scaled) * SOM_ITERATIONS_MULTIPLIER
    console.print(f"[dim]Training SOM ({SOM_GRID_X}×{SOM_GRID_Y}) for {n_iters:,} iterations…[/dim]")

    som = MiniSom(
        x=SOM_GRID_X, y=SOM_GRID_Y, input_len=X_scaled.shape[1],
        sigma=SOM_SIGMA, learning_rate=SOM_LEARNING_RATE,
        random_seed=SOM_RANDOM_SEED,
    )
    som.random_weights_init(X_scaled)

    # Train in blocks so we can show a progress bar
    block = max(1, n_iters // 50)
    trained = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Training SOM…", total=n_iters)
        while trained < n_iters:
            this_block = min(block, n_iters - trained)
            som.train_random(X_scaled, num_iteration=this_block, verbose=False)
            trained += this_block
            progress.advance(task, this_block)

    qe = som.quantization_error(X_scaled)
    console.print(f"  [dim]SOM quantization error: {qe:.6f}[/dim]")
    return som, qe


# ── Save artifacts ─────────────────────────────────────────────────────────────

def save_artifacts(
    scaler, kmeans, som, qe: float,
    n_samples: int, n_features: int,
    elapsed: float, source: str,
) -> str:
    version = str(int(time.time()))
    paths = {
        "scaler": ARTIFACTS_DIR / f"scaler_{version}.pkl",
        "kmeans": ARTIFACTS_DIR / f"kmeans_{version}.pkl",
        "som":    ARTIFACTS_DIR / f"som_{version}.pkl",
    }
    for name, obj in [("scaler", scaler), ("kmeans", kmeans), ("som", som)]:
        with open(paths[name], "wb") as fh:
            pickle.dump(obj, fh)
        console.print(f"  [dim]Saved {paths[name].name}[/dim]")

    meta = {
        "version":          version,
        "trained_at":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source":           source,
        "n_samples":        n_samples,
        "n_features":       n_features,
        "training_seconds": round(elapsed, 2),
        "kmeans_clusters":  kmeans.n_clusters,
        "kmeans_inertia":   float(kmeans.inertia_),
        "som_grid":         [SOM_GRID_X, SOM_GRID_Y],
        "som_qe_baseline":  float(qe),
        "artifacts":        {k: str(v.name) for k, v in paths.items()},
    }
    latest = ARTIFACTS_DIR / "latest.json"
    with open(latest, "w") as fh:
        json.dump(meta, fh, indent=2)

    console.print(f"  [dim]latest.json → version {version}[/dim]")
    return version


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train K-means + SOM on URL feature vectors.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train on scan data already in the DB
  python -m training.train

  # Train on a CSV of raw URLs (features extracted automatically, streamed)
  python -m training.train --csv /path/to/urls.csv --url-column url

  # Same but also save extracted features to DB for future reuse
  python -m training.train --csv urls.csv --url-column url --save-to-db

  # Train on a CSV with pre-computed feature columns
  python -m training.train --csv features.csv --all-features

  # Specific named columns, semicolon-delimited
  python -m training.train --csv data.csv --feature-columns url_length,entropy,digit_ratio --delimiter ";"

  # After training, hot-reload without restarting the server:
  python -m cli.client admin reload
        """
    )

    parser.add_argument("--csv",             type=Path, default=None,
                        help="CSV file to train on (skips DB if given)")
    parser.add_argument("--url-column",      type=str,  default=None,
                        help="CSV column with URLs — features extracted automatically")
    parser.add_argument("--feature-columns", type=str,  default=None,
                        help="Comma-separated feature column names in CSV")
    parser.add_argument("--all-features",    action="store_true",
                        help="Use all 17 features in canonical order from CSV")
    parser.add_argument("--delimiter",       type=str,  default=",",
                        help="CSV delimiter (default: ',')")
    parser.add_argument("--save-to-db",      action="store_true",
                        help="Save extracted feature vectors to the DB (avoids re-extraction next time)")
    parser.add_argument("--min-samples",     type=int,  default=10,
                        help="Abort if fewer than N samples (default: 10)")

    args = parser.parse_args()
    feat_cols = [c.strip() for c in args.feature_columns.split(",") if c.strip()] \
        if args.feature_columns else None

    console.rule("[bold]URL Scanner — Model Training[/bold]")

    # ── Load ───────────────────────────────────────────────────────────────────
    if args.csv:
        source = f"csv:{args.csv.name}"
        console.print(f"[bold]Source:[/bold] CSV — {args.csv}")
        X = load_vectors_from_csv(
            csv_path=args.csv,
            url_column=args.url_column,
            feature_columns=feat_cols,
            all_features=args.all_features,
            delimiter=args.delimiter,
            save_to_db=args.save_to_db,
        )
    else:
        source = "db"
        console.print(f"[bold]Source:[/bold] SQLite DB — {DB_PATH}")
        X = load_vectors_from_db()

    if X.size == 0:
        console.print("[red]No data found.[/red]")
        sys.exit(1)

    if len(X) < args.min_samples:
        console.print(
            f"[red]Only {len(X):,} samples — need at least {args.min_samples}.[/red]"
        )
        sys.exit(1)

    # ── Train ──────────────────────────────────────────────────────────────────
    console.print()
    t0 = time.time()

    console.print("[dim]Fitting StandardScaler…[/dim]")
    scaler  = StandardScaler()
    scaler.fit(X)
    X_s = scaler.transform(X)

    console.print()
    kmeans      = train_kmeans(X_s)
    console.print()
    som, som_qe = train_som(X_s)

    elapsed = time.time() - t0
    console.print()
    version = save_artifacts(
        scaler=scaler, kmeans=kmeans, som=som, qe=som_qe,
        n_samples=len(X), n_features=X.shape[1],
        elapsed=elapsed, source=source,
    )

    console.print()
    console.rule()
    console.print(
        f"[bold green]✓ Training complete[/bold green] — "
        f"{len(X):,} samples in {elapsed:.1f}s — version [cyan]{version}[/cyan]"
    )
    console.print(
        "[dim]Hot-reload:  python -m cli.client admin reload[/dim]"
    )


if __name__ == "__main__":
    main()
