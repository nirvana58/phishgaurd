"""
core/models.py

Runtime model wrapper. Loaded once at server startup; hot-swapped by the
admin reload endpoint without restarting the server.

Responsibilities:
  - Find and load the latest trained artifacts (scaler + kmeans + som)
  - Apply the fitted scaler to a raw feature vector
  - Score the scaled vector through both models
  - Return a structured AnomalyResult with individual + combined scores
    and enough detail for the report generator to explain the verdict

Does NOT do feature extraction (that's core/features.py) or
thresholding/verdict logic (that's server/scanner.py, which has access to
scan context, external API results, etc.).
"""

import json
import math
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "training" / "artifacts"


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class KMeansResult:
    cluster_id: int          # which cluster this URL was assigned to
    distance_to_centroid: float   # Euclidean distance (in scaled space)
    # Anomaly score: distance normalised by mean centroid-to-centroid spread.
    # 0 = right at cluster centre, 1+ = progressively more anomalous.
    anomaly_score: float


@dataclass
class SOMResult:
    bmu_x: int               # Best Matching Unit grid coordinates
    bmu_y: int
    quantization_error: float  # distance from vector to BMU weight vector
    # Anomaly score: QE normalised by the mean QE seen during training.
    # Stored in the SOM artifact as som.quantization_error(training_data).
    anomaly_score: float


@dataclass
class AnomalyResult:
    kmeans: KMeansResult
    som: SOMResult
    # Weighted combination; default weights give each model equal say.
    combined_score: float
    # Agreement flag: True when both models independently flag as anomalous.
    models_agree: bool
    # Raw scaled vector, kept for debugging.
    scaled_vector: list[float]
    model_version: str
    # Per-feature contribution to the combined anomaly score.
    # Keys are FEATURE_NAMES, values are percentages (sum ≈ 100).
    # Higher % = this feature drove the anomaly score more.
    feature_contributions: dict[str, float] = None


# ── Artifact loading ───────────────────────────────────────────────────────────

class ModelLoadError(Exception):
    pass


def _load_latest_meta() -> dict:
    latest_path = ARTIFACTS_DIR / "latest.json"
    if not latest_path.exists():
        raise ModelLoadError(
            f"No trained models found at {ARTIFACTS_DIR}. "
            "Run `python -m training.train` first."
        )
    with open(latest_path) as f:
        return json.load(f)


def _load_pickle(name: str, meta: dict) -> object:
    filename = meta["artifacts"][name]
    path = ARTIFACTS_DIR / filename
    if not path.exists():
        raise ModelLoadError(f"Artifact file missing: {path}")
    with open(path, "rb") as f:
        return pickle.load(f)


# ── ModelStore ────────────────────────────────────────────────────────────────

class ModelStore:
    """
    Holds the three loaded artifacts (scaler, kmeans, som) plus derived
    calibration stats used to normalise anomaly scores.

    Instantiate once at server startup via ModelStore.load().
    For hot-reload, call ModelStore.load() again and replace the reference
    in main.py's app.state — thread-safe enough for single-worker asyncio.
    """

    def __init__(self, scaler, kmeans, som, meta: dict):
        self._scaler = scaler
        self._kmeans = kmeans
        self._som = som
        self.meta = meta
        self.version = meta["version"]

        # Calibration: compute mean inter-centroid distance for K-means score
        # normalisation and mean QE from training meta (stored during train).
        centroids = self._kmeans.cluster_centers_
        n = len(centroids)
        if n > 1:
            dists = [
                np.linalg.norm(centroids[i] - centroids[j])
                for i in range(n)
                for j in range(i + 1, n)
            ]
            self._kmeans_spread = float(np.mean(dists))
        else:
            self._kmeans_spread = 1.0   # fallback: single cluster edge case

        # SOM calibration baseline: stored in meta by train.py (not yet),
        # so we fall back to 1.0 if absent — scores will still be ordinal
        # even if not perfectly normalised until we add it to train.py.
        self._som_qe_baseline = float(meta.get("som_qe_baseline", 1.0))

        # Weights for combined score: [kmeans_weight, som_weight], must sum to 1
        self.combined_score_weights = (0.5, 0.5)

    @classmethod
    def load(cls) -> "ModelStore":
        meta = _load_latest_meta()
        scaler = _load_pickle("scaler", meta)
        kmeans = _load_pickle("kmeans", meta)
        som    = _load_pickle("som", meta)
        print(f"[models] Loaded version {meta['version']} "
              f"(trained on {meta['n_samples']} samples)")
        return cls(scaler, kmeans, som, meta)

    def score(
        self,
        raw_vector: list[float],
        kmeans_threshold: float = 1.0,
        som_threshold: float = 1.0,
    ) -> AnomalyResult:
        """
        Scale raw_vector and score it through both models.

        Thresholds (in normalised anomaly-score space):
          > 1.0 = noticeably outside the trained distribution.
        These are tunable from the admin panel later.
        """
        X = np.array(raw_vector, dtype=np.float64).reshape(1, -1)
        X_scaled = self._scaler.transform(X)
        scaled_list = X_scaled[0].tolist()

        # ── K-means ──────────────────────────────────────────────────────────
        cluster_id = int(self._kmeans.predict(X_scaled)[0])
        centroid = self._kmeans.cluster_centers_[cluster_id]
        dist_to_centroid = float(np.linalg.norm(X_scaled[0] - centroid))
        kmeans_score = dist_to_centroid / max(self._kmeans_spread, 1e-9)

        km_result = KMeansResult(
            cluster_id=cluster_id,
            distance_to_centroid=dist_to_centroid,
            anomaly_score=kmeans_score,
        )

        # ── SOM ───────────────────────────────────────────────────────────────
        bmu = self._som.winner(X_scaled[0])
        bmu_weight = self._som.get_weights()[bmu[0], bmu[1]]
        qe = float(np.linalg.norm(X_scaled[0] - bmu_weight))
        som_score = qe / max(self._som_qe_baseline, 1e-9)

        som_result = SOMResult(
            bmu_x=int(bmu[0]),
            bmu_y=int(bmu[1]),
            quantization_error=qe,
            anomaly_score=som_score,
        )

        # ── Combined ──────────────────────────────────────────────────────────
        wk, ws = self.combined_score_weights
        combined = wk * kmeans_score + ws * som_score

        models_agree = (
            kmeans_score > kmeans_threshold and
            som_score > som_threshold
        )

        # ── Per-feature importance ────────────────────────────────────────────
        # For each feature, compute how much it contributed to the anomaly score.
        #
        # K-means contribution: |scaled_value - centroid_value|
        #   Features where the URL deviates most from its cluster centroid
        #   are the features that pushed it away from "normal".
        #
        # SOM contribution: |scaled_value - bmu_weight_value|
        #   Features where the URL deviates most from its closest neuron.
        #
        # We weight-combine both (matching combined_score_weights) then
        # normalise the whole vector to sum to 100% so each feature gets
        # a share of the total anomaly — easy to read in a report.
        try:
            from core.features import FEATURE_NAMES
            km_contrib   = np.abs(X_scaled[0] - centroid)
            som_contrib  = np.abs(X_scaled[0] - bmu_weight)
            raw_contrib  = wk * km_contrib + ws * som_contrib
            total_contrib = raw_contrib.sum()
            if total_contrib > 1e-9:
                pct = (raw_contrib / total_contrib * 100)
            else:
                pct = np.zeros_like(raw_contrib)
            feature_contributions = {
                name: round(float(pct[i]), 2)
                for i, name in enumerate(FEATURE_NAMES)
                if i < len(pct)
            }
        except Exception:
            feature_contributions = {}

        return AnomalyResult(
            kmeans=km_result,
            som=som_result,
            combined_score=combined,
            models_agree=models_agree,
            scaled_vector=scaled_list,
            model_version=self.version,
            feature_contributions=feature_contributions,
        )

    def score_dict(self, raw_vector: list[float], **kwargs) -> dict:
        """Convenience wrapper: returns AnomalyResult as a plain dict
        for JSON serialisation into the scan_jobs result_json column."""
        r = self.score(raw_vector, **kwargs)
        return {
            "model_version":        r.model_version,
            "combined_score":       r.combined_score,
            "models_agree":         r.models_agree,
            "feature_contributions": r.feature_contributions or {},
            "kmeans": {
                "cluster_id":          r.kmeans.cluster_id,
                "distance_to_centroid": r.kmeans.distance_to_centroid,
                "anomaly_score":        r.kmeans.anomaly_score,
            },
            "som": {
                "bmu":                 [r.som.bmu_x, r.som.bmu_y],
                "quantization_error":  r.som.quantization_error,
                "anomaly_score":       r.som.anomaly_score,
            },
            "scaled_vector": r.scaled_vector,
        }