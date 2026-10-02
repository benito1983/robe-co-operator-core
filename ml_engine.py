# backend/affiliate/ml_engine.py
#
# Pure ML logic for the Affiliate module - regression/decision-tree
# sales forecasting, k-means product clustering, nearest-neighbor
# product recommendations. Ported from robe_mobile's ml_engine.py
# (itself ported from the CLI's MLEngine class) - same scikit-learn
# models, same feature set, same thresholds, same math throughout.
#
# Two deliberate deviations from the source, both about SEPARATION OF
# CONCERNS rather than the ML logic itself:
#
# 1. No file I/O, no DB in here at all. The JSON version's MLEngine
#    loaded/saved its own joblib .pkl files directly (self.model_dir).
#    This one only exports/imports models as in-memory objects or bytes
#    (export_models()/import_models() below) - actual persistence lives
#    in ml_model_repository.py, the same Repository Layer split every
#    other module on this platform already follows (business logic
#    never touches storage directly).
#
# 2. No duplicate score formula. The source computed its own
#    "_calc_score()" from a product's "historie" list - a second copy
#    of the SAME formula already implemented in
#    analytics.py::product_score() (Baustein 1). Here, the caller
#    (ml_service.py) computes the score once via analytics.py and
#    passes it in as part of each row - one formula, one place, no risk
#    of the two ever drifting apart.
#
# OPEN QUESTION RESOLVED 23.09.2026: the four "# PRUEFEN" spots from the
# .pyc reconstruction were reviewed against the mobile port + CLI behavior:
# FEATURE_COLUMNS (clicks/price/commission/score), DecisionTree max_depth=5,
# cluster features (clicks/sales/price/commission) and similar-products
# features (+score) are all INTENTIONAL and kept. Markers removed.
from __future__ import annotations

import hashlib
import hmac
import io
import logging
import os
import warnings
from datetime import datetime
from statistics import mean, stdev
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.linear_model import HuberRegressor
from sklearn.metrics import r2_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeRegressor

_logger = logging.getLogger(__name__)
_UNSIGNED_FALLBACK = False

Row = dict[str, Any]

FEATURE_COLUMNS = ["clicks", "price", "commission", "score"]

# Reviewed 23.09.2026: feature sets below are intentional (see header note).
CLUSTER_FEATURES = ["clicks", "sales", "price", "commission"]
SIMILARITY_FEATURES = ["clicks", "sales", "price", "commission", "score"]
DT_MAX_DEPTH = 5


class MLEngine:
    """Stateful on purpose - one instance holds one org's fitted models
    (or none yet). Instantiate fresh, then either train_all() or
    import_models() before calling any of the prediction/analysis
    methods."""

    def __init__(self):
        self.lr_model = None
        self.dt_model = None
        self.kmeans_model = None
        self.scaler = None
        self.last_training: str | None = None
        self.lr_score: float | None = None
        self.dt_score: float | None = None
        self._training_stats: dict[str, Any] | None = None

    @property
    def training_stats(self) -> dict[str, Any] | None:
        return self._training_stats

    # -- training ---------------------------------------------------------

    @staticmethod
    def _outlier_mask(values: list[float], threshold: float = 3.0) -> list[bool]:
        n = len(values)
        if n < 5:
            return [True] * n
        m = mean(values)
        s = stdev(values)
        if s == 0:
            return [True] * n
        return [abs((v - m) / s) <= threshold for v in values]

    def train_all(self, rows: list[Row]) -> tuple[bool, str]:
        """`rows` is one dict per product: {"name","clicks","sales",
        "price","commission","score"} - see ml_service.build_training_rows().
        Returns (success, message); message is the same German
        user-facing text the JSON version already produced, unchanged -
        it's meant to reach an end-user screen eventually."""
        df = pd.DataFrame(rows)

        if len(df) < 20:
            return False, "Zu wenige Daten (mind. 20 Produkte) – Training übersprungen."

        messages = []

        clicks_mask = self._outlier_mask(df["clicks"].tolist(), threshold=3.0)
        sales_mask = self._outlier_mask(df["sales"].tolist(), threshold=3.0)
        mask = [c and s for c, s in zip(clicks_mask, sales_mask, strict=False)]

        df_training = df[mask].reset_index(drop=True)
        excluded_count = len(df) - len(df_training)

        if len(df_training) < 5:
            df_training = df
            excluded_count = 0

        if excluded_count:
            messages.append(
                f"{excluded_count} Ausreißer beim Training ausgeschlossen (Produktdaten unverändert)."
            )

        X = df_training[FEATURE_COLUMNS]
        y = df_training["sales"]

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            y_train_log = np.log1p(y_train)

            self.lr_model = HuberRegressor()
            self.lr_model.fit(X_train, y_train_log)

            if len(X_test) > 0:
                lr_pred_log = self.lr_model.predict(X_test)
                lr_pred = np.expm1(lr_pred_log)
                try:
                    raw_r2 = r2_score(y_test, lr_pred)
                except Exception:
                    raw_r2 = 0.0
                # M2: r2 is undefined for constant y_test (NaN) - report 0.0.
                lr_score = float(np.nan_to_num(raw_r2, nan=0.0, posinf=0.0, neginf=0.0))
            else:
                lr_score = 0
            messages.append(f"Robuste Regression trainiert (R² = {lr_score:.2f})")

            self.dt_model = DecisionTreeRegressor(max_depth=DT_MAX_DEPTH, random_state=42)
            self.dt_model.fit(X_train, y_train)
            if len(X_test) > 0:
                try:
                    raw_dt = self.dt_model.score(X_test, y_test)
                except Exception:
                    raw_dt = 0.0
                dt_score = float(np.nan_to_num(raw_dt, nan=0.0, posinf=0.0, neginf=0.0))
            else:
                dt_score = 0
            messages.append(f"Entscheidungsbaum trainiert (R² = {dt_score:.2f})")

            cluster_features = df[CLUSTER_FEATURES]
            self.scaler = StandardScaler()
            cluster_scaled = self.scaler.fit_transform(cluster_features)

            # M3: at least 2 products per cluster - 5 products -> max 2 clusters,
            # not 3 single-item "clusters".
            n_clusters = max(1, min(3, len(df) // 2))
            self.kmeans_model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            self.kmeans_model.fit(cluster_scaled)
            messages.append(f"Clustering abgeschlossen ({n_clusters} Gruppen)")

        self.last_training = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.lr_score = round(float(lr_score), 3)
        self.dt_score = round(float(dt_score), 3)
        self._training_stats = self._data_snapshot(rows)
        self._training_stats["lr_score"] = self.lr_score
        self._training_stats["dt_score"] = self.dt_score
        self._training_stats["outliers_excluded"] = excluded_count

        return True, " · ".join(messages)

    @staticmethod
    def _data_snapshot(rows: list[Row]) -> dict[str, Any]:
        return {
            "product_count": len(rows),
            "total_clicks": sum(r.get("clicks", 0) for r in rows),
            "total_sales": sum(r.get("sales", 0) for r in rows),
            "products_snapshot": {
                r.get("name", f"product_{i}"): {
                    "clicks": r.get("clicks", 0),
                    "sales": r.get("sales", 0),
                }
                for i, r in enumerate(rows)
            },
        }

    @staticmethod
    def _single_product_changed(
        old: float, new: float, threshold_percent: float, min_absolute: float = 5
    ) -> bool:
        diff = abs(new - old)
        if diff < min_absolute:
            return False
        if old == 0:
            return True
        return diff / old * 100 > threshold_percent

    def is_stale(
        self, current_rows: list[Row], threshold_percent: float = 30
    ) -> tuple[bool, str | None]:
        """(False, None) if this engine has never been trained - same as
        the JSON version's "no training-time snapshot yet" case."""
        stats_at_training = self._training_stats
        if not stats_at_training:
            return False, None

        current = self._data_snapshot(current_rows)

        def changed(old_value, new_value) -> bool:
            if old_value == 0:
                return new_value > 0
            return abs(new_value - old_value) / old_value * 100 > threshold_percent

        reasons = []

        if changed(stats_at_training["product_count"], current["product_count"]):
            reasons.append(
                f"Produkte: {stats_at_training['product_count']} → {current['product_count']}"
            )
        if changed(stats_at_training["total_clicks"], current["total_clicks"]):
            reasons.append(
                f"Klicks: {stats_at_training['total_clicks']} → {current['total_clicks']}"
            )
        if changed(stats_at_training["total_sales"], current["total_sales"]):
            reasons.append(
                f"Verkäufe: {stats_at_training['total_sales']} → {current['total_sales']}"
            )

        snapshot_at_training = stats_at_training.get("products_snapshot", {})
        if snapshot_at_training:
            hits = []
            for row in current_rows:
                name = row.get("name", "")
                old = snapshot_at_training.get(name)
                if old is None:
                    continue

                clicks_changed = self._single_product_changed(
                    old["clicks"], row.get("clicks", 0), threshold_percent
                )
                sales_changed = self._single_product_changed(
                    old["sales"], row.get("sales", 0), threshold_percent
                )

                if clicks_changed or sales_changed:
                    hits.append(
                        f"{name} (Klicks: {old['clicks']} → {row.get('clicks', 0)}, "
                        f"Verkäufe: {old['sales']} → {row.get('sales', 0)})"
                    )

            if hits:
                shown = hits[:3]
                rest = len(hits) - len(shown)
                text = "Einzelne Produkte stark verändert: " + "; ".join(shown)
                if rest > 0:
                    text += f" (+{rest} weitere)"
                reasons.append(text)

        if reasons:
            return (
                True,
                "Daten haben sich seit dem letzten Training deutlich verändert ("
                + "; ".join(reasons)
                + ").",
            )

        return False, None

    # -- prediction ---------------------------------------------------------

    def predict_sales_linear(self, clicks, price, commission, score) -> float | None:
        if self.lr_model is None:
            return None
        X = [[clicks, price, commission, score]]
        pred_log = self.lr_model.predict(X)[0]
        pred = max(0.0, np.expm1(pred_log))
        return round(float(pred), 1)

    def predict_sales_tree(self, clicks, price, commission, score) -> float | None:
        if self.dt_model is None:
            return None
        X = [[clicks, price, commission, score]]
        return round(float(self.dt_model.predict(X)[0]), 1)

    def cluster_products(self, rows: list[Row]) -> list[dict[str, Any]] | None:
        if self.kmeans_model is None:
            return None

        df = pd.DataFrame(rows)
        features = df[CLUSTER_FEATURES]
        scaled = self.scaler.transform(features)
        clusters = self.kmeans_model.predict(scaled)

        result = []
        for i, row in df.iterrows():
            result.append(
                {
                    "name": row["name"],
                    "clicks": row["clicks"],
                    "sales": row["sales"],
                    "price": row["price"],
                    "commission": row["commission"],
                    "cluster": int(clusters[i]),
                }
            )
        return result

    def cluster_summary(self, rows: list[Row]):
        """List of per-cluster dicts, or the German "nothing trained
        yet" fallback string - same shape as the JSON version, callers
        already branch on `isinstance(result, str)`."""
        cluster_data = self.cluster_products(rows)
        if not cluster_data:
            return "Keine Cluster verfügbar."

        groups: dict[int, list[dict[str, Any]]] = {}
        for item in cluster_data:
            groups.setdefault(item["cluster"], []).append(item)

        summary = []
        for cluster_id, items in sorted(groups.items()):
            avg_clicks = sum(i["clicks"] for i in items) / len(items)
            avg_sales = sum(i["sales"] for i in items) / len(items)
            avg_price = sum(i["price"] for i in items) / len(items)

            names = ", ".join(i["name"] for i in items[:3])
            if len(items) > 3:
                names += " und " + str(len(items) - 3) + " weitere"

            summary.append(
                {
                    "cluster_id": cluster_id,
                    "count": len(items),
                    "avg_clicks": round(avg_clicks, 1),
                    "avg_sales": round(avg_sales, 1),
                    "avg_price": round(avg_price, 2),
                    "products_text": names,
                }
            )

        return summary

    def compare_all_products(self, rows: list[Row]) -> list[dict[str, Any]] | None:
        if self.lr_model is None or self.dt_model is None:
            return None

        df = pd.DataFrame(rows)
        X = df[FEATURE_COLUMNS]

        lr_preds_log = self.lr_model.predict(X)
        lr_preds = np.maximum(0.0, np.expm1(lr_preds_log))
        dt_preds = self.dt_model.predict(X)

        results = []
        for i, row in df.iterrows():
            actual = row["sales"]
            lr_pred = round(float(lr_preds[i]), 1)
            dt_pred = round(float(dt_preds[i]), 1)
            results.append(
                {
                    "name": row["name"],
                    "actual": actual,
                    "lr_prediction": lr_pred,
                    "dt_prediction": dt_pred,
                    "lr_deviation": round(lr_pred - actual, 1),
                    "dt_deviation": round(dt_pred - actual, 1),
                }
            )
        return results

    def similar_products(self, product_name: str, rows: list[Row], top_n: int = 5):
        """Z-score standardised Euclidean distance - doesn't need a trained
        model at all (same as the JSON version, whose screen loaded models
        only as an unused side effect).

        2: raw Euclidean on [clicks, sales, price, commission, score] is
        dominated by clicks/sales (4-stellig) while commission/score
        (1-2-stellig) vanish. Standardise per-column from the current
        rows (mean/std, std==0 -> 1.0) so every feature contributes.
        Single-row orgs return [] (nothing to compare)."""
        df = pd.DataFrame(rows)
        if len(df) < 2:
            return []
        matches = df.index[df["name"] == product_name]
        if len(matches) == 0:
            return None
        idx = matches[0]

        features = SIMILARITY_FEATURES
        matrix = df[features].astype(float).to_numpy()
        means = matrix.mean(axis=0)
        stds = matrix.std(axis=0)
        stds[stds == 0] = 1.0
        scaled = (matrix - means) / stds

        # idx comes from df.index, so get_loc always succeeds - no fallback.
        pos = df.index.get_loc(idx)
        target_vector = scaled[pos]

        distances = []
        for i, row in df.iterrows():
            if i == idx:
                continue
            ipos = df.index.get_loc(i)
            vec = scaled[ipos]
            dist = float(np.linalg.norm(vec - target_vector))
            distances.append((row["name"], dist))

        distances.sort(key=lambda x: x[1])
        return distances[:top_n]

    # -- (de)serialization, used by ml_model_repository.py -------------------

    def export_models(self) -> dict[str, bytes]:
        """Serializes the four fitted model objects to bytes (joblib
        into an in-memory buffer, no filesystem involved) -
        ml_model_repository.py writes these straight into the
        ml_models table's BYTEA columns."""
        return {
            "lr_model": _dump_bytes(self.lr_model),
            "dt_model": _dump_bytes(self.dt_model),
            "kmeans_model": _dump_bytes(self.kmeans_model),
            "scaler": _dump_bytes(self.scaler),
        }

    def import_models(
        self,
        blobs: dict[str, bytes],
        lr_score,
        dt_score,
        training_stats: dict[str, Any],
        trained_at: str,
    ) -> None:
        """7: explicit guard - a NULL column or partial row used to raise
        a bare KeyError/TypeError deep in joblib. Fail with a clear
        message so ops knows to re-train instead of debugging pickle."""
        required = ("lr_model", "dt_model", "kmeans_model", "scaler")
        missing = [k for k in required if not blobs.get(k)]
        if missing:
            raise ValueError(
                f"Incomplete ML model row - missing blobs: {missing}. Re-train the model."
            )
        self.lr_model = _load_bytes(blobs["lr_model"])
        self.dt_model = _load_bytes(blobs["dt_model"])
        self.kmeans_model = _load_bytes(blobs["kmeans_model"])
        self.scaler = _load_bytes(blobs["scaler"])
        self.lr_score = float(lr_score)
        self.dt_score = float(dt_score)
        self._training_stats = training_stats
        self.last_training = trained_at


def _get_hmac_key() -> bytes | None:
    """Get HMAC key from environment. Returns None with warning if not set."""
    global _UNSIGNED_FALLBACK
    key_hex = os.environ.get("ROBE_ML_HMAC_KEY", "").strip()
    if not key_hex:
        if not _UNSIGNED_FALLBACK:
            _logger.warning(
                "ROBE_ML_HMAC_KEY not set - ML models stored WITHOUT integrity signing. "
                "Set this key for production deployments."
            )
            _UNSIGNED_FALLBACK = True
        return None
    key = bytes.fromhex(key_hex)
    if len(key) < 32:
        raise RuntimeError("ROBE_ML_HMAC_KEY must be at least 32 bytes (64 hex chars)")
    return key


def _dump_bytes(obj) -> bytes:
    """Serialize with optional HMAC signature."""
    buffer = io.BytesIO()
    joblib.dump(obj, buffer, compress=3)
    payload = buffer.getvalue()
    key = _get_hmac_key()
    if key is None:
        return b"\x00" + payload  # \x00 = unsigned marker
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return b"\x01" + signature.encode("ascii") + payload  # \x01 = signed marker


def _load_bytes(data: bytes):
    """Deserialize with optional HMAC verification."""
    if not data:
        raise ValueError("ML model blob is empty")
    marker = data[0:1]
    if marker == b"\x00":
        return joblib.load(io.BytesIO(data[1:]))
    elif marker == b"\x01":
        if len(data) < 65:  # 1 marker + 64 signature
            raise ValueError("ML model blob too short or corrupted")
        signature = data[1:65].decode("ascii")
        payload = data[65:]
        key = _get_hmac_key()
        if key is None:
            raise ValueError("Cannot verify signed ML model - ROBE_ML_HMAC_KEY is not set")
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("ML model integrity check failed - blob may have been tampered with")
        return joblib.load(io.BytesIO(payload))
    else:
        # B1/S1: legacy blobs without integrity marker (pre-HMAC rows).
        # Reject in strict mode; allow only when explicitly opted in via
        # ROBE_ML_ALLOW_LEGACY=1 (one-time migration path, logs a warning).
        if os.environ.get("ROBE_ML_ALLOW_LEGACY", "").strip() == "1":
            _logger.warning(
                "Loading legacy unsigned ML model blob (no integrity marker). "
                "Re-train to migrate to signed format."
            )
            return joblib.load(io.BytesIO(data))
        raise ValueError(
            "Legacy unsigned ML model blob rejected - re-train the model "
            "(or set ROBE_ML_ALLOW_LEGACY=1 for one-time migration)."
        )


def model_quality_text(score: float | None) -> str:
    """1:1 aus main.py::_modellguete_text() uebernommen."""
    if score is None:
        return "Modellgüte unbekannt (noch nicht trainiert)"
    if score >= 0.5:
        return f"R² = {score:.2f} – gute Modellgüte"
    elif score >= 0.2:
        return f"R² = {score:.2f} – mäßige Modellgüte"
    else:
        return f"R² = {score:.2f} – wenig verlässlich"
