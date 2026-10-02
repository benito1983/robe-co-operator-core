# backend/affiliate/ml_service.py
#
# Orchestration for the Affiliate module's ML features (Baustein 6.2) -
# training, staleness checks, sales forecasting, clustering, comparison,
# similar-product lookup. Ties together ProductRepository (product +
# daily-stats data), analytics.py (the single score formula - see
# ml_engine.py's header for why the JSON version's duplicate was
# removed), ml_engine.py (the actual scikit-learn models) and
# ml_model_repository.py (persistence).
#
# Mirrors amazon_sync.py's shape: a thin org-scoped orchestration layer,
# blocking/synchronous on purpose - training in particular is CPU-bound
# and was already run off the UI thread in the mobile app
# (asyncio.to_thread() in produkt_ml.py); an eventual API/UI layer here
# carries the same responsibility.
from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from backend.affiliate.analytics import product_score
from backend.affiliate.ml_engine import MLEngine, model_quality_text
from backend.affiliate.ml_model_repository import MLModelRepository
from backend.affiliate.repository import ProductRepository

MIN_PRODUCTS_FOR_TRAINING = 20
# 6: bound process-local cache (was unbounded dict -> OOM at scale).
MAX_CACHED_ENGINES = 100

# In-process cache of already-deserialized engines, keyed by org_id - a
# prediction/cluster/comparison/staleness call would otherwise pay for a
# Postgres round-trip PLUS four joblib.load() deserializations (compressed
# sklearn models) on every single request, even though the underlying
# model only changes when train() runs. Keyed per org_id (never a single
# shared instance) to keep the "no shared mutable state between orgs"
# rule this platform already follows elsewhere (see ai_service.py) - one
# org's cached engine can never leak into another org's response.
#
# Invalidation contract: train() below updates this cache itself right
# after a successful save (with the engine already in memory - no need to
# round-trip through the DB again). Any OTHER code path that changes or
# removes an org's persisted model (e.g. a future "delete my model" admin
# action calling MLModelRepository.delete() directly) MUST also call
# invalidate_engine_cache(org_id), or a stale engine keeps being served
# from this process's cache until it restarts.
#
# B12 multi-worker note: the cache is process-local by design. To avoid
# serving a stale engine after ANOTHER worker trained, load_engine()
# compares the cached engine's trained_at against a lightweight
# SELECT trained_at version token (no model payload). Mismatch ->
# reload from DB. Clock skew tolerant: string comparison of the
# formatted timestamp.
_engine_cache: OrderedDict[UUID, MLEngine] = OrderedDict()
_engine_cache_lock = threading.Lock()


def _cache_store(org_id: UUID, engine: MLEngine) -> None:
    """6: LRU insert with eviction at MAX_CACHED_ENGINES."""
    with _engine_cache_lock:
        _engine_cache.pop(org_id, None)
        _engine_cache[org_id] = engine
        _engine_cache.move_to_end(org_id)
        while len(_engine_cache) > MAX_CACHED_ENGINES:
            _engine_cache.popitem(last=False)


def _cache_get(org_id: UUID) -> MLEngine | None:
    with _engine_cache_lock:
        engine = _engine_cache.get(org_id)
        if engine is not None:
            _engine_cache.move_to_end(org_id)
        return engine


def _cache_pop(org_id: UUID) -> None:
    with _engine_cache_lock:
        _engine_cache.pop(org_id, None)


def invalidate_engine_cache(org_id: UUID) -> None:
    """Drops the cached engine for one org, if any is cached. Call this
    after any write to ml_models that doesn't go through train() (which
    already keeps the cache in sync itself) - see the cache's docstring
    above for why this matters."""
    _cache_pop(org_id)


def build_training_rows(org_id: UUID) -> list[dict[str, Any]]:
    """One row per product with its current score - the exact input
    shape train_all()/cluster_products()/compare_all_products()/
    similar_products() all expect. Recomputed fresh on every call
    (cheap: pure functions over already-loaded data, never cached) - a
    stale cached score would silently skew every ML result that reads
    it."""
    products_repo = ProductRepository()
    products = products_repo.list_all(org_id)

    rows = []
    for product in products:
        daily_stats = products_repo.daily_stats(org_id, product["id"])
        rows.append(
            {
                "name": product["name"],
                "clicks": int(product.get("clicks", 0)),
                "sales": int(product.get("sales", 0)),
                "price": float(product.get("price", 0)),
                "commission": float(product.get("commission_percent", 0)),
                "score": product_score(product, daily_stats),
            }
        )
    return rows


def load_engine(org_id: UUID) -> MLEngine | None:
    """None if the org has never trained a model - same "nothing to
    load yet" signal the JSON version's load_models() == False gave.

    Cached per org after the first call (see _engine_cache above) - a
    cache hit skips both the Postgres round-trip and the four joblib
    deserializations entirely. B12: validates against the DB version
    token first so a train() on another worker invalidates us."""
    cached = _cache_get(org_id)
    if cached is not None:
        try:
            db_version = MLModelRepository().get_trained_at(org_id)
        except Exception:
            return cached
        if db_version is None:
            _cache_pop(org_id)
            return None
        cached_version = getattr(cached, "last_training", None)
        db_version_str = (
            db_version.strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(db_version, "strftime")
            else str(db_version)
        )
        if cached_version == db_version_str:
            return cached
        # version mismatch -> fall through to full reload

    row = MLModelRepository().get(org_id)
    if row is None:
        return None

    engine = MLEngine()
    engine.import_models(
        blobs={
            "lr_model": bytes(row["lr_model"]),
            "dt_model": bytes(row["dt_model"]),
            "kmeans_model": bytes(row["kmeans_model"]),
            "scaler": bytes(row["scaler"]),
        },
        lr_score=row["lr_score"],
        dt_score=row["dt_score"],
        training_stats=row["training_stats"],
        trained_at=row["trained_at"].strftime("%Y-%m-%d %H:%M:%S"),
    )

    _cache_store(org_id, engine)
    return engine


def train(org_id: UUID) -> dict[str, Any]:
    """{"success": bool, "message": str} - message is the same German
    user-facing text MLEngine.train_all() already produces (including
    the too-few-data case), unchanged shape for a future screen to
    reuse as-is."""
    rows = build_training_rows(org_id)
    if len(rows) < MIN_PRODUCTS_FOR_TRAINING:
        return {
            "success": False,
            "message": "Zu wenige Daten (mind. 20 Produkte) – Training übersprungen.",
        }

    engine = MLEngine()
    success, message = engine.train_all(rows)

    if success:
        MLModelRepository().save(
            org_id,
            blobs=engine.export_models(),
            lr_score=engine.lr_score,
            dt_score=engine.dt_score,
            training_stats=engine.training_stats,
            trained_at=datetime.now(UTC),
        )
        # Cache the engine we already have in memory instead of just
        # invalidating and letting the next load_engine() call round-trip
        # through Postgres + joblib again for data we already hold.
        _cache_store(org_id, engine)

    return {"success": success, "message": message}


def staleness_check(org_id: UUID) -> dict[str, Any]:
    """{"status": "no_model" | "fresh" | "stale", "reason": str | None}."""
    engine = load_engine(org_id)
    if engine is None:
        return {"status": "no_model", "reason": None}

    rows = build_training_rows(org_id)
    is_stale, reason = engine.is_stale(rows)
    return {"status": "stale" if is_stale else "fresh", "reason": reason}


def predict_for_product(org_id: UUID, product_id: UUID) -> dict[str, Any] | None:
    """None if there's no trained model yet, OR the product doesn't
    exist in this org - same fail-closed shape used everywhere else on
    this platform."""
    engine = load_engine(org_id)
    if engine is None:
        return None

    products_repo = ProductRepository()
    product = products_repo.get(org_id, product_id)
    if product is None:
        return None

    daily_stats = products_repo.daily_stats(org_id, product_id)
    score = product_score(product, daily_stats)
    clicks = int(product.get("clicks", 0))
    price = float(product.get("price", 0))
    commission = float(product.get("commission_percent", 0))

    return {
        "lr_prediction": engine.predict_sales_linear(clicks, price, commission, score),
        "dt_prediction": engine.predict_sales_tree(clicks, price, commission, score),
        "lr_quality": model_quality_text(engine.lr_score),
        "dt_quality": model_quality_text(engine.dt_score),
        "current_sales": int(product.get("sales", 0)),
    }


def cluster_summary(org_id: UUID):
    """None if there's no trained model, else the same list-of-dicts /
    German-fallback-string shape MLEngine.cluster_summary() returns."""
    engine = load_engine(org_id)
    if engine is None:
        return None
    return engine.cluster_summary(build_training_rows(org_id))


def compare_all_products(org_id: UUID):
    engine = load_engine(org_id)
    if engine is None:
        return None
    return engine.compare_all_products(build_training_rows(org_id))


def similar_products(org_id: UUID, product_name: str, top_n: int = 5):
    """Doesn't need a trained model at all (pure feature-distance calc)
    - same as the JSON version's empfehlungen(), whose screen called
    load_models() only for a side effect it never used."""
    engine = MLEngine()
    return engine.similar_products(product_name, build_training_rows(org_id), top_n=top_n)
