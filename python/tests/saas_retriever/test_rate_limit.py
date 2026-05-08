"""Adaptive token bucket + global rate limiter smoke tests."""

from __future__ import annotations

import asyncio

import pytest

from saas_retriever import (
    AdaptiveTokenBucket,
    BucketKey,
    GlobalRateLimiter,
    RateLimited,
)


def test_bucket_key_is_hashable() -> None:
    a = BucketKey(connector_kind="github", tenant_id="org:plenoai")
    b = BucketKey(connector_kind="github", tenant_id="org:plenoai")
    assert hash(a) == hash(b)
    assert {a, b} == {a}


def test_bucket_rejects_zero_capacity_or_rate() -> None:
    with pytest.raises(ValueError):
        AdaptiveTokenBucket(capacity=0.0, rate=10.0)
    with pytest.raises(ValueError):
        AdaptiveTokenBucket(capacity=10.0, rate=0.0)


def test_bucket_rejects_cost_above_capacity() -> None:
    bucket = AdaptiveTokenBucket(capacity=10.0, rate=10.0)
    with pytest.raises(ValueError, match="exceeds bucket capacity"):
        asyncio.run(bucket.acquire(cost=100.0))


@pytest.mark.asyncio
async def test_bucket_acquire_within_capacity_does_not_block() -> None:
    bucket = AdaptiveTokenBucket(capacity=100.0, rate=1.0)
    # Capacity available immediately on construction; the loop runs to
    # completion well under the per-token wait time.
    for _ in range(5):
        await bucket.acquire(cost=1.0)


@pytest.mark.asyncio
async def test_bucket_acquire_times_out_when_starved() -> None:
    # rate=1/s, capacity=1 — second call needs a full second; timeout=0.05s.
    bucket = AdaptiveTokenBucket(capacity=1.0, rate=1.0)
    await bucket.acquire(cost=1.0)
    with pytest.raises(RateLimited):
        await bucket.acquire(cost=1.0, timeout=0.05)


def test_throttle_signal_factor_validated() -> None:
    bucket = AdaptiveTokenBucket(capacity=10.0, rate=10.0)
    with pytest.raises(ValueError, match="factor"):
        bucket.on_throttle_signal(factor=0.0)
    with pytest.raises(ValueError, match="factor"):
        bucket.on_throttle_signal(factor=1.0)


def test_throttle_signal_halves_rate_then_recovery_grows_back() -> None:
    bucket = AdaptiveTokenBucket(capacity=10.0, rate=10.0)
    bucket.on_throttle_signal(factor=0.5)
    assert bucket.current_rate == 5.0
    bucket.on_throttle_signal(factor=0.5)
    assert bucket.current_rate == 2.5
    bucket.on_success(recovery=2.5)
    assert bucket.current_rate == 5.0
    bucket.on_success(recovery=100.0)  # capped at ceiling
    assert bucket.current_rate == 10.0


def test_throttle_signal_floor_protects_against_zero_rate() -> None:
    bucket = AdaptiveTokenBucket(capacity=10.0, rate=10.0)
    for _ in range(20):
        bucket.on_throttle_signal(factor=0.5)
    assert bucket.current_rate >= 0.5  # _MIN_RATE


def test_recovery_must_be_positive() -> None:
    bucket = AdaptiveTokenBucket(capacity=10.0, rate=10.0)
    with pytest.raises(ValueError):
        bucket.on_success(recovery=0.0)


# --- GlobalRateLimiter --------------------------------------------------


def test_limiter_requires_positive_defaults() -> None:
    with pytest.raises(ValueError):
        GlobalRateLimiter(default_capacity=0.0)
    with pytest.raises(ValueError):
        GlobalRateLimiter(default_rate=0.0)


def test_limiter_configure_pin_per_kind() -> None:
    limiter = GlobalRateLimiter()
    limiter.configure("github", capacity=5000.0, rate=1.39)
    with pytest.raises(ValueError):
        limiter.configure("github", capacity=0.0, rate=1.0)


@pytest.mark.asyncio
async def test_limiter_acquires_per_bucket() -> None:
    limiter = GlobalRateLimiter(default_capacity=10.0, default_rate=10.0)
    a = BucketKey(connector_kind="github", tenant_id="org:a")
    b = BucketKey(connector_kind="github", tenant_id="org:b")
    # Both tenants share kind but get distinct buckets — exhausting one
    # must not affect the other.
    for _ in range(10):
        await limiter.acquire(a)
    await limiter.acquire(b)  # b is fresh, succeeds immediately
    with pytest.raises(RateLimited):
        await limiter.acquire(a, timeout=0.05)


@pytest.mark.asyncio
async def test_limiter_throttle_and_success_route_to_right_bucket() -> None:
    limiter = GlobalRateLimiter(default_capacity=10.0, default_rate=10.0)
    key = BucketKey(connector_kind="slack", tenant_id="T01")
    await limiter.on_throttle_signal(key, factor=0.5)
    await limiter.on_success(key, recovery=1.0)
    # Smoke check: the bucket exists and reports a sane rate.
    bucket = limiter._buckets[key]
    assert 0 < bucket.current_rate <= bucket.rate
