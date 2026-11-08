"""Performance retention and corpus contract tests (docs/performance/
01_PRODUCT_SPEC.md §9 and §10)."""

from __future__ import annotations

from datetime import timedelta

from shared_models.performance_corpus import CORPUS_EPOCH, generate_corpus
from shared_models.performance_retention import (
    DEFAULT_SAMPLES_DAYS, RetentionPolicy, plan_retention,
)


def test_retention_windows_are_named_policies():
    policy = RetentionPolicy(policy_key="bank-default")
    assert policy.samples_days == DEFAULT_SAMPLES_DAYS
    assert policy.aggregates_days == 365


def test_the_plan_classifies_exactly_and_counts_unknown_rows():
    rows = generate_corpus(20, seed=20261121)
    now = CORPUS_EPOCH + timedelta(days=DEFAULT_SAMPLES_DAYS - 1)
    plan = plan_retention(rows, policy=RetentionPolicy(policy_key="p"),
                          now=now)
    assert plan.retained_total == 20 and plan.expired_total == 0
    later = plan_retention(rows, policy=RetentionPolicy(policy_key="p"),
                           now=CORPUS_EPOCH + timedelta(days=365))
    assert later.expired_total == 20 and later.retained_total == 0
    assert later.as_dict()["expired_total"] == 20
    assert later.as_dict()["note"].startswith("a retention plan is a projection")
