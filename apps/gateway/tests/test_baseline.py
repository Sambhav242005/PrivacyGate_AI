"""PG-015/T-23: baseline beats random on synthetic holdout. Stdlib only."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from apps.gateway.ai.baseline import MODEL_VERSION, evaluate
from apps.gateway.ai.dataset import DEFAULT_SEED, generate_dataset


def test_baseline_beats_random_on_holdout():
    _, test = generate_dataset(seed=DEFAULT_SEED)
    m = evaluate(test)
    n = m["n"]
    n_pos = m["tp"] + m["fn"]
    prevalence = n_pos / n
    # Random classifier predicting positive at prevalence rate:
    rand_precision = prevalence
    rand_recall = prevalence
    rand_f1 = 2 * rand_precision * rand_recall / (rand_precision + rand_recall)
    print(f"\nmodel={m['model_version']} seed={DEFAULT_SEED} n={n} "
          f"TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']} "
          f"P={m['precision']} R={m['recall']} F1={m['f1']} "
          f"FPR={m['fpr']} FNR={m['fnr']} rand_F1={rand_f1:.4f}")
    assert m["model_version"] == MODEL_VERSION == "rule-v1"
    assert m["tp"] + m["fp"] + m["tn"] + m["fn"] == n
    assert m["precision"] > rand_precision, "baseline must beat random precision"
    assert m["recall"] > rand_recall, "baseline must beat random recall"
    assert m["f1"] > rand_f1 and m["f1"] > 0.5


def test_splits_disjoint_and_reproducible():
    train1, test1 = generate_dataset(seed=DEFAULT_SEED)
    train2, test2 = generate_dataset(seed=DEFAULT_SEED)
    assert train1 == train2 and test1 == test2
    assert len(train1) == 900 and len(test1) == 300
