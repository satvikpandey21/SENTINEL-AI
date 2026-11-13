"""Offline controlled development benchmark. Synthetic-only, never a security accuracy claim."""

import argparse
import hashlib
import json
import random
from pathlib import Path

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.anomaly_model import (
    ARTIFACT_FORMAT,
    TRAINER_VERSION,
    AnomalyModel,
    canonical_bytes,
    transform,
)
from sentinel_security.features import FEATURE_SCHEMA, ML_FEATURES, extract


def controlled_windows(seed: int, count: int, kind: str = "normal"):
    """Generate labeled, disjoint synthetic request windows and derive real aggregate features."""
    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark, no security tokens
    result = []
    policy = AnalysisPolicy()
    for _ in range(count):
        requests = rng.randint(30, 90)
        if kind == "burst":
            requests = rng.randint(500, 1000)
        elif kind == "benign_shift":
            requests = rng.randint(100, 180)
        entries = {}
        for i in range(requests):
            endpoint = rng.choice(("/api/items", "/api/items/{id}", "/api/demo/login"))
            failed = rng.random() < 0.005
            error = failed or rng.random() < 0.02
            if kind == "auth":
                endpoint, failed, error = "/api/demo/login", i < 25, i < 25
            elif kind == "scan":
                endpoint, error = f"/controlled/route-{i % 60}", rng.random() < 0.8
            entries[f"{i:032x}"] = {
                "time": rng.uniform(0, 60),
                "endpoint": endpoint,
                "auth": failed,
                "error": error,
                "rate": kind == "burst" and i > 600,
                "episodes": [],
            }
        result.append(extract(entries, policy))
    return result


def train_and_evaluate():
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest

    if sklearn.__version__ != TRAINER_VERSION:
        raise ValueError("training dependency version does not match the supported exporter")
    train = controlled_windows(4101, 512)
    calibration = controlled_windows(4102, 128)
    normal = controlled_windows(4103, 256)
    abnormal = sum(
        (
            controlled_windows(4200 + i, 64, kind)
            for i, kind in enumerate(("burst", "auth", "scan"))
        ),
        [],
    )
    shifted = controlled_windows(4301, 128, "benign_shift")

    def matrix(rows):
        return np.asarray([transform(row.vector()) for row in rows], dtype=np.float32)

    model = IsolationForest(
        n_estimators=32,
        max_samples=128,
        max_features=1.0,
        contamination="auto",
        random_state=41,
        n_jobs=1,
    )
    model.fit(matrix(train))
    # Threshold chosen on normal calibration only, before evaluation labels are examined.
    threshold = max(0.5, float(np.quantile(-model.score_samples(matrix(calibration)), 0.99)))
    artifact = {
        "format": ARTIFACT_FORMAT,
        "version": "experimental-iforest-v1",
        "feature_schema": FEATURE_SCHEMA,
        "features": ML_FEATURES,
        "sklearn_version": TRAINER_VERSION,
        "window_seconds": 60,
        "transform": "log1p-count-interval-v1",
        "max_samples": 128,
        "threshold": threshold,
        "trees": [],
    }
    for estimator in model.estimators_:
        tree = estimator.tree_
        artifact["trees"].append(
            {
                "nodes": [
                    [
                        int(tree.feature[i]),
                        float(tree.threshold[i]),
                        int(tree.children_left[i]),
                        int(tree.children_right[i]),
                        int(tree.n_node_samples[i]),
                    ]
                    for i in range(tree.node_count)
                ]
            }
        )
    from sentinel_security.anomaly_model import Artifact

    validated = Artifact.model_validate(artifact)
    runner = AnomalyModel(AnalysisPolicy())
    runner.artifact = validated
    runner.status = "ready"
    outputs = [runner.infer(row, complete_window=True) for row in normal + abnormal + shifted]
    reference = -model.score_samples(matrix(normal + abnormal + shifted))
    parity = max(
        abs(output["anomaly_score"] - float(expected))
        for output, expected in zip(outputs, reference, strict=True)
    )
    assert parity < 1e-12, "exported inference differs from sklearn"  # noqa: S101
    fp = sum(output["anomalous"] for output in outputs[: len(normal)])
    tp = sum(output["anomalous"] for output in outputs[len(normal) : len(normal) + len(abnormal)])

    def hashes(rows):
        return {hashlib.sha256(canonical_bytes(row.model_dump())).hexdigest() for row in rows}

    datasets = [hashes(rows) for rows in (train, calibration, normal, abnormal, shifted)]
    if any(a & b for i, a in enumerate(datasets) for b in datasets[i + 1 :]):
        raise ValueError("training, calibration, or evaluation records overlap")
    report = {
        "scope": "synthetic controlled anomaly benchmark; not validated attack classification",
        "training": {"normal_windows": len(train), "seed": 4101},
        "calibration": {"normal_windows": len(calibration), "seed": 4102, "quantile": 0.99},
        "evaluation": {
            "normal_windows": len(normal),
            "anomalous_windows": len(abnormal),
            "true_negative": len(normal) - fp,
            "false_positive": fp,
            "true_positive": tp,
            "false_negative": len(abnormal) - tp,
        },
        "benign_shift": {
            "windows": len(shifted),
            "false_positive": sum(o["anomalous"] for o in outputs[-len(shifted) :]),
        },
        "anomaly_breakdown": {
            kind: {
                "windows": 64,
                "flagged": sum(
                    o["anomalous"]
                    for o in outputs[len(normal) + i * 64 : len(normal) + (i + 1) * 64]
                ),
            }
            for i, kind in enumerate(("burst", "auth", "scan"))
        },
        "dataset_sha256": {
            name: hashlib.sha256("".join(sorted(hashes(rows))).encode()).hexdigest()
            for name, rows in (
                ("training", train),
                ("calibration", calibration),
                ("evaluation_normal", normal),
                ("evaluation_anomalous", abnormal),
                ("benign_shift", shifted),
            )
        },
        "threshold": threshold,
        "max_sklearn_export_error": parity,
        "model_sha256": hashlib.sha256(canonical_bytes(artifact)).hexdigest(),
        "sklearn_version": sklearn.__version__,
        "feature_schema": FEATURE_SCHEMA,
        "features": ML_FEATURES,
        "sample_inference": {"normal": outputs[0], "burst": outputs[len(normal)]},
    }
    return artifact, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    artifact, report = train_and_evaluate()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "experimental-iforest-v1.json").write_bytes(canonical_bytes(artifact))
    (args.output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
