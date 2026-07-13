"""XGBoost inference wrapper. Pure module: no aiokafka.

Loads the committed artifact (services/sentinel/model/sentinel_xgb.json,
trained deterministically by training/train_sentinel.py) and refuses to start
if the sidecar metadata disagrees with this code's feature order or class
layout — an artifact/code drift must fail loudly at boot, not misclassify
quietly at 3am.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import xgboost as xgb

from .features import FEATURE_NAMES

CLASSES = ("benign", "suspicious", "malicious")


class SentinelModel:
    def __init__(self, booster: xgb.Booster) -> None:
        self._booster = booster

    @classmethod
    def load(cls, model_path: str | Path) -> "SentinelModel":
        path = Path(model_path)
        meta = json.loads(path.with_name("metadata.json").read_text(encoding="utf-8"))
        if tuple(meta["feature_names"]) != FEATURE_NAMES:
            raise ValueError(
                f"model artifact feature order {meta['feature_names']} does not "
                f"match app.features.FEATURE_NAMES — retrain via training/train_sentinel.py"
            )
        if tuple(meta["classes"]) != CLASSES:
            raise ValueError(f"model artifact classes {meta['classes']} != {CLASSES}")
        booster = xgb.Booster()
        booster.load_model(str(path))
        return cls(booster)

    def predict(self, feats: dict) -> tuple[float, float, float]:
        """(p_benign, p_suspicious, p_malicious) for one window's features."""
        vec = np.array([[float(feats[name]) for name in FEATURE_NAMES]], dtype=np.float32)
        row = self._booster.inplace_predict(vec)[0]
        return float(row[0]), float(row[1]), float(row[2])

    @property
    def num_trees(self) -> int:
        return self._booster.num_boosted_rounds()
