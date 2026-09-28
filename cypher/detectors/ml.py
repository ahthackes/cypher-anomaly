from __future__ import annotations
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump, load
from typing import Dict, Any

FEATURE_COLS = [
    "hour","weekday","month",
    "ip_o1","ip_o2","ip_o3","ip_o4","is_private",
    "status","size",
    "is_failed_ssh","is_invalid_user","is_sudo","is_sudo_fail"
]

def train_iforest(df: pd.DataFrame, params: Dict[str, Any]) -> IsolationForest:
    X = df.fillna(0)[FEATURE_COLS].values
    clf = IsolationForest(
        n_estimators=int(params.get("n_estimators",200)),
        max_samples=params.get("max_samples","auto"),
        contamination=float(params.get("contamination",0.02)),
        random_state=int(params.get("random_state",42)),
        n_jobs=-1
    )
    clf.fit(X)
    return clf

def score_iforest(clf: IsolationForest, df: pd.DataFrame) -> pd.DataFrame:
    X = df.fillna(0)[FEATURE_COLS].values
    scores = clf.decision_function(X)  # higher = less anomalous
    preds = clf.predict(X)  # -1 anomalous, 1 normal
    out = df.copy()
    out["anom_score"] = scores
    out["anom_pred"] = preds
    return out

def save_model(clf: IsolationForest, path: str):
    dump(clf, path)

def load_model(path: str) -> IsolationForest:
    return load(path)
