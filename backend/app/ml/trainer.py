"""
Training & Evaluation Pipeline for Moriarty SQL Injection ML Model.

Builds, trains, evaluates, and serializes a lightweight, deterministic
TF-IDF + Logistic Regression classification pipeline for SQL injection detection.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

from app.ml.dataset import get_dataset

MODEL_VERSION = "1.0.0"
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent / "models" / "v1"


def build_pipeline() -> Pipeline:
    """
    Construct the TF-IDF and Logistic Regression classification pipeline.
    Uses character n-grams with word boundaries to capture syntax patterns
    (e.g., quotes, string concatenation, f-string prefixes, parameter markers).
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        min_df=1,
        sublinear_tf=True,
    )
    classifier = LogisticRegression(
        C=2.0,
        solver="lbfgs",
        max_iter=500,
        random_state=42,
    )
    return Pipeline([
        ("vectorizer", vectorizer),
        ("classifier", classifier),
    ])


def train_and_evaluate(
    model_dir: Path | None = None,
    test_size: float = 0.25,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Train the model on curated samples, evaluate on holdout test split,
    and persist the model artifact and metadata to disk.
    """
    samples = get_dataset()
    X = [s.code for s in samples]
    y = [s.label for s in samples]

    # Stratified train/test split to preserve balance without data leakage
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    pipeline = build_pipeline()

    # 5-fold cross-validation on training partition
    cv = StratifiedKFold(n_splits=4, shuffle=True, random_state=random_state)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")

    # Fit final pipeline on training set
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test partition
    y_pred = pipeline.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    # Refit on full dataset for maximum generalization in production
    full_pipeline = build_pipeline()
    full_pipeline.fit(X, y)

    # Target directory setup
    out_dir = model_dir or DEFAULT_MODEL_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    model_file = out_dir / "sql_injection_model.joblib"
    joblib.dump(full_pipeline, model_file)

    metadata: dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "model_type": "TfidfVectorizer(char_wb, 2-5) + LogisticRegression(C=2.0)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(samples),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics": {
            "test_accuracy": round(acc, 4),
            "test_precision": round(prec, 4),
            "test_recall": round(rec, 4),
            "test_f1": round(f1, 4),
            "cv_f1_mean": round(float(cv_scores.mean()), 4),
            "cv_f1_std": round(float(cv_scores.std()), 4),
        },
        "artifact_file": model_file.name,
    }

    metadata_file = out_dir / "model_metadata.json"
    metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return metadata


if __name__ == "__main__":
    meta = train_and_evaluate()
    print("Moriarty ML Model Successfully Trained & Serialized:")
    print(json.dumps(meta, indent=2))
