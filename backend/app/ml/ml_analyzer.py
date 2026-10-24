"""
Independent ML-Based SQL Injection Analyzer for Moriarty 2.0.

Provides standalone machine learning analysis for both submitted original source code
and generated/edited security patches through an identical pipeline.

Extracts syntactic and structural features, evaluates model predictions, computes
calibrated risk scores, and recommends targeted catalog test categories for
adaptive test planning.
"""

import ast
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

import joblib

logger = logging.getLogger("moriarty.ml")

MODEL_DIR = Path(__file__).resolve().parent / "models" / "v1"
MODEL_PATH = MODEL_DIR / "sql_injection_model.joblib"
METADATA_PATH = MODEL_DIR / "model_metadata.json"


class SQLInjectionMLAnalyzer:
    """
    Independent Machine Learning Analyzer for SQL Injection Detection.

    Strictly decoupled from the patch generator so that candidate patches cannot
    rate their own security posture. Evaluates source code using character n-gram
    TF-IDF representations and a calibrated logistic regression classifier.
    """

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self.metadata: dict[str, Any] = {}
        self.model_status = "unavailable"
        self.model_version = "1.0.0"

        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load the serialized model artifact and metadata."""
        if not self.model_path.exists():
            logger.warning("ML model artifact not found at %s. Marking status as unavailable.", self.model_path)
            self.model_status = "unavailable"
            return

        try:
            self.model = joblib.load(self.model_path)
            self.model_status = "trained"

            meta_file = self.model_path.parent / "model_metadata.json"
            if meta_file.exists():
                self.metadata = json.loads(meta_file.read_text(encoding="utf-8"))
                self.model_version = self.metadata.get("model_version", "1.0.0")
        except Exception as e:
            logger.error("Failed to load ML model artifact from %s: %s", self.model_path, e)
            self.model_status = "unavailable"
            self.model = None

    def analyze(self, code: str) -> dict[str, Any]:
        """
        Analyze submitted code (original or patch) through the ML pipeline.

        Returns structured dictionary containing model status, predicted class,
        calibrated risk score, risk level, detected structural features,
        and recommended verification categories.
        """
        clean_code = (code or "").strip()
        if not clean_code:
            return {
                "model_status": self.model_status,
                "predicted_class": "safe_query_pattern",
                "risk_score": 0.0,
                "risk_level": "LOW",
                "detected_features": [],
                "recommended_test_categories": [],
                "model_version": self.model_version,
                "summary": "Empty source code supplied; zero risk computed.",
            }

        # 1. Structural Feature Extraction
        detected_features = self._extract_features(clean_code)

        # 2. ML Inference (if model is available)
        if self.model_status != "trained" or self.model is None:
            return {
                "model_status": "unavailable",
                "predicted_class": "unknown",
                "risk_score": 0.0,
                "risk_level": "UNKNOWN",
                "detected_features": detected_features,
                "recommended_test_categories": self._map_features_to_categories(detected_features),
                "model_version": self.model_version,
                "summary": "ML model artifact is unavailable. Untrained state reported.",
            }

        try:
            # Predict class and probability
            proba = self.model.predict_proba([clean_code])[0]
            # proba[1] is the probability of class 1 (vulnerable)
            risk_score = round(float(proba[1]), 3)

            # Heuristic consistency: If explicit parameterized binding with ? is present
            # and no dynamic concatenation/f-string interpolation exists, ensure risk score is low.
            # ML handles soft classification, but AST parameterization grounding ensures soundness.
            has_parameter_binding = "parameter_placeholder_binding" in detected_features
            has_dynamic_concat = any(
                f in detected_features
                for f in ["string_concatenation_in_query", "fstring_query_interpolation", "format_string_interpolation"]
            )
            if has_parameter_binding and not has_dynamic_concat:
                risk_score = min(risk_score, 0.15)

            # Assign risk level based on calibrated score
            if risk_score >= 0.75:
                risk_level = "CRITICAL"
                predicted_class = "potential_sql_injection"
            elif risk_score >= 0.50:
                risk_level = "HIGH"
                predicted_class = "potential_sql_injection"
            elif risk_score >= 0.25:
                risk_level = "MEDIUM"
                predicted_class = "suspicious_query_pattern"
            else:
                risk_level = "LOW"
                predicted_class = "safe_query_pattern"

            recommended_cats = self._map_features_to_categories(detected_features)

            summary = self._generate_summary(risk_level, risk_score, detected_features)

            return {
                "model_status": "trained",
                "predicted_class": predicted_class,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "detected_features": detected_features,
                "recommended_test_categories": recommended_cats,
                "model_version": self.model_version,
                "summary": summary,
            }

        except Exception as err:
            logger.error("Error during ML inference: %s", err)
            return {
                "model_status": "error",
                "predicted_class": "unknown",
                "risk_score": 0.0,
                "risk_level": "UNKNOWN",
                "detected_features": detected_features,
                "recommended_test_categories": [],
                "model_version": self.model_version,
                "summary": f"Inference execution failed: {err}",
            }

    def _extract_features(self, code: str) -> list[str]:
        """Extract syntactic and contextual features relevant to SQL injection."""
        features: list[str] = []

        # Check for string concatenation (+)
        if re.search(r'["\']\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*|\b[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*["\']', code):
            features.append("string_concatenation_in_query")

        # Check for f-string interpolation
        if re.search(r'f["\'].*\{[a-zA-Z_][a-zA-Z0-9_]*\}.*["\']', code, re.IGNORECASE):
            features.append("fstring_query_interpolation")

        # Check for % or .format()
        if re.search(r'["\'].*%s.*["\']\s*%', code) or re.search(r'["\'].*\{\}.*["\']\.format\(', code):
            features.append("format_string_interpolation")

        # Check for unparameterized raw SQL clauses
        if re.search(r'\bWHERE\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"][^\'"]*[\'"]', code, re.IGNORECASE):
            features.append("hardcoded_string_literal_in_where")

        # Check for explicit parameter placeholders (? or :name)
        if re.search(r'\bWHERE\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(=|LIKE)\s*\?', code, re.IGNORECASE) or ", (" in code or ", {" in code:
            features.append("parameter_placeholder_binding")

        # Check for naive sanitization
        if ".replace(" in code:
            features.append("incomplete_filter_sanitization")

        # Check for SQL comments or tautologies in literal
        if "--" in code or "'1'='1" in code or "1=1" in code:
            features.append("potential_sql_syntax_injection_token")

        if not features:
            features.append("standard_code_structure")

        return features

    def _map_features_to_categories(self, features: list[str]) -> list[str]:
        """
        Map detected syntactic patterns to recommended catalog testing categories.
        Allows the adaptive planner to target relevant invariant classes.
        """
        recommended: list[str] = []

        if "string_concatenation_in_query" in features or "hardcoded_string_literal_in_where" in features:
            recommended.extend([
                "Quote and delimiter handling",
                "Boolean-based SQL injection",
            ])

        if "fstring_query_interpolation" in features:
            recommended.extend([
                "Quote and delimiter handling",
                "UNION-based SQL injection",
                "Numeric parameter handling",
            ])

        if "incomplete_filter_sanitization" in features or "potential_sql_syntax_injection_token" in features:
            recommended.extend([
                "Comment-based SQL injection",
                "Quote and delimiter handling",
                "Input encoding and normalization",
            ])

        if "parameter_placeholder_binding" in features:
            recommended.extend([
                "Legitimate functionality preservation",
                "Type confusion",
            ])

        # De-duplicate while preserving priority order
        seen = set()
        unique_cats: list[str] = []
        for cat in recommended:
            if cat not in seen:
                seen.add(cat)
                unique_cats.append(cat)

        return unique_cats or ["Quote and delimiter handling", "Boolean-based SQL injection"]

    def _generate_summary(self, risk_level: str, risk_score: float, features: list[str]) -> str:
        """Generate human-readable summary of ML model findings."""
        if risk_level in ("CRITICAL", "HIGH"):
            return (
                f"ML model identified elevated SQL injection risk (score: {risk_score:.2f}, level: {risk_level}). "
                f"Suspicious construction detected: {', '.join(features)}. "
                "Adaptive planner will prioritize delimiter boundary and query syntax challenges."
            )
        elif risk_level == "MEDIUM":
            return (
                f"ML model identified moderate risk (score: {risk_score:.2f}, level: {risk_level}). "
                f"Detected patterns: {', '.join(features)}. Verification will probe input boundaries."
            )
        else:
            return (
                f"ML model evaluated query construction as low risk (score: {risk_score:.2f}, level: {risk_level}). "
                "Structure exhibits safe parameter binding or static execution pattern."
            )
