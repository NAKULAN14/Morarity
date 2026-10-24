"""
LLM-Assisted Security Reasoning Module for Moriarty.

Provides structured security hypothesis generation, code explanation, adaptive test suggestions,
and patch reasoning for unfamiliar SQL structures and Python database code.

Integrates with configured LLM providers (Gemini, OpenAI) when API keys are available,
and includes a robust, deterministic, local heuristic reasoning engine as a zero-dependency fallback.

Crucial Security Principle:
The LLM is ADVISORY ONLY. It proposes hypotheses and test candidates, but CANNOT independently
determine the final verification verdict. The empirical verification engine remains authoritative.
"""

import ast
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from app.analysis.sqlite_parser import SQLiteParser
from app.models.schemas import LLMReasoningResult


class LLMSecurityReasoner:
    """
    Modular security reasoning engine leveraging LLMs or deterministic heuristic modeling.
    """

    def __init__(self, model_name: Optional[str] = None, timeout_seconds: float = 4.0) -> None:
        self.gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.openai_key = os.environ.get("OPENAI_API_KEY")
        self.timeout_seconds = timeout_seconds

        if self.gemini_key:
            self.provider = "gemini"
            self.model_name = model_name or "gemini-1.5-flash"
        elif self.openai_key:
            self.provider = "openai"
            self.model_name = model_name or "gpt-4o-mini"
        else:
            self.provider = "local_heuristic"
            self.model_name = model_name or "moriarty-reasoner-v1 (local heuristic)"

    def reason_about_source(
        self,
        code: str,
        input_type: str = "auto",
        ast_findings: Optional[list[Any]] = None,
        ml_analysis: Optional[Any] = None,
    ) -> LLMReasoningResult:
        """
        Analyze code structure, generate security hypotheses, and suggest adaptive tests.
        """
        start_time = time.perf_counter()
        if not code or not code.strip():
            return LLMReasoningResult(
                summary="No code submitted for reasoning.",
                hypotheses=[],
                confidence=0.0,
                status="UNAVAILABLE",
            )

        # Attempt live LLM provider if configured
        if self.provider in ("gemini", "openai"):
            try:
                res = self._call_provider(code, mode="source", ast_findings=ast_findings, ml_analysis=ml_analysis)
                res.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return res
            except Exception:
                # Graceful fallback to deterministic heuristic on timeout/failure
                pass

        res = self._heuristic_reasoning(code, mode="source", ast_findings=ast_findings, ml_analysis=ml_analysis)
        res.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return res

    def reason_about_patch(
        self,
        original_code: str,
        patch_code: str,
        ast_findings: Optional[list[Any]] = None,
        ml_analysis: Optional[Any] = None,
    ) -> LLMReasoningResult:
        """
        Analyze candidate patch relative to original code.
        Evaluates whether vulnerabilities were eliminated, whether sanitization is incomplete,
        and whether benign functionality was preserved.
        """
        start_time = time.perf_counter()
        if not patch_code or not patch_code.strip():
            return LLMReasoningResult(
                summary="No candidate patch submitted for reasoning.",
                hypotheses=[],
                confidence=0.0,
                status="UNAVAILABLE",
            )

        if self.provider in ("gemini", "openai"):
            try:
                res = self._call_provider(
                    patch_code,
                    mode="patch",
                    original_code=original_code,
                    ast_findings=ast_findings,
                    ml_analysis=ml_analysis,
                )
                res.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return res
            except Exception:
                pass

        res = self._heuristic_reasoning(
            patch_code,
            mode="patch",
            original_code=original_code,
            ast_findings=ast_findings,
            ml_analysis=ml_analysis,
        )
        res.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return res

    def suggest_adaptive_tests(
        self,
        code: str,
        ast_findings: Optional[list[Any]] = None,
        ml_analysis: Optional[Any] = None,
    ) -> list[dict[str, Any]]:
        """
        Generate contextual test suggestions tailored to the discovered SQL syntax and parameter binding.
        """
        reasoning = self.reason_about_source(code, ast_findings=ast_findings, ml_analysis=ml_analysis)
        return reasoning.additional_test_suggestions

    def _call_provider(
        self,
        code: str,
        mode: str = "source",
        original_code: Optional[str] = None,
        ast_findings: Optional[list[Any]] = None,
        ml_analysis: Optional[Any] = None,
    ) -> LLMReasoningResult:
        """Execute request to external LLM provider."""
        prompt = self._build_prompt(code, mode, original_code, ast_findings, ml_analysis)

        if self.provider == "gemini":
            return self._call_gemini(prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt)

        raise ValueError("No external provider configured.")

    def _build_prompt(
        self,
        code: str,
        mode: str,
        original_code: Optional[str],
        ast_findings: Optional[list[Any]],
        ml_analysis: Optional[Any],
    ) -> str:
        findings_summary = ", ".join([f.rule_id for f in ast_findings]) if ast_findings else "None"
        ml_score = getattr(ml_analysis, "risk_score", 0.0) if ml_analysis else 0.0

        if mode == "patch":
            return f"""You are an elite security verification assistant for Moriarty.
Analyze this candidate security patch for SQL injection.
ORIGINAL CODE:
```
{original_code or "N/A"}
```
CANDIDATE PATCH:
```
{code}
```
ML Risk Score: {ml_score}
Static Findings: {findings_summary}

Respond ONLY with valid JSON adhering to this exact schema:
{{
  "summary": "Technical explanation of whether patch correctly parameterizes the query or has remaining flaws",
  "hypotheses": ["hypothesis 1", "hypothesis 2"],
  "suspicious_code_regions": ["code line or token"],
  "recommended_test_categories": ["Quote and delimiter handling", "Boolean-based SQL injection"],
  "additional_test_suggestions": [
    {{"test_id": "LLM_TEST_001", "name": "Quote check", "category": "Quote and delimiter handling", "payload": "' OR 1=1 --", "expected_behavior": "Input treated strictly as literal data."}}
  ],
  "patch_concerns": ["Any incomplete sanitization or regression concerns"],
  "confidence": 0.85,
  "limitations": ["Verified on SQLite syntax; does not prove application-wide security"]
}}"""
        else:
            return f"""You are an elite security verification assistant for Moriarty.
Analyze this code for SQL injection vulnerabilities.
CODE:
```
{code}
```
ML Risk Score: {ml_score}
Static Findings: {findings_summary}

Respond ONLY with valid JSON adhering to this exact schema:
{{
  "summary": "Technical explanation of SQL construction vulnerabilities",
  "hypotheses": ["hypothesis 1", "hypothesis 2"],
  "suspicious_code_regions": ["code line or token"],
  "recommended_test_categories": ["Quote and delimiter handling", "Boolean-based SQL injection"],
  "additional_test_suggestions": [
    {{"test_id": "LLM_TEST_001", "name": "Quote check", "category": "Quote and delimiter handling", "payload": "' OR 1=1 --", "expected_behavior": "Observe if syntax escape occurs."}}
  ],
  "patch_concerns": [],
  "confidence": 0.85,
  "limitations": ["Requires dynamic execution to prove exploitability"]
}}"""

    def _call_gemini(self, prompt: str) -> LLMReasoningResult:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.gemini_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(text)
            return LLMReasoningResult(
                summary=parsed.get("summary", ""),
                hypotheses=parsed.get("hypotheses", []),
                suspicious_code_regions=parsed.get("suspicious_code_regions", []),
                recommended_test_categories=parsed.get("recommended_test_categories", []),
                additional_test_suggestions=parsed.get("additional_test_suggestions", []),
                patch_concerns=parsed.get("patch_concerns", []),
                confidence=float(parsed.get("confidence", 0.85)),
                limitations=parsed.get("limitations", []),
                model_name=f"gemini/{self.model_name}",
                status="ACTIVE",
            )

    def _call_openai(self, prompt: str) -> LLMReasoningResult:
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity verification assistant. Output only JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.openai_key}"},
        )

        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            text = resp_data["choices"][0]["message"]["content"]
            parsed = json.loads(text)
            return LLMReasoningResult(
                summary=parsed.get("summary", ""),
                hypotheses=parsed.get("hypotheses", []),
                suspicious_code_regions=parsed.get("suspicious_code_regions", []),
                recommended_test_categories=parsed.get("recommended_test_categories", []),
                additional_test_suggestions=parsed.get("additional_test_suggestions", []),
                patch_concerns=parsed.get("patch_concerns", []),
                confidence=float(parsed.get("confidence", 0.85)),
                limitations=parsed.get("limitations", []),
                model_name=f"openai/{self.model_name}",
                status="ACTIVE",
            )

    def _heuristic_reasoning(
        self,
        code: str,
        mode: str = "source",
        original_code: Optional[str] = None,
        ast_findings: Optional[list[Any]] = None,
        ml_analysis: Optional[Any] = None,
    ) -> LLMReasoningResult:
        """
        High-precision deterministic heuristic reasoning engine.
        Grounded in Python AST semantics and SQLite grammar patterns.
        """
        hypotheses: list[str] = []
        suspicious_regions: list[str] = []
        recommended_cats: list[str] = []
        test_suggestions: list[dict[str, Any]] = []
        patch_concerns: list[str] = []
        limitations: list[str] = [
            "Reasoning operates on syntactic and local semantic structures.",
            "Dynamic verification is required to establish runtime exploitability or proof of neutralization.",
            "Database driver specific restrictions (e.g. SQLite multi-statement restrictions) apply.",
        ]

        # Extract structural signals
        has_concat = bool(re.search(r'(\+\s*[\'"][^\'"]*|[\'"][^\'"]*\s*\+)', code)) or any(
            f.rule_id == "SQLI_UNSAFE_QUERY" for f in (ast_findings or [])
        )
        has_fstring = "f\"" in code or "f'" in code
        has_format = ".format(" in code or " % " in code
        has_literal_where = bool(re.search(r'\bWHERE\s+.*(=|!=|<>|LIKE)\s*[\'"][^\'"]*[\'"]', code, re.IGNORECASE))
        has_param = "?" in code or any(f.rule_id == "SQLI_PARAMETERIZED_QUERY" for f in (ast_findings or []))
        has_comment_strip = ".replace('--'" in code or ".replace(\"--\"" in code
        has_single_quote_strip = ".replace(\"'\"" in code

        tables = SQLiteParser.extract_tables(code)
        columns = SQLiteParser.extract_columns(code)
        table_label = tables[0] if tables else "target table"

        if mode == "source":
            if has_concat or has_fstring or has_format or (has_literal_where and not has_param):
                hypotheses.append(
                    f"Delimiter Boundary Escape: Dynamic query interpolation on '{table_label}' allows string delimiter breakout via single quotes."
                )
                hypotheses.append(
                    "Tautology Predicate Injection: Boolean expressions (' OR '1'='1) can alter WHERE logic to return unauthorized records."
                )
                recommended_cats.extend(["Quote and delimiter handling", "Boolean-based SQL injection", "Comment-based SQL injection"])
                suspicious_regions.append(f"Dynamic SQL construction referencing {table_label}")

                test_suggestions.append({
                    "test_id": "LLM_HYP_001",
                    "name": "Delimiter Escape Boundary Challenge",
                    "category": "Quote and delimiter handling",
                    "payload": "' OR '1'='1",
                    "expected_behavior": "Neutralized patch binds input strictly as data; returns 0 unauthorized rows.",
                    "security_invariant": "UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
                })
                test_suggestions.append({
                    "test_id": "LLM_HYP_002",
                    "name": "Comment Truncation Challenge",
                    "category": "Comment-based SQL injection",
                    "payload": "' OR 1=1 --",
                    "expected_behavior": "Comment markers must not alter statement syntax or truncate trailing predicates.",
                    "security_invariant": "SQL_COMMENT_MARKERS_CANNOT_TRUNCATE_QUERY",
                })
                summary = (
                    f"Identified elevated SQL injection risk in {table_label} query. Dynamic construction via "
                    f"{'f-string' if has_fstring else 'string concatenation'} directly binds external input without parameterization. "
                    "Adaptive verification should challenge string delimiters and boolean predicates."
                )
                confidence = 0.92
            elif has_param:
                hypotheses.append("Driver-Level Parameter Binding: Uses native DB parameter markers (?), isolating user data from SQL compilation.")
                recommended_cats.append("Benign functionality preservation")
                summary = f"Code for '{table_label}' uses parameterized queries. Syntax is structurally resilient against injection."
                confidence = 0.95
            else:
                hypotheses.append("Unverified Query Structure: Structure requires empirical verification to establish data flow.")
                summary = "Code inspected. Requires dynamic differential challenge to establish baseline vulnerability."
                confidence = 0.70

        else:  # mode == "patch"
            if has_comment_strip and not has_param:
                patch_concerns.append("Incomplete Sanitization: Code attempts blacklist filtering (stripping '--') but leaves single-quote delimiters unescaped.")
                hypotheses.append("Bypass via Quote Delimiters: Attackers can craft boolean injection without comments using balanced quotes (' OR '1'='1).")
                recommended_cats.extend(["Quote and delimiter handling", "Boolean-based SQL injection"])
                summary = "Flawed patch: Stripping comment markers does not neutralize boolean-or delimiter escapes."
                confidence = 0.90
            elif "WHERE id = 1" in code or "WHERE 1=1" in code or ("WHERE" in code and "username" not in code and "?" not in code):
                patch_concerns.append("Functionality Regression: Query replaces dynamic lookup with hardcoded static predicate, breaking legitimate searches.")
                recommended_cats.append("Benign functionality preservation")
                summary = "Suspicious patch: Neutralizes injection through hardcoded lookup, causing functional regression for benign inputs."
                confidence = 0.88
            elif has_param:
                hypotheses.append("Robust Parameterization: Candidate patch properly binds inputs using driver placeholders (?).")
                summary = f"Candidate patch successfully parameterizes query on '{table_label}'. Preserves benign user lookup invariant."
                confidence = 0.94
            else:
                patch_concerns.append("Ambiguous Patch Pattern: Unrecognized patch modification pattern.")
                summary = "Patch re-analyzed. Verifier must execute dynamic differential tests before determining safety."
                confidence = 0.75

        return LLMReasoningResult(
            summary=summary,
            hypotheses=hypotheses,
            suspicious_code_regions=suspicious_regions,
            recommended_test_categories=recommended_cats,
            additional_test_suggestions=test_suggestions,
            patch_concerns=patch_concerns,
            confidence=confidence,
            limitations=limitations,
            model_name=self.model_name,
            status="ACTIVE",
        )
