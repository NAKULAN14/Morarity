from app.models.schemas import AnalysisResult


class SecurityInvariantGenerator:
    """
    Generate security and functionality invariants for SQL injection
    patch verification.
    """

    DEFAULT_INVARIANTS = [
        "SQL query structure must not be controlled by untrusted input.",
        "User-controlled values must be passed separately through query parameters.",
        "Required application functionality must remain intact.",
    ]

    def generate(self, analysis: AnalysisResult) -> list[str]:
        invariants = list(self.DEFAULT_INVARIANTS)

        for finding in analysis.findings:
            if finding.rule_id == "SQLI_UNSAFE_QUERY":
                invariants.append(
                    "Dynamically constructed SQL must be replaced with "
                    "a safe query structure."
                )

            elif finding.rule_id == "SQLI_UNKNOWN_QUERY":
                invariants.append(
                    "Unclassified SQL execution paths must be investigated "
                    "before declaring the patch verified."
                )

            elif finding.rule_id == "SQLI_PARAMETERIZED_QUERY":
                invariants.append(
                    "Parameterized query execution must be preserved "
                    "after patching."
                )

        # Remove duplicates while preserving order.
        return list(dict.fromkeys(invariants))


def generate_invariants(analysis: AnalysisResult) -> list[str]:
    """
    Convenience function for API routes and other modules.
    """

    generator = SecurityInvariantGenerator()
    return generator.generate(analysis)