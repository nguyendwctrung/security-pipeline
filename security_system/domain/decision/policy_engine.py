"""
Policy-based decision engine for scan issues.

Contains pure business rules that convert normalized SecurityIssue entries
into a DecisionReport.
"""

from __future__ import annotations

from datetime import datetime

from security_system.domain.models import DecisionReport, SecurityIssue


class PolicyEngine:
    """Evaluates security issues using simple severity-based policy rules."""

    _FAIL_THRESHOLD: float = 7.0
    _WARN_THRESHOLD: float = 4.0

    def evaluate(self, issues: list[SecurityIssue]) -> DecisionReport:
        """
        Apply policy rules to a list of security issues.

        Rules (priority order):
        - Any CRITICAL issue -> FAIL
        - Else any HIGH issue -> WARN
        - Else -> PASS
        """
        total_issue_count = len(issues)
        has_critical = any(self._severity_of(issue) == "CRITICAL" for issue in issues)
        has_high = any(self._severity_of(issue) == "HIGH" for issue in issues)

        if has_critical:
            decision = "FAIL"
            summary = (
                "Critical severity issue detected; policy evaluation result is FAIL"
            )
        elif has_high:
            decision = "WARN"
            summary = "High severity issue detected; policy evaluation result is WARN"
        else:
            decision = "PASS"
            summary = "No HIGH or CRITICAL issues detected; policy evaluation result is PASS"

        risk_score = max((issue.score for issue in issues), default=0.0)

        return DecisionReport(
            timestamp=datetime.now().isoformat(),
            decision=decision,
            reason=summary,
            risk_score=risk_score,
            is_malicious=False,
            fail_threshold=self._FAIL_THRESHOLD,
            warn_threshold=self._WARN_THRESHOLD,
            detected_patterns=[],
            recommendations=[],
            metadata={
                "status": decision,
                "summary": summary,
                "total_issue_count": total_issue_count,
            },
        )

    @staticmethod
    def _severity_of(issue: SecurityIssue) -> str:
        """Returns a normalized severity string for a SecurityIssue."""
        severity = issue.severity
        if hasattr(severity, "value"):
            return str(severity.value).upper()
        return str(severity).upper()
