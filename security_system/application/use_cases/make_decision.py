"""
make_decision use case — orchestrates risk evaluation and report creation.

Dependency flow:
  AnalysisResult + summaries → domain/decision/DecisionEngine → DecisionReport

No business logic here. Only assembles inputs and calls the domain engine.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from security_system.domain.decision import DecisionEngine
from security_system.domain.decision.policy_engine import PolicyEngine
from security_system.domain.models import AnalysisResult, DecisionReport, SecurityIssue
from security_system.domain.parsers import ToolSummary

logger = logging.getLogger(__name__)


def make_decision(
	analysis: AnalysisResult | list[SecurityIssue],
	summaries: Dict[str, ToolSummary] | None = None,
	reports_dir: Path | None = None,
) -> DecisionReport:
	"""
	Produce a final DecisionReport using either:
	- PolicyEngine for a list of SecurityIssue objects, or
	- DecisionEngine for the legacy AnalysisResult + summaries flow.

	Args:
		analysis:    Either AnalysisResult or list[SecurityIssue].
		summaries:   Per-tool ToolSummary objects from the run_scan use case
		             (legacy AnalysisResult path only).
		reports_dir: Directory where the decision report will be persisted
		             (legacy AnalysisResult path only).

	Returns:
		DecisionReport with PASS / WARN / FAIL decision.
	"""
	if isinstance(analysis, list) and (
		not analysis or all(isinstance(issue, SecurityIssue) for issue in analysis)
	):
		report = PolicyEngine().evaluate(analysis)
		logger.info("Decision: %s (policy path)", report.decision)
		return report

	if summaries is None or reports_dir is None:
		raise ValueError(
			"summaries and reports_dir are required when analysis is AnalysisResult"
		)

	if not isinstance(analysis, AnalysisResult):
		raise ValueError(
			"analysis must be AnalysisResult for the legacy DecisionEngine path"
		)

	summary_dict = _build_summary_dict(summaries)

	engine = DecisionEngine(reports_dir=reports_dir)
	report = engine.decide(analysis, summary_dict)

	logger.info("Decision: %s (risk=%.1f)", report.decision, report.risk_score)
	return report


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _build_summary_dict(summaries: Dict[str, ToolSummary]) -> Dict[str, Any]:
	"""
	Aggregates ToolSummary objects into the summary dict expected by
	DecisionEngine.decide() as optional metadata.
	"""
	by_severity: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
	for ts in summaries.values():
		for level, count in ts.by_severity.items():
			by_severity[level] = by_severity.get(level, 0) + count

	total = sum(ts.total_findings for ts in summaries.values())
	avg_score = (
		sum(ts.average_score for ts in summaries.values()) / len(summaries)
		if summaries
		else 0.0
	)

	return {
		"timestamp": datetime.now().isoformat(),
		"total_findings": total,
		"by_tool": {name: ts.total_findings for name, ts in summaries.items()},
		"by_severity": by_severity,
		"overall_score": round(avg_score, 1),
		"tools": [ts.to_dict() for ts in summaries.values()],
	}