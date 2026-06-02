from __future__ import annotations

from typing import Sequence

from ...domain import AgentResult, Finding, GitContext, ScanSummary, Severity
from .base_rule import BaseRule, RuleResult


class MaliciousIntentRule(BaseRule):
	"""Policy rule driven by malicious_intent_agent confidence and evidence quality."""

	HIGH_CONFIDENCE_THRESHOLD = 0.75
	MEDIUM_CONFIDENCE_THRESHOLD = 0.5

	def evaluate(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		agent_outputs: Sequence[AgentResult],
		git_context: GitContext,
	) -> RuleResult:
		_ = (summary, findings, git_context)

		result = self._find_malicious_intent_output(agent_outputs)
		if result is None:
			return self.pass_result(
				reason="No malicious_intent_agent output found.",
				severity=Severity.INFO,
				metadata={
					"rule": "malicious_intent_rule",
					"agent_present": False,
				},
			)

		confidence = float(result.confidence)
		has_specific_evidence = self._has_specific_evidence(result.evidence)

		# Must not fail when evidence is missing or generic.
		if confidence >= self.HIGH_CONFIDENCE_THRESHOLD and has_specific_evidence:
			return self.fail_result(
				reason=(
					"Malicious intent confidence is high and supported by specific evidence from the agent report."
				),
				severity=Severity.CRITICAL,
				metadata={
					"rule": "malicious_intent_rule",
					"agent_name": result.agent_name,
					"confidence": confidence,
					"risk_score": result.risk_score,
					"evidence_count": len(result.evidence),
					"specific_evidence_count": self._specific_evidence_count(result.evidence),
					"recommendations": result.recommendations,
				},
			)

		if confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD:
			return self.warn_result(
				reason=(
					"Malicious intent confidence is medium or higher, but evidence is not strong enough for a blocking decision."
				),
				severity=Severity.HIGH if has_specific_evidence else Severity.MEDIUM,
				metadata={
					"rule": "malicious_intent_rule",
					"agent_name": result.agent_name,
					"confidence": confidence,
					"risk_score": result.risk_score,
					"evidence_count": len(result.evidence),
					"specific_evidence_count": self._specific_evidence_count(result.evidence),
					"recommendations": result.recommendations,
				},
			)

		return self.pass_result(
			reason="Malicious intent confidence is low.",
			severity=Severity.INFO,
			metadata={
				"rule": "malicious_intent_rule",
				"agent_name": result.agent_name,
				"confidence": confidence,
				"risk_score": result.risk_score,
			},
		)

	def _find_malicious_intent_output(self, agent_outputs: Sequence[AgentResult]) -> AgentResult | None:
		for output in agent_outputs:
			if output.agent_name == "malicious_intent_agent":
				return output
		return None

	def _has_specific_evidence(self, evidence_items: Sequence[str]) -> bool:
		return self._specific_evidence_count(evidence_items) > 0

	def _specific_evidence_count(self, evidence_items: Sequence[str]) -> int:
		keywords = (
			"finding ",
			"cve-",
			"rule",
			"file",
			"path",
			"diff evidence",
			"in_changed_files",
			"in_git_diff",
			"signal",
		)

		count = 0
		for item in evidence_items:
			text = str(item).strip().lower()
			if not text:
				continue
			if any(token in text for token in keywords) and len(text) >= 20:
				count += 1
		return count
