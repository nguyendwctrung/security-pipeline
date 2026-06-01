from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from ..domain import AgentResult, Decision, DecisionStatus, Finding, ScanSummary, Severity


@dataclass(slots=True)
class PolicyEvaluationContext:
	"""Typed input for policy evaluation."""

	summary: ScanSummary
	agent_outputs: List[AgentResult]
	security_policy: Dict[str, Any]
	allowlist: Dict[str, Any]
	baseline: Dict[str, Any]


class PolicyEngine:
	"""Simple policy engine that converts findings + agent risk into PASS/WARN/FAIL."""

	DEFAULT_RULES: Dict[str, Any] = {
		"fail_on_critical": True,
		"fail_on_high_count": 2,
		"warn_on_high_count": 1,
		"warn_on_medium_count": 3,
		"fail_on_real_secret": True,
	}

	def evaluate(self, context: PolicyEvaluationContext) -> Decision:
		rules = self._effective_rules(context.security_policy)
		findings = self._apply_allowlist(context.summary.findings, context.allowlist)
		severity_counts = self._severity_counts(findings)

		blocking_reasons: List[str] = []
		warnings: List[str] = []
		recommendations: List[str] = self._merge_recommendations(context.agent_outputs)

		if rules["fail_on_critical"] and severity_counts[Severity.CRITICAL.value] > 0:
			blocking_reasons.append(
				f"Critical findings detected: {severity_counts[Severity.CRITICAL.value]}."
			)

		if severity_counts[Severity.HIGH.value] >= int(rules["fail_on_high_count"]):
			blocking_reasons.append(
				f"High findings exceed fail threshold: {severity_counts[Severity.HIGH.value]} >= {int(rules['fail_on_high_count'])}."
			)

		if rules["fail_on_real_secret"] and self._has_real_secret(findings):
			blocking_reasons.append("At least one likely real secret exposure is present.")

		if severity_counts[Severity.HIGH.value] >= int(rules["warn_on_high_count"]):
			warnings.append(
				f"High findings exceed warning threshold: {severity_counts[Severity.HIGH.value]} >= {int(rules['warn_on_high_count'])}."
			)

		if severity_counts[Severity.MEDIUM.value] >= int(rules["warn_on_medium_count"]):
			warnings.append(
				f"Medium findings exceed warning threshold: {severity_counts[Severity.MEDIUM.value]} >= {int(rules['warn_on_medium_count'])}."
			)

		final_score = self._final_score(findings, context.agent_outputs)

		if blocking_reasons:
			status = DecisionStatus.FAIL
		elif warnings:
			status = DecisionStatus.WARN
		else:
			status = DecisionStatus.PASS

		if not recommendations:
			recommendations = [
				"Prioritize remediation by severity and verify fixes with a follow-up scan.",
			]

		return Decision(
			status=status,
			blocking_reasons=blocking_reasons,
			warnings=warnings,
			recommendations=recommendations,
			final_score=round(final_score, 2),
		)

	def _effective_rules(self, security_policy: Dict[str, Any]) -> Dict[str, Any]:
		rules_raw = security_policy.get("rules")
		policy_rules: Dict[str, Any] = rules_raw if isinstance(rules_raw, dict) else {}
		effective = dict(self.DEFAULT_RULES)
		for key in self.DEFAULT_RULES:
			if key in policy_rules:
				effective[key] = policy_rules[key]
		return effective

	def _apply_allowlist(self, findings: Sequence[Finding], allowlist: Dict[str, Any]) -> List[Finding]:
		ids = {str(item) for item in self._list_value(allowlist, "finding_ids")}
		rules = {str(item).lower() for item in self._list_value(allowlist, "rule_ids")}
		cves = {str(item).upper() for item in self._list_value(allowlist, "cves")}

		filtered: List[Finding] = []
		for finding in findings:
			if finding.id in ids:
				continue
			if finding.rule_id and finding.rule_id.lower() in rules:
				continue
			if finding.cve and finding.cve.upper() in cves:
				continue
			filtered.append(finding)
		return filtered

	def _severity_counts(self, findings: Sequence[Finding]) -> Dict[str, int]:
		counts = {severity.value: 0 for severity in Severity}
		for finding in findings:
			counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
		return counts

	def _has_real_secret(self, findings: Sequence[Finding]) -> bool:
		for finding in findings:
			category = str(finding.metadata.get("category") or "").lower()
			classification = str(finding.metadata.get("secret_classification") or "").lower()
			if category == "secret" and classification in {"", "real"}:
				return True
		return False

	def _final_score(self, findings: Sequence[Finding], agent_outputs: Sequence[AgentResult]) -> float:
		if not findings and not agent_outputs:
			return 0.0

		severity_weight = {
			Severity.CRITICAL: 100.0,
			Severity.HIGH: 75.0,
			Severity.MEDIUM: 45.0,
			Severity.LOW: 20.0,
			Severity.INFO: 10.0,
			Severity.UNKNOWN: 15.0,
		}

		if findings:
			severity_component = sum(severity_weight.get(item.severity, 15.0) for item in findings) / len(findings)
		else:
			severity_component = 0.0

		if agent_outputs:
			agent_component = sum(item.risk_score for item in agent_outputs) / len(agent_outputs)
		else:
			agent_component = 0.0

		combined = (severity_component * 0.6) + (agent_component * 0.4)
		return max(0.0, min(100.0, combined))

	def _merge_recommendations(self, agent_outputs: Sequence[AgentResult]) -> List[str]:
		ordered: List[str] = []
		seen = set()
		for output in agent_outputs:
			for recommendation in output.recommendations:
				if recommendation in seen:
					continue
				seen.add(recommendation)
				ordered.append(recommendation)
		return ordered

	def _list_value(self, data: Dict[str, Any], key: str) -> List[Any]:
		value = data.get(key)
		if isinstance(value, list):
			return value
		return []
