from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
from typing import Any, Dict, List, Sequence

from ..domain import AgentResult, Decision, DecisionStatus, Finding, GitContext, ScanSummary, Severity
from ..repositories.policy_repository import PolicyRepository
from .rules.base_rule import BaseRule, RuleResult
from .rules.malicious_intent_rule import MaliciousIntentRule
from .rules.secret_rule import SecretRule
from .rules.semgrep_rule import SemgrepRule
from .rules.trivy_rule import TrivyRule


@dataclass(slots=True)
class PolicyEvaluationContext:
	"""Typed input for policy evaluation."""

	summary: ScanSummary
	agent_outputs: List[AgentResult]
	git_context: GitContext | None
	security_policy: Dict[str, Any]
	allowlist: Dict[str, Any]
	baseline: Dict[str, Any]


class PolicyEngine:
	"""Rule-driven policy engine that converts rule results into PASS/WARN/FAIL."""

	def __init__(
		self,
		policy_repository: PolicyRepository | None = None,
		rules: Sequence[BaseRule] | None = None,
	) -> None:
		self.policy_repository = policy_repository or PolicyRepository()
		self.rules: List[BaseRule] = list(rules) if rules is not None else self._default_rules()

	def evaluate(self, context: PolicyEvaluationContext) -> Decision:
		loaded = self._load_policy_bundle()
		security_policy = self._merge_policy_dicts(loaded.get("security_policy", {}), context.security_policy)
		allowlist = self._merge_policy_dicts(loaded.get("allowlist", {}), context.allowlist)
		baseline = self._merge_policy_dicts(loaded.get("baseline", {}), context.baseline)

		summary = self._prepare_summary_for_rules(context.summary, security_policy)
		findings = self._annotate_findings_for_policy(summary.findings, allowlist, baseline)
		git_context = context.git_context or self._empty_git_context(summary)

		rule_results = self._run_rules(
			summary=summary,
			findings=findings,
			git_context=git_context,
			agent_outputs=context.agent_outputs,
		)

		blocking_reasons = [result.reason for result in rule_results if result.blocking or result.status == DecisionStatus.FAIL]
		warnings = [result.reason for result in rule_results if result.status == DecisionStatus.WARN]
		recommendations = self._merge_recommendations(context.agent_outputs, rule_results)

		final_score = self._final_score(findings, context.agent_outputs)

		# Decision policy requested by user:
		# blocking rules => FAIL, warning rules => WARN, no issue => PASS.
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

	def _load_policy_bundle(self) -> Dict[str, Dict[str, Any]]:
		try:
			return self.policy_repository.read_all()
		except Exception:
			return {
				"security_policy": {},
				"allowlist": {},
				"baseline": {},
			}

	def _default_rules(self) -> List[BaseRule]:
		return [
			SecretRule(),
			SemgrepRule(),
			TrivyRule(),
			MaliciousIntentRule(),
		]

	def _run_rules(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		git_context: GitContext,
		agent_outputs: Sequence[AgentResult],
	) -> List[RuleResult]:
		results: List[RuleResult] = []
		for rule in self.rules:
			try:
				result = rule.evaluate(summary, findings, agent_outputs, git_context)
			except Exception as exc:
				result = rule.warn_result(
					reason=f"Rule execution error in {rule.__class__.__name__}: {exc}",
					severity=Severity.MEDIUM,
					metadata={"rule": rule.__class__.__name__},
				)
			results.append(result)
		return results

	def _prepare_summary_for_rules(self, summary: ScanSummary, security_policy: Dict[str, Any]) -> ScanSummary:
		prepared = deepcopy(summary)
		prepared.metadata["security_policy"] = security_policy

		rules_cfg = security_policy.get("rules") if isinstance(security_policy.get("rules"), dict) else {}
		if isinstance(rules_cfg, dict):
			if "allow_dev_test_dependencies" in rules_cfg:
				prepared.metadata["policy_allow_dev_test_dependencies"] = bool(rules_cfg["allow_dev_test_dependencies"])
			if "allow_dev_dependencies" in rules_cfg:
				prepared.metadata["policy_allow_dev_dependencies"] = bool(rules_cfg["allow_dev_dependencies"])
			if "allow_test_dependencies" in rules_cfg:
				prepared.metadata["policy_allow_test_dependencies"] = bool(rules_cfg["allow_test_dependencies"])

		return prepared

	def _annotate_findings_for_policy(
		self,
		findings: Sequence[Finding],
		allowlist: Dict[str, Any],
		baseline: Dict[str, Any],
	) -> List[Finding]:
		allowlist_ids = {str(item) for item in self._list_value(allowlist, "finding_ids")}
		allowlist_rules = {str(item).lower() for item in self._list_value(allowlist, "rule_ids")}
		allowlist_cves = {str(item).upper() for item in self._list_value(allowlist, "cves")}

		baseline_ids = {str(item) for item in self._list_value(baseline, "finding_ids")}
		baseline_rules = {str(item).lower() for item in self._list_value(baseline, "rule_ids")}
		baseline_cves = {str(item).upper() for item in self._list_value(baseline, "cves")}

		annotated = deepcopy(list(findings))
		for finding in annotated:
			in_allowlist = (
				finding.id in allowlist_ids
				or (finding.rule_id is not None and finding.rule_id.lower() in allowlist_rules)
				or (finding.cve is not None and finding.cve.upper() in allowlist_cves)
			)
			in_baseline = (
				finding.id in baseline_ids
				or (finding.rule_id is not None and finding.rule_id.lower() in baseline_rules)
				or (finding.cve is not None and finding.cve.upper() in baseline_cves)
			)

			if in_allowlist:
				finding.metadata["allowlisted"] = True
				finding.metadata["allowlist_hit"] = True
			if in_baseline:
				finding.metadata["in_baseline"] = True
				finding.metadata["baseline_hit"] = True

		return annotated

	def _empty_git_context(self, summary: ScanSummary):
		from ..domain import GitContext
		from datetime import datetime

		context_payload = summary.metadata.get("git_context")
		if isinstance(context_payload, dict):
			try:
				return GitContext.from_dict(context_payload)
			except Exception:
				pass

		return GitContext(
			commit_hash="",
			branch="",
			author="",
			timestamp=datetime.utcnow(),
			commit_message="",
			changed_files=[],
			diff="",
		)

	def _merge_policy_dicts(self, loaded: Dict[str, Any], provided: Dict[str, Any]) -> Dict[str, Any]:
		result: Dict[str, Any] = dict(loaded or {})
		for key, value in (provided or {}).items():
			result[key] = value
		return result

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

	def _merge_recommendations(self, agent_outputs: Sequence[AgentResult], rule_results: Sequence[RuleResult]) -> List[str]:
		ordered: List[str] = []
		seen = set()
		for output in agent_outputs:
			for recommendation in output.recommendations:
				if recommendation in seen:
					continue
				seen.add(recommendation)
				ordered.append(recommendation)
		for result in rule_results:
			raw_recommendations = result.metadata.get("recommendations")
			if not isinstance(raw_recommendations, list):
				continue
			for recommendation in raw_recommendations:
				rec = str(recommendation)
				if rec in seen:
					continue
				seen.add(rec)
				ordered.append(rec)
		return ordered

	def _list_value(self, data: Dict[str, Any], key: str) -> List[Any]:
		value = data.get(key)
		if isinstance(value, list):
			return value
		return []
