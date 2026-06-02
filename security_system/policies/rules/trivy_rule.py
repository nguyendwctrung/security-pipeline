from __future__ import annotations

from pathlib import PurePath
from typing import Sequence

from ...domain import AgentResult, Finding, GitContext, ScanSummary, ScannerType, Severity
from .base_rule import BaseRule, RuleResult


class TrivyRule(BaseRule):
	"""Policy rule for Trivy dependency vulnerabilities."""

	def evaluate(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		agent_outputs: Sequence[AgentResult],
		git_context: GitContext,
	) -> RuleResult:
		_ = (agent_outputs, git_context)

		dependency_findings = [finding for finding in findings if self._is_trivy_dependency_finding(finding)]
		if not dependency_findings:
			return self.pass_result(
				reason="No Trivy dependency findings detected.",
				severity=Severity.INFO,
				metadata={
					"rule": "trivy_rule",
					"dependency_count": 0,
				},
			)

		evaluated = [
			(item, self._dependency_scope(item, summary), self._has_fixed_version(item))
			for item in dependency_findings
		]

		# If policy allows dev/test dependencies, remove them from blocking/warn checks.
		policy_allowed = [
			item
			for item, scope, _ in evaluated
			if scope in {"dev_dependency", "test_dependency"} and self._is_policy_allow_dev_test(summary, item, scope)
		]
		remaining = [
			(item, scope, has_fix)
			for item, scope, has_fix in evaluated
			if item not in policy_allowed
		]

		runtime_critical = [
			item for item, scope, _ in remaining if scope == "runtime_dependency" and item.severity == Severity.CRITICAL
		]
		if runtime_critical:
			return self.fail_result(
				reason=(
					f"Trivy detected {len(runtime_critical)} CRITICAL runtime dependency vulnerability(ies)."
				),
				severity=Severity.CRITICAL,
				metadata={
					"rule": "trivy_rule",
					"dependency_count": len(dependency_findings),
					"runtime_critical_count": len(runtime_critical),
					"finding_ids": [item.id for item in runtime_critical],
					"recommendations": [
						"Upgrade runtime dependencies with critical CVEs immediately.",
						"If fixed versions are available, pin to patched versions and redeploy.",
					],
				},
			)

		high_or_no_fix = [
			item
			for item, _scope, has_fix in remaining
			if item.severity == Severity.HIGH or not has_fix
		]
		if high_or_no_fix:
			return self.warn_result(
				reason=(
					f"Trivy detected {len(high_or_no_fix)} dependency finding(s) that are HIGH severity or missing fixed versions."
				),
				severity=self._max_severity(high_or_no_fix),
				metadata={
					"rule": "trivy_rule",
					"dependency_count": len(dependency_findings),
					"warn_count": len(high_or_no_fix),
					"finding_ids": [item.id for item in high_or_no_fix],
					"recommendations": [
						"Prioritize HIGH dependency findings in the next patch window.",
						"Track vulnerabilities without fixed versions and monitor upstream advisories.",
					],
				},
			)

		return self.pass_result(
			reason="Trivy dependency findings are acceptable under current policy.",
			severity=Severity.INFO,
			metadata={
				"rule": "trivy_rule",
				"dependency_count": len(dependency_findings),
				"policy_allowed_dev_test_count": len(policy_allowed),
				"allowed_finding_ids": [item.id for item in policy_allowed],
			},
		)

	def _is_trivy_dependency_finding(self, finding: Finding) -> bool:
		if finding.tool != ScannerType.TRIVY:
			return False
		return str(finding.metadata.get("category") or "").lower() == "dependency"

	def _dependency_scope(self, finding: Finding, summary: ScanSummary) -> str:
		explicit_scope = str(finding.metadata.get("dependency_scope") or "").lower()
		if explicit_scope in {"runtime_dependency", "dev_dependency", "test_dependency"}:
			return explicit_scope

		target = str(finding.metadata.get("target") or finding.file_path or "").replace("\\", "/").lower()
		text = " ".join(
			[
				finding.title,
				finding.description,
				str(finding.package_name or ""),
				target,
			]
		).lower()

		path_parts = {part.lower() for part in PurePath(target).parts}
		test_markers = {"tests", "test", "fixtures", "mocks", "spec", "specs", "__tests__"}
		dev_markers = (
			"dev dependency",
			"development dependency",
			"lint",
			"eslint",
			"prettier",
			"pytest",
			"mypy",
		)

		if path_parts.intersection(test_markers) or any(marker in text for marker in ("test dependency", "testing only")):
			return "test_dependency"
		if any(marker in text for marker in dev_markers):
			return "dev_dependency"

		# Optional summary-level overrides.
		scope_overrides = summary.metadata.get("dependency_scope_overrides")
		if isinstance(scope_overrides, dict) and finding.id in scope_overrides:
			override = str(scope_overrides[finding.id]).lower()
			if override in {"runtime_dependency", "dev_dependency", "test_dependency"}:
				return override

		return "runtime_dependency"

	def _has_fixed_version(self, finding: Finding) -> bool:
		if bool((finding.fixed_version or "").strip()):
			return True
		fixed_version = str(finding.metadata.get("fixed_version") or "")
		return bool(fixed_version.strip())

	def _is_policy_allow_dev_test(self, summary: ScanSummary, finding: Finding, scope: str) -> bool:
		if scope not in {"dev_dependency", "test_dependency"}:
			return False

		# Allow at finding level.
		if bool(finding.metadata.get("policy_allow_dev_test")):
			return True
		if scope == "dev_dependency" and bool(finding.metadata.get("policy_allow_dev")):
			return True
		if scope == "test_dependency" and bool(finding.metadata.get("policy_allow_test")):
			return True

		# Allow at summary/pipeline level.
		if bool(summary.metadata.get("policy_allow_dev_test_dependencies")):
			return True
		if scope == "dev_dependency" and bool(summary.metadata.get("policy_allow_dev_dependencies")):
			return True
		if scope == "test_dependency" and bool(summary.metadata.get("policy_allow_test_dependencies")):
			return True

		return False

	def _max_severity(self, findings: Sequence[Finding]) -> Severity:
		rank = {
			Severity.CRITICAL: 6,
			Severity.HIGH: 5,
			Severity.MEDIUM: 4,
			Severity.LOW: 3,
			Severity.INFO: 2,
			Severity.UNKNOWN: 1,
		}
		if not findings:
			return Severity.INFO
		return sorted(findings, key=lambda item: rank.get(item.severity, 1), reverse=True)[0].severity
