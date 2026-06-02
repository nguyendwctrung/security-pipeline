from __future__ import annotations

from pathlib import Path
from typing import List, Sequence

from ...domain import AgentResult, Finding, GitContext, ScanSummary, ScannerType, Severity
from .base_rule import BaseRule, RuleResult


class SecretRule(BaseRule):
	"""Policy rule for secret-exposure findings from Gitleaks."""

	def evaluate(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		agent_outputs: Sequence[AgentResult],
		git_context: GitContext,
	) -> RuleResult:
		_ = (summary, agent_outputs, git_context)

		secret_findings = [finding for finding in findings if self._is_gitleaks_secret(finding)]
		new_secrets = [finding for finding in secret_findings if finding.is_new]

		if not new_secrets:
			return self.pass_result(
				reason="No new Gitleaks secret findings detected.",
				severity=Severity.INFO,
				metadata={
					"rule": "secret_rule",
					"secret_count": len(secret_findings),
					"new_secret_count": 0,
					"recommendations": [
						"Keep secret scanning enabled in CI.",
					],
				},
			)

		allowlist_or_test = [finding for finding in new_secrets if self._is_allowlisted_or_test_secret(finding)]
		real_new = [finding for finding in new_secrets if finding not in allowlist_or_test]

		if real_new:
			return self.fail_result(
				reason=(
					f"Detected {len(real_new)} new secret finding(s) from Gitleaks that are not allowlisted/test data."
				),
				severity=self._max_severity(real_new),
				metadata={
					"rule": "secret_rule",
					"new_secret_count": len(new_secrets),
					"real_new_secret_count": len(real_new),
					"finding_ids": [item.id for item in real_new],
					"recommendations": [
						"Revoke the exposed credential immediately.",
						"Rotate the secret and update all dependent systems.",
						"Remove secrets from source history and move them to a secure secret manager.",
					],
				},
			)

		return self.warn_result(
			reason=(
				f"Detected {len(allowlist_or_test)} new secret finding(s) marked as allowlisted/test data."
			),
			severity=self._max_severity(allowlist_or_test),
			metadata={
				"rule": "secret_rule",
				"new_secret_count": len(new_secrets),
				"allowlist_or_test_count": len(allowlist_or_test),
				"finding_ids": [item.id for item in allowlist_or_test],
				"recommendations": [
					"Validate that each allowlisted/test secret is truly non-production.",
					"If any secret is real, revoke and rotate it immediately.",
				],
			},
		)

	def _is_gitleaks_secret(self, finding: Finding) -> bool:
		if finding.tool == ScannerType.GITLEAKS:
			return True
		return str(finding.metadata.get("category") or "").lower() == "secret"

	def _is_allowlisted_or_test_secret(self, finding: Finding) -> bool:
		classification = str(finding.metadata.get("secret_classification") or "").lower()
		if classification in {"test", "false_positive", "allowlisted"}:
			return True

		allowlist_flags = (
			"allowlisted",
			"is_allowlisted",
			"allowlist_hit",
			"in_allowlist",
		)
		for key in allowlist_flags:
			if bool(finding.metadata.get(key)):
				return True

		path_parts = {part.lower() for part in Path(finding.file_path).parts}
		if path_parts.intersection({"test", "tests", "fixtures", "samples", "examples", "docs"}):
			return True

		text = " ".join(
			[
				finding.title,
				finding.description,
				str(finding.metadata.get("match") or ""),
			]
		).lower()
		return any(marker in text for marker in ("dummy", "fixture", "example", "sample token", "test key"))

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
