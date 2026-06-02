from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ...domain import AgentResult, Finding, GitContext, ScanSummary, ScannerType, Severity
from .base_rule import BaseRule, RuleResult


class SemgrepRule(BaseRule):
	"""Policy rule for Semgrep findings in changed code paths."""

	def evaluate(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		agent_outputs: Sequence[AgentResult],
		git_context: GitContext,
	) -> RuleResult:
		_ = (summary, agent_outputs)

		semgrep_findings = [finding for finding in findings if finding.tool == ScannerType.SEMGREP]
		if not semgrep_findings:
			return self.pass_result(
				reason="No Semgrep findings detected.",
				severity=Severity.INFO,
				metadata={
					"rule": "semgrep_rule",
					"semgrep_count": 0,
				},
			)

		changed_findings = [item for item in semgrep_findings if self._is_in_changed_files(item, git_context)]
		if not changed_findings:
			return self.pass_result(
				reason="Semgrep findings are outside changed files or are in accepted baseline.",
				severity=Severity.INFO,
				metadata={
					"rule": "semgrep_rule",
					"semgrep_count": len(semgrep_findings),
					"changed_file_count": 0,
				},
			)

		high_or_critical = [
			item for item in changed_findings if item.severity in {Severity.HIGH, Severity.CRITICAL}
		]
		if high_or_critical:
			return self.fail_result(
				reason=(
					f"Semgrep detected {len(high_or_critical)} HIGH/CRITICAL finding(s) in changed files."
				),
				severity=self._max_severity(high_or_critical),
				metadata={
					"rule": "semgrep_rule",
					"changed_semgrep_count": len(changed_findings),
					"high_or_critical_count": len(high_or_critical),
					"finding_ids": [item.id for item in high_or_critical],
					"recommendations": [
						"Fix or suppress each HIGH/CRITICAL finding with explicit justification before merge.",
						"Prioritize exploitable sink paths first (for example auth, query execution, deserialization).",
					],
				},
			)

		medium_findings = [item for item in changed_findings if item.severity == Severity.MEDIUM]
		if medium_findings:
			return self.warn_result(
				reason=f"Semgrep detected {len(medium_findings)} MEDIUM finding(s) in changed files.",
				severity=Severity.MEDIUM,
				metadata={
					"rule": "semgrep_rule",
					"changed_semgrep_count": len(changed_findings),
					"medium_count": len(medium_findings),
					"finding_ids": [item.id for item in medium_findings],
					"recommendations": [
						"Address medium findings before release or add time-bound risk acceptance.",
					],
				},
			)

		# Remaining changed-file findings are low/info/unknown; treat as pass with context.
		return self.pass_result(
			reason="Semgrep findings in changed files are below MEDIUM severity or accepted baseline.",
			severity=Severity.LOW,
			metadata={
				"rule": "semgrep_rule",
				"changed_semgrep_count": len(changed_findings),
				"finding_ids": [item.id for item in changed_findings],
			},
		)

	def _is_in_changed_files(self, finding: Finding, git_context: GitContext) -> bool:
		if self._is_baseline_finding(finding):
			return False

		finding_path = finding.file_path.replace("\\", "/")
		for changed in git_context.changed_files:
			normalized_changed = changed.replace("\\", "/")
			if (
				finding_path == normalized_changed
				or finding_path.endswith(normalized_changed)
				or normalized_changed.endswith(finding_path)
			):
				return True
		return False

	def _is_baseline_finding(self, finding: Finding) -> bool:
		baseline_flags = ("in_baseline", "baseline_hit", "is_baseline")
		for flag in baseline_flags:
			if bool(finding.metadata.get(flag)):
				return True

		status_text = str(finding.metadata.get("status") or "").lower()
		if status_text in {"baseline", "accepted_baseline"}:
			return True

		text = " ".join(
			[
				finding.title,
				finding.description,
				str(finding.metadata.get("message") or ""),
			]
		).lower()
		if "baseline" in text and "valid" in text:
			return True

		# Optional marker by path convention for baseline snapshots.
		path_parts = {part.lower() for part in Path(finding.file_path).parts}
		return "baseline" in path_parts

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
