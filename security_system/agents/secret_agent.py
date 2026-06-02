from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from ..domain import AgentResult, Finding, GitContext, RiskLevel, ScannerType, Severity
from .base_agent import AgentConfig, BaseSecurityAgent
from .prompts import get_agent_prompt
from .tools import create_read_only_tools


@dataclass(slots=True)
class SecretAnalysis:
	"""Internal classification for a potential secret leak."""

	finding: Finding
	classification: str
	in_changed_files: bool
	risk_score: float
	evidence: List[str]
	recommendations: List[str]


class SecretAgent(BaseSecurityAgent):
	"""Analyze gitleaks findings and triage likely real versus non-actionable secrets."""

	def __init__(self, llm_model: str = "gemini-2.5-flash-lite", tools: Optional[List[object]] = None) -> None:
		resolved_tools = tools if tools is not None else [create_read_only_tools()]
		super().__init__(
			AgentConfig(
				agent_name="secret_agent",
				role="Secret Leak Triage Specialist",
				goal="Determine whether secret findings are real, risky, and require immediate remediation.",
				backstory=(
					"You specialize in reviewing leaked credentials, test keys, and false positives from source control "
					"scanners. You distinguish between real production leaks and benign placeholders, then propose "
					"practical remediation steps."
				),
				llm_model=llm_model,
				prompt=get_agent_prompt("secret_agent"),
				tools=resolved_tools,
			)
		)

	def analyze(self, findings: Sequence[Finding], git_context: Optional[GitContext] = None) -> AgentResult:
		secret_findings = [finding for finding in findings if self._is_secret_finding(finding)]
		analyses = [self._analyze_secret(finding, git_context) for finding in secret_findings]

		if not analyses:
			return AgentResult(
				agent_name=self.agent_name,
				risk_score=0.0,
				risk_level=RiskLevel.NONE,
				findings=[],
				recommendations=["No gitleaks secret findings were provided to the secret agent."],
				summary="No secret findings to analyze.",
				confidence=1.0,
				evidence=["Input finding list did not contain any gitleaks or secret-category findings."],
			)

		total_risk = sum(item.risk_score for item in analyses)
		average_risk = total_risk / len(analyses)
		real_count = sum(1 for item in analyses if item.classification == "real")
		test_count = sum(1 for item in analyses if item.classification == "test")
		false_positive_count = sum(1 for item in analyses if item.classification == "false_positive")

		recommendations = self._merge_recommendations(analyses)
		evidence = [detail for item in analyses for detail in item.evidence]
		risk_level = self._risk_level_from_score(average_risk)
		confidence = self._confidence_from_analyses(analyses)

		summary = (
			f"Analyzed {len(analyses)} secret findings: {real_count} likely real, {test_count} likely test data, "
			f"and {false_positive_count} likely false positives. "
			f"Overall leak risk is {risk_level.value.lower()}."
		)

		return AgentResult(
			agent_name=self.agent_name,
			risk_score=round(average_risk, 2),
			risk_level=risk_level,
			findings=[item.finding for item in analyses],
			recommendations=recommendations,
			summary=summary,
			confidence=confidence,
			evidence=evidence,
		)

	def _analyze_secret(self, finding: Finding, git_context: Optional[GitContext]) -> SecretAnalysis:
		classification = self._classify_secret(finding)
		in_changed_files = self._is_in_changed_files(finding, git_context)
		risk_score = self._score_secret(finding, classification, in_changed_files)
		evidence = self._build_evidence(finding, classification, in_changed_files)
		recommendations = self._build_recommendations(classification, in_changed_files)

		finding.metadata["secret_classification"] = classification
		finding.metadata["in_changed_files"] = in_changed_files
		finding.metadata["secret_risk_score"] = round(risk_score, 2)

		return SecretAnalysis(
			finding=finding,
			classification=classification,
			in_changed_files=in_changed_files,
			risk_score=risk_score,
			evidence=evidence,
			recommendations=recommendations,
		)

	def _is_secret_finding(self, finding: Finding) -> bool:
		if finding.tool == ScannerType.GITLEAKS:
			return True
		return str(finding.metadata.get("category") or "").lower() == "secret"

	def _classify_secret(self, finding: Finding) -> str:
		text = " ".join(
			[
				finding.title,
				finding.description,
				finding.file_path,
				str(finding.rule_id or ""),
				str(finding.metadata.get("match") or ""),
			]
		).lower()

		false_positive_markers = ("false positive", "example.com", "<redacted>", "xxxxx", "sample token")
		test_markers = (
			"test",
			"dummy",
			"mock",
			"fixture",
			"example",
			"sample",
			"sandbox",
		)

		path_parts = {part.lower() for part in Path(finding.file_path).parts}
		if any(marker in text for marker in false_positive_markers):
			return "false_positive"
		if path_parts.intersection({"tests", "test", "fixtures", "samples", "examples", "docs"}):
			return "test"
		if any(marker in text for marker in test_markers):
			return "test"
		return "real"

	def _is_in_changed_files(self, finding: Finding, git_context: Optional[GitContext]) -> bool:
		if git_context is None:
			return False

		finding_path = finding.file_path.replace("\\", "/")
		for changed_file in git_context.changed_files:
			normalized_changed = changed_file.replace("\\", "/")
			if finding_path == normalized_changed or finding_path.endswith(normalized_changed) or normalized_changed.endswith(finding_path):
				return True
		return False

	def _score_secret(self, finding: Finding, classification: str, in_changed_files: bool) -> float:
		score = 25.0

		if finding.severity == Severity.CRITICAL:
			score += 45.0
		elif finding.severity == Severity.HIGH:
			score += 30.0
		elif finding.severity == Severity.MEDIUM:
			score += 15.0

		if classification == "real":
			score += 20.0
		elif classification == "test":
			score -= 20.0
		elif classification == "false_positive":
			score -= 35.0

		if in_changed_files:
			score += 10.0
		if finding.is_new:
			score += 5.0

		return max(0.0, min(100.0, score))

	def _build_evidence(self, finding: Finding, classification: str, in_changed_files: bool) -> List[str]:
		evidence = [
			f"Finding {finding.id} classified as {classification}.",
			f"Secret detected in file {finding.file_path}.",
		]
		if finding.rule_id:
			evidence.append(f"Matched gitleaks rule: {finding.rule_id}.")
		if in_changed_files:
			evidence.append("Secret appears in files changed by the analyzed commit.")
		else:
			evidence.append("Secret was not matched against the changed file list.")
		match_preview = str(finding.metadata.get("match") or "").strip()
		if match_preview:
			evidence.append(f"Matched content preview: {match_preview[:120]}")
		return evidence

	def _build_recommendations(self, classification: str, in_changed_files: bool) -> List[str]:
		recommendations: List[str] = []

		if classification == "real":
			recommendations.extend(
				[
					"Revoke the exposed key or credential immediately.",
					"Rotate the secret and update downstream systems to use the new value.",
					"Move the secret to GitHub Secrets or environment variables instead of committing it to source control.",
				]
			)
		elif classification == "test":
			recommendations.extend(
				[
					"Replace committed test secrets with clearly non-sensitive placeholders where possible.",
					"Document approved test credentials in fixtures or test data allowlists to reduce future noise.",
				]
			)
		else:
			recommendations.extend(
				[
					"Review this finding and add an allowlist rule if it is a confirmed false positive.",
					"Keep secret scanning enabled and periodically revalidate the suppression rule.",
				]
			)

		if in_changed_files:
			recommendations.append("Block the pull request until the changed file no longer contains the leaked secret.")

		return recommendations

	def _merge_recommendations(self, analyses: Sequence[SecretAnalysis]) -> List[str]:
		ordered: List[str] = []
		seen = set()
		for analysis in analyses:
			for recommendation in analysis.recommendations:
				if recommendation in seen:
					continue
				seen.add(recommendation)
				ordered.append(recommendation)
		return ordered

	def _risk_level_from_score(self, score: float) -> RiskLevel:
		if score >= 80.0:
			return RiskLevel.CRITICAL
		if score >= 60.0:
			return RiskLevel.HIGH
		if score >= 35.0:
			return RiskLevel.MEDIUM
		if score > 0.0:
			return RiskLevel.LOW
		return RiskLevel.NONE

	def _confidence_from_analyses(self, analyses: Sequence[SecretAnalysis]) -> float:
		if not analyses:
			return 0.0

		confidence = 0.75
		if all(item.classification in {"real", "test", "false_positive"} for item in analyses):
			confidence += 0.1
		if any(item.in_changed_files for item in analyses):
			confidence += 0.1
		return min(1.0, round(confidence, 2))
