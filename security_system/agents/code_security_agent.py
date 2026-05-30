from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from ..domain import AgentResult, Finding, GitContext, RiskLevel, ScannerType, Severity
from .base_agent import AgentConfig, BaseSecurityAgent
from .prompts import get_agent_prompt
from .tools import create_read_only_tools


@dataclass(slots=True)
class CodeSecurityAnalysis:
	"""Internal triage details for a Semgrep code security finding."""

	finding: Finding
	vulnerability_type: str
	in_changed_files: bool
	in_git_diff: bool
	risk_score: float
	evidence: List[str]
	recommendations: List[str]


class CodeSecurityAgent(BaseSecurityAgent):
	"""Analyze Semgrep findings related to source-code security vulnerabilities."""

	def __init__(self, llm_model: str = "gemini-2.5-flash-lite", tools: Optional[List[object]] = None) -> None:
		resolved_tools = tools if tools is not None else [create_read_only_tools()]
		super().__init__(
			AgentConfig(
				agent_name="code_security_agent",
				role="Source Code Vulnerability Reviewer",
				goal="Prioritize Semgrep-detected code vulnerabilities and propose precise code remediation steps.",
				backstory=(
					"You specialize in reviewing application security findings in source code. You focus on exploitability, "
					"whether the risky code appears in the current change set, and how developers should edit files or rules "
					"to remediate the issue safely."
				),
				llm_model=llm_model,
				prompt=get_agent_prompt("code_security_agent"),
				tools=resolved_tools,
			)
		)

	def analyze(self, findings: Sequence[Finding], git_context: Optional[GitContext] = None) -> AgentResult:
		semgrep_findings = [finding for finding in findings if self._is_code_security_finding(finding)]
		analyses = [self._analyze_finding(finding, git_context) for finding in semgrep_findings]

		if not analyses:
			return AgentResult(
				agent_name=self.agent_name,
				risk_score=0.0,
				risk_level=RiskLevel.NONE,
				findings=[],
				recommendations=["No Semgrep source-code findings were provided to the code security agent."],
				summary="No Semgrep findings to analyze.",
				confidence=1.0,
				evidence=["Input finding list did not contain Semgrep code security findings."],
			)

		average_risk = sum(item.risk_score for item in analyses) / len(analyses)
		recommendations = self._merge_recommendations(analyses)
		evidence = [detail for item in analyses for detail in item.evidence]
		risk_level = self._risk_level_from_score(average_risk)
		confidence = self._confidence_from_analyses(analyses)

		type_counts = self._count_types(analyses)
		summary = (
			f"Analyzed {len(analyses)} Semgrep findings across source code. "
			f"Detected categories: {type_counts}. Overall code vulnerability risk is {risk_level.value.lower()}."
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

	def _analyze_finding(self, finding: Finding, git_context: Optional[GitContext]) -> CodeSecurityAnalysis:
		vulnerability_type = self._classify_vulnerability(finding)
		in_changed_files = self._is_in_changed_files(finding, git_context)
		in_git_diff = self._is_in_git_diff(finding, git_context)
		risk_score = self._score_finding(finding, vulnerability_type, in_changed_files, in_git_diff)
		evidence = self._build_evidence(finding, vulnerability_type, in_changed_files, in_git_diff)
		recommendations = self._build_recommendations(finding, vulnerability_type)

		finding.metadata["vulnerability_type"] = vulnerability_type
		finding.metadata["in_changed_files"] = in_changed_files
		finding.metadata["in_git_diff"] = in_git_diff
		finding.metadata["code_risk_score"] = round(risk_score, 2)

		return CodeSecurityAnalysis(
			finding=finding,
			vulnerability_type=vulnerability_type,
			in_changed_files=in_changed_files,
			in_git_diff=in_git_diff,
			risk_score=risk_score,
			evidence=evidence,
			recommendations=recommendations,
		)

	def _is_code_security_finding(self, finding: Finding) -> bool:
		if finding.tool != ScannerType.SEMGREP:
			return False
		category = str(finding.metadata.get("category") or "").lower()
		return category in {"security", "code"} or True

	def _classify_vulnerability(self, finding: Finding) -> str:
		text = " ".join(
			[
				finding.title,
				finding.description,
				str(finding.rule_id or ""),
				str(finding.metadata.get("metadata") or ""),
				str(finding.metadata.get("lines") or ""),
			]
		).lower()

		if any(token in text for token in ("sql", "sqli", "injection", "execute raw query", "select * from")):
			return "sql_injection"
		if any(token in text for token in ("xss", "cross-site scripting", "dangerouslysetinnerhtml", "innerhtml")):
			return "xss"
		if any(token in text for token in ("auth bypass", "authorization bypass", "missing authorization", "missing auth")):
			return "auth_bypass"
		if any(token in text for token in ("deserialize", "deserialization", "pickle", "yaml.load", "objectinputstream")):
			return "insecure_deserialization"
		if any(token in text for token in ("debug=true", "verify=false", "disable security", "hardcoded config", "insecure config")):
			return "dangerous_config"
		return "generic_code_vulnerability"

	def _is_in_changed_files(self, finding: Finding, git_context: Optional[GitContext]) -> bool:
		if git_context is None:
			return False

		finding_path = finding.file_path.replace("\\", "/")
		for changed_file in git_context.changed_files:
			normalized_changed = changed_file.replace("\\", "/")
			if finding_path == normalized_changed or finding_path.endswith(normalized_changed) or normalized_changed.endswith(finding_path):
				return True
		return False

	def _is_in_git_diff(self, finding: Finding, git_context: Optional[GitContext]) -> bool:
		if git_context is None or not git_context.diff:
			return False

		diff_text = git_context.diff.lower()
		if finding.file_path.replace("\\", "/").lower() not in diff_text:
			return False

		rule_text = str(finding.rule_id or "").lower()
		title_text = finding.title.lower()
		return any(token and token in diff_text for token in (rule_text, title_text[:40]))

	def _score_finding(
		self,
		finding: Finding,
		vulnerability_type: str,
		in_changed_files: bool,
		in_git_diff: bool,
	) -> float:
		score = 20.0

		if finding.severity == Severity.CRITICAL:
			score += 45.0
		elif finding.severity == Severity.HIGH:
			score += 30.0
		elif finding.severity == Severity.MEDIUM:
			score += 15.0
		elif finding.severity == Severity.LOW:
			score += 5.0

		type_bonus = {
			"sql_injection": 25.0,
			"xss": 18.0,
			"auth_bypass": 25.0,
			"insecure_deserialization": 22.0,
			"dangerous_config": 15.0,
			"generic_code_vulnerability": 10.0,
		}
		score += type_bonus.get(vulnerability_type, 10.0)

		if in_changed_files:
			score += 10.0
		if in_git_diff:
			score += 10.0
		if finding.is_new:
			score += 5.0

		return max(0.0, min(100.0, score))

	def _build_evidence(
		self,
		finding: Finding,
		vulnerability_type: str,
		in_changed_files: bool,
		in_git_diff: bool,
	) -> List[str]:
		evidence = [
			f"Finding {finding.id} classified as {vulnerability_type}.",
			f"Source file affected: {finding.file_path}.",
		]
		if finding.rule_id:
			evidence.append(f"Semgrep rule triggered: {finding.rule_id}.")
		if in_changed_files:
			evidence.append("The vulnerable file is part of the current changed file set.")
		if in_git_diff:
			evidence.append("The risky pattern appears to overlap with the current git diff.")
		if not in_changed_files and not in_git_diff:
			evidence.append("The finding was not directly correlated with the current diff and may pre-exist the change set.")
		return evidence

	def _build_recommendations(self, finding: Finding, vulnerability_type: str) -> List[str]:
		file_hint = f"Edit {finding.file_path}"
		rule_hint = f"Review Semgrep rule {finding.rule_id}" if finding.rule_id else "Review the triggered Semgrep rule"

		recommendations = {
			"sql_injection": [
				f"{file_hint} to replace dynamic query construction with parameterized statements or ORM-bound parameters.",
				f"{rule_hint} and add a safe-query helper wrapper if this pattern appears repeatedly.",
			],
			"xss": [
				f"{file_hint} to escape or sanitize user-controlled output before rendering it to the client.",
				f"{rule_hint} and replace unsafe DOM APIs with framework-safe rendering patterns.",
			],
			"auth_bypass": [
				f"{file_hint} to enforce authentication and authorization checks before the protected code path executes.",
				f"{rule_hint} and centralize access control in middleware or guard functions.",
			],
			"insecure_deserialization": [
				f"{file_hint} to remove unsafe deserialization and use strict, validated data formats instead.",
				f"{rule_hint} and block dangerous loader APIs such as unrestricted pickle or yaml.load usage.",
			],
			"dangerous_config": [
				f"{file_hint} to remove hardcoded insecure flags and move configuration to safe environment-based settings.",
				f"{rule_hint} and add a secure default configuration baseline.",
			],
		}

		return recommendations.get(
			vulnerability_type,
			[
				f"{file_hint} to remove the insecure pattern and align with the secure coding standard for this module.",
				f"{rule_hint} to understand the exact unsafe pattern that should be eliminated.",
			],
		)

	def _merge_recommendations(self, analyses: Sequence[CodeSecurityAnalysis]) -> List[str]:
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
		if score >= 85.0:
			return RiskLevel.CRITICAL
		if score >= 65.0:
			return RiskLevel.HIGH
		if score >= 40.0:
			return RiskLevel.MEDIUM
		if score > 0.0:
			return RiskLevel.LOW
		return RiskLevel.NONE

	def _confidence_from_analyses(self, analyses: Sequence[CodeSecurityAnalysis]) -> float:
		if not analyses:
			return 0.0

		confidence = 0.7
		if any(item.in_changed_files for item in analyses):
			confidence += 0.1
		if any(item.in_git_diff for item in analyses):
			confidence += 0.1
		if all(item.vulnerability_type != "generic_code_vulnerability" for item in analyses):
			confidence += 0.05
		return min(1.0, round(confidence, 2))

	def _count_types(self, analyses: Sequence[CodeSecurityAnalysis]) -> str:
		counts: dict[str, int] = {}
		for analysis in analyses:
			counts[analysis.vulnerability_type] = counts.get(analysis.vulnerability_type, 0) + 1
		return ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
