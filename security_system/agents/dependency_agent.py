from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath
from typing import List, Optional, Sequence

from ..domain import AgentResult, Finding, GitContext, RiskLevel, ScannerType, Severity
from .base_agent import AgentConfig, BaseSecurityAgent
from .prompts import get_agent_prompt
from .tools import create_read_only_tools


@dataclass(slots=True)
class DependencyAnalysis:
	"""Internal triage details for a Trivy dependency vulnerability finding."""

	finding: Finding
	dependency_scope: str
	fixed_version_available: bool
	in_changed_files: bool
	risk_score: float
	evidence: List[str]
	recommendations: List[str]


class DependencyAgent(BaseSecurityAgent):
	"""Analyze Trivy dependency findings and prioritize upgrade actions."""

	def __init__(self, llm_model: str = "gemini-2.5-flash-lite", tools: Optional[List[object]] = None) -> None:
		resolved_tools = tools if tools is not None else [create_read_only_tools()]
		super().__init__(
			AgentConfig(
				agent_name="dependency_agent",
				role="Dependency Vulnerability Reviewer",
				goal="Assess vulnerable dependencies, distinguish package scope, and recommend practical upgrades.",
				backstory=(
					"You specialize in package and supply-chain risk analysis. You review Trivy dependency findings, "
					"decide whether vulnerable packages affect runtime or only development workflows, and recommend "
					"safe upgrade actions using fixed versions when available."
				),
				llm_model=llm_model,
				prompt=get_agent_prompt("dependency_agent"),
				tools=resolved_tools,
			)
		)

	def analyze(self, findings: Sequence[Finding], git_context: Optional[GitContext] = None) -> AgentResult:
		dependency_findings = [finding for finding in findings if self._is_dependency_finding(finding)]
		analyses = [self._analyze_finding(finding, git_context) for finding in dependency_findings]

		if not analyses:
			return AgentResult(
				agent_name=self.agent_name,
				risk_score=0.0,
				risk_level=RiskLevel.NONE,
				findings=[],
				recommendations=["No Trivy dependency findings were provided to the dependency agent."],
				summary="No dependency vulnerabilities to analyze.",
				confidence=1.0,
				evidence=["Input finding list did not contain Trivy dependency-category vulnerabilities."],
			)

		average_risk = sum(item.risk_score for item in analyses) / len(analyses)
		risk_level = self._risk_level_from_score(average_risk)
		recommendations = self._merge_recommendations(analyses)
		evidence = [detail for item in analyses for detail in item.evidence]
		confidence = self._confidence_from_analyses(analyses)

		scope_counts = self._count_dependency_scopes(analyses)
		fixable_count = sum(1 for item in analyses if item.fixed_version_available)
		summary = (
			f"Analyzed {len(analyses)} Trivy dependency findings across scopes: {scope_counts}. "
			f"{fixable_count} findings have a fixed version available. Overall dependency risk is {risk_level.value.lower()}."
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

	def _analyze_finding(self, finding: Finding, git_context: Optional[GitContext]) -> DependencyAnalysis:
		dependency_scope = self._classify_dependency_scope(finding)
		fixed_version_available = bool((finding.fixed_version or "").strip())
		in_changed_files = self._is_in_changed_files(finding, git_context)
		risk_score = self._score_finding(finding, dependency_scope, fixed_version_available, in_changed_files)
		evidence = self._build_evidence(finding, dependency_scope, fixed_version_available, in_changed_files)
		recommendations = self._build_recommendations(finding, dependency_scope, fixed_version_available)

		finding.metadata["dependency_scope"] = dependency_scope
		finding.metadata["fixed_version_available"] = fixed_version_available
		finding.metadata["in_changed_files"] = in_changed_files
		finding.metadata["dependency_risk_score"] = round(risk_score, 2)

		return DependencyAnalysis(
			finding=finding,
			dependency_scope=dependency_scope,
			fixed_version_available=fixed_version_available,
			in_changed_files=in_changed_files,
			risk_score=risk_score,
			evidence=evidence,
			recommendations=recommendations,
		)

	def _is_dependency_finding(self, finding: Finding) -> bool:
		if finding.tool != ScannerType.TRIVY:
			return False
		return str(finding.metadata.get("category") or "").lower() == "dependency"

	def _classify_dependency_scope(self, finding: Finding) -> str:
		target = str(finding.metadata.get("target") or finding.file_path or "").replace("\\", "/").lower()
		text = " ".join(
			[
				finding.title,
				finding.description,
				str(finding.package_name or ""),
				str(finding.rule_id or ""),
				target,
			]
		).lower()

		path_parts = {part.lower() for part in PurePath(target).parts}

		test_markers = {
			"tests",
			"test",
			"spec",
			"specs",
			"fixtures",
			"mocks",
			"__tests__",
		}
		dev_files = {
			"package-lock.json",
			"pnpm-lock.yaml",
			"yarn.lock",
			"poetry.lock",
			"pipfile.lock",
			"requirements-dev.txt",
			"tox.ini",
			"pyproject.toml",
			"setup.cfg",
		}
		dev_markers = (
			"devdependency",
			"dev dependency",
			"development dependency",
			"lint",
			"eslint",
			"prettier",
			"webpack",
			"vite",
			"babel",
			"pytest",
			"mypy",
			"black",
		)

		file_name = PurePath(target).name.lower()
		if path_parts.intersection(test_markers) or any(marker in text for marker in ("test dependency", "testing only", "fixture")):
			return "test_dependency"
		if file_name in dev_files or any(marker in text for marker in dev_markers):
			return "dev_dependency"
		return "runtime_dependency"

	def _is_in_changed_files(self, finding: Finding, git_context: Optional[GitContext]) -> bool:
		if git_context is None:
			return False

		finding_path = finding.file_path.replace("\\", "/")
		target_path = str(finding.metadata.get("target") or "").replace("\\", "/")
		candidates = [path for path in (finding_path, target_path) if path]

		for changed_file in git_context.changed_files:
			normalized_changed = changed_file.replace("\\", "/")
			for candidate in candidates:
				if candidate == normalized_changed or candidate.endswith(normalized_changed) or normalized_changed.endswith(candidate):
					return True
		return False

	def _score_finding(
		self,
		finding: Finding,
		dependency_scope: str,
		fixed_version_available: bool,
		in_changed_files: bool,
	) -> float:
		score = 18.0

		if finding.severity == Severity.CRITICAL:
			score += 45.0
		elif finding.severity == Severity.HIGH:
			score += 30.0
		elif finding.severity == Severity.MEDIUM:
			score += 18.0
		elif finding.severity == Severity.LOW:
			score += 8.0

		scope_bonus = {
			"runtime_dependency": 18.0,
			"dev_dependency": 7.0,
			"test_dependency": 3.0,
		}
		score += scope_bonus.get(dependency_scope, 8.0)

		if fixed_version_available:
			score += 7.0
		if in_changed_files:
			score += 8.0
		if finding.is_new:
			score += 5.0
		if finding.cve:
			score += 5.0

		return max(0.0, min(100.0, score))

	def _build_evidence(
		self,
		finding: Finding,
		dependency_scope: str,
		fixed_version_available: bool,
		in_changed_files: bool,
	) -> List[str]:
		package_name = finding.package_name or "unknown-package"
		installed_version = str(finding.metadata.get("installed_version") or "unknown")
		evidence = [
			f"Finding {finding.id} affects package {package_name} ({installed_version}).",
			f"Dependency scope classified as {dependency_scope}.",
			f"Affected manifest or target: {finding.file_path}.",
		]
		if finding.cve:
			evidence.append(f"CVE identified: {finding.cve}.")
		if fixed_version_available:
			evidence.append(f"A fixed version is available: {finding.fixed_version}.")
		else:
			evidence.append("No fixed version was provided in the Trivy result.")
		if in_changed_files:
			evidence.append("The vulnerable dependency appears in the current changed file set.")
		else:
			evidence.append("The vulnerable dependency was not directly matched to the current changed files.")
		return evidence

	def _build_recommendations(
		self,
		finding: Finding,
		dependency_scope: str,
		fixed_version_available: bool,
	) -> List[str]:
		package_name = finding.package_name or "the affected package"
		installed_version = str(finding.metadata.get("installed_version") or "current version")
		target = str(finding.metadata.get("target") or finding.file_path or "the dependency manifest")

		recommendations: List[str] = []
		if fixed_version_available and finding.fixed_version:
			recommendations.append(
				f"Upgrade {package_name} in {target} from {installed_version} to {finding.fixed_version}."
			)
		else:
			recommendations.append(
				f"Review vendor advisories for {package_name} and pin it to the nearest patched release once one becomes available."
			)

		if dependency_scope == "runtime_dependency":
			recommendations.append(
				f"Prioritize this package upgrade because {package_name} appears to affect the runtime attack surface."
			)
		elif dependency_scope == "dev_dependency":
			recommendations.append(
				f"Schedule the {package_name} upgrade in the build or tooling stack and verify CI, bundling, and local developer workflows after the update."
			)
		else:
			recommendations.append(
				f"Update {package_name} in test-only tooling and confirm the test harness or fixtures still behave as expected."
			)

		if finding.cve:
			recommendations.append(
				f"Track remediation for {finding.cve} in the dependency management backlog until the vulnerable version is fully removed."
			)

		return recommendations

	def _merge_recommendations(self, analyses: Sequence[DependencyAnalysis]) -> List[str]:
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

	def _confidence_from_analyses(self, analyses: Sequence[DependencyAnalysis]) -> float:
		if not analyses:
			return 0.0

		confidence = 0.72
		if any(item.fixed_version_available for item in analyses):
			confidence += 0.08
		if any(item.in_changed_files for item in analyses):
			confidence += 0.1
		if all(item.dependency_scope in {"runtime_dependency", "dev_dependency", "test_dependency"} for item in analyses):
			confidence += 0.05
		return min(1.0, round(confidence, 2))

	def _count_dependency_scopes(self, analyses: Sequence[DependencyAnalysis]) -> str:
		counts: dict[str, int] = {}
		for analysis in analyses:
			counts[analysis.dependency_scope] = counts.get(analysis.dependency_scope, 0) + 1
		return ", ".join(f"{scope}={count}" for scope, count in sorted(counts.items()))
