from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import List, Optional, Sequence

from ..domain import AgentResult, Finding, GitContext, RiskLevel, ScannerType, Severity
from .base_agent import AgentConfig, BaseSecurityAgent
from .prompts import get_agent_prompt
from .tools import create_read_only_tools


@dataclass(slots=True)
class DockerImageAnalysis:
	"""Internal triage details for Trivy Docker image vulnerability findings."""

	finding: Finding
	base_image: str
	base_image_status: str
	has_critical_cve: bool
	in_changed_files: bool
	risk_score: float
	evidence: List[str]
	recommendations: List[str]


class DockerImageAgent(BaseSecurityAgent):
	"""Analyze Trivy image-scan findings and prioritize container hardening actions."""

	_IMAGE_RE = re.compile(r"([a-z0-9./_-]+(?::[a-zA-Z0-9._-]+|@sha256:[a-f0-9]{16,}))")

	def __init__(self, llm_model: str = "gemini-2.5-flash-lite", tools: Optional[List[object]] = None) -> None:
		resolved_tools = tools if tools is not None else [create_read_only_tools()]
		super().__init__(
			AgentConfig(
				agent_name="docker_image_agent",
				role="Container Image Security Reviewer",
				goal="Assess Trivy image vulnerabilities, evaluate image freshness, and recommend secure image hardening.",
				backstory=(
					"You specialize in Docker image security and supply-chain hardening. You review image-layer CVEs, "
					"check if base images are outdated, and provide concrete remediation by switching base image, "
					"upgrading image tag, and reducing unnecessary packages."
				),
				llm_model=llm_model,
				prompt=get_agent_prompt("docker_image_agent"),
				tools=resolved_tools,
			)
		)

	def analyze(self, findings: Sequence[Finding], git_context: Optional[GitContext] = None) -> AgentResult:
		image_findings = [finding for finding in findings if self._is_image_finding(finding)]
		analyses = [self._analyze_finding(finding, git_context) for finding in image_findings]

		if not analyses:
			return AgentResult(
				agent_name=self.agent_name,
				risk_score=0.0,
				risk_level=RiskLevel.NONE,
				findings=[],
				recommendations=["No Trivy image-scan findings were provided to the docker image agent."],
				summary="No Docker image findings to analyze.",
				confidence=1.0,
				evidence=["Input finding list did not contain Trivy image-scan vulnerabilities."],
			)

		average_risk = sum(item.risk_score for item in analyses) / len(analyses)
		risk_level = self._risk_level_from_score(average_risk)
		recommendations = self._merge_recommendations(analyses)
		evidence = [detail for item in analyses for detail in item.evidence]
		confidence = self._confidence_from_analyses(analyses)

		critical_count = sum(1 for item in analyses if item.has_critical_cve)
		outdated_count = sum(1 for item in analyses if item.base_image_status == "outdated")
		summary = (
			f"Analyzed {len(analyses)} Trivy image findings. "
			f"Critical-CVE findings: {critical_count}; outdated base-image indicators: {outdated_count}. "
			f"Overall container image risk is {risk_level.value.lower()}."
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

	def _analyze_finding(self, finding: Finding, git_context: Optional[GitContext]) -> DockerImageAnalysis:
		base_image = self._extract_base_image(finding)
		base_image_status = self._classify_base_image_status(base_image)
		has_critical_cve = bool(finding.cve) and finding.severity == Severity.CRITICAL
		in_changed_files = self._is_in_changed_files(finding, git_context)
		risk_score = self._score_finding(finding, base_image_status, has_critical_cve, in_changed_files)
		evidence = self._build_evidence(finding, base_image, base_image_status, has_critical_cve, in_changed_files)
		recommendations = self._build_recommendations(finding, base_image, base_image_status, has_critical_cve)

		finding.metadata["base_image"] = base_image
		finding.metadata["base_image_status"] = base_image_status
		finding.metadata["critical_cve_in_layer"] = has_critical_cve
		finding.metadata["in_changed_files"] = in_changed_files
		finding.metadata["docker_image_risk_score"] = round(risk_score, 2)

		return DockerImageAnalysis(
			finding=finding,
			base_image=base_image,
			base_image_status=base_image_status,
			has_critical_cve=has_critical_cve,
			in_changed_files=in_changed_files,
			risk_score=risk_score,
			evidence=evidence,
			recommendations=recommendations,
		)

	def _is_image_finding(self, finding: Finding) -> bool:
		if finding.tool != ScannerType.TRIVY:
			return False
		scan_type = str(finding.metadata.get("scan_type") or "").lower()
		if scan_type == "image":
			return True

		# Fallback for payloads that do not preserve scan_type but include image-like targets.
		target = str(finding.metadata.get("target") or finding.file_path or "").lower()
		return ":" in target or "@sha256:" in target

	def _extract_base_image(self, finding: Finding) -> str:
		for candidate in (
			str(finding.metadata.get("base_image") or ""),
			str(finding.metadata.get("target") or ""),
			finding.file_path,
			finding.title,
			finding.description,
		):
			match = self._IMAGE_RE.search(candidate.lower())
			if match:
				return match.group(1)
		return "unknown"

	def _classify_base_image_status(self, base_image: str) -> str:
		if base_image == "unknown":
			return "unknown"

		if "@sha256:" in base_image:
			return "pinned_digest"

		name, tag = (base_image.split(":", 1) + [""])[:2]
		if not tag or tag == "latest":
			return "outdated"

		match = re.search(r"(\d+)(?:\.(\d+))?", tag)
		if not match:
			return "unknown"

		major = int(match.group(1))
		minor = int(match.group(2) or 0)

		if "python" in name and major <= 3 and minor < 10:
			return "outdated"
		if "node" in name and major < 18:
			return "outdated"
		if "ubuntu" in name and major < 22:
			return "outdated"
		if "debian" in name and major < 11:
			return "outdated"
		if "alpine" in name and (major < 3 or (major == 3 and minor < 18)):
			return "outdated"
		if "golang" in name and major < 1:
			return "outdated"

		return "current"

	def _is_in_changed_files(self, finding: Finding, git_context: Optional[GitContext]) -> bool:
		if git_context is None:
			return False

		target = str(finding.metadata.get("target") or finding.file_path or "").replace("\\", "/")
		candidates = [target, finding.file_path.replace("\\", "/")]
		for changed_file in git_context.changed_files:
			normalized_changed = changed_file.replace("\\", "/")
			for candidate in candidates:
				if not candidate:
					continue
				if candidate == normalized_changed or candidate.endswith(normalized_changed) or normalized_changed.endswith(candidate):
					return True

		# Common Docker build files are considered related context for image vulnerabilities.
		for changed_file in git_context.changed_files:
			name = PurePath(changed_file).name.lower()
			if name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "containerfile"}:
				return True
		return False

	def _score_finding(
		self,
		finding: Finding,
		base_image_status: str,
		has_critical_cve: bool,
		in_changed_files: bool,
	) -> float:
		score = 20.0

		if finding.severity == Severity.CRITICAL:
			score += 45.0
		elif finding.severity == Severity.HIGH:
			score += 30.0
		elif finding.severity == Severity.MEDIUM:
			score += 18.0
		elif finding.severity == Severity.LOW:
			score += 8.0

		if has_critical_cve:
			score += 12.0
		if base_image_status == "outdated":
			score += 15.0
		elif base_image_status == "pinned_digest":
			score -= 5.0
		if finding.fixed_version:
			score += 7.0
		if in_changed_files:
			score += 8.0
		if finding.is_new:
			score += 5.0

		return max(0.0, min(100.0, score))

	def _build_evidence(
		self,
		finding: Finding,
		base_image: str,
		base_image_status: str,
		has_critical_cve: bool,
		in_changed_files: bool,
	) -> List[str]:
		package_name = finding.package_name or "unknown-package"
		installed = str(finding.metadata.get("installed_version") or "unknown")
		target = str(finding.metadata.get("target") or finding.file_path or "unknown-target")

		evidence = [
			f"Image-layer finding {finding.id} affects package {package_name} ({installed}).",
			f"Image target/layer: {target}.",
			f"Base image inferred as {base_image} with status {base_image_status}.",
		]
		if finding.cve:
			evidence.append(f"CVE observed in image layer: {finding.cve}.")
		if has_critical_cve:
			evidence.append("This finding is a critical CVE in the container image layer.")
		if finding.fixed_version:
			evidence.append(f"A fixed package version is available: {finding.fixed_version}.")
		else:
			evidence.append("No fixed package version was provided by Trivy for this layer finding.")
		if in_changed_files:
			evidence.append("Current changes include container-related files tied to this image risk.")
		return evidence

	def _build_recommendations(
		self,
		finding: Finding,
		base_image: str,
		base_image_status: str,
		has_critical_cve: bool,
	) -> List[str]:
		package_name = finding.package_name or "the vulnerable package"
		target = str(finding.metadata.get("target") or finding.file_path or "the image build definition")
		installed = str(finding.metadata.get("installed_version") or "current version")

		recommendations: List[str] = []

		if base_image_status in {"outdated", "unknown"}:
			recommendations.append(
				f"Change the base image in {target} to a current and maintained variant (for example, distroless, slim, or latest LTS)."
			)
		if base_image_status == "outdated":
			recommendations.append(
				f"Upgrade image tag from {base_image} to a newer supported tag and rebuild the image."
			)

		if finding.fixed_version:
			recommendations.append(
				f"Upgrade {package_name} in the image layer from {installed} to {finding.fixed_version}."
			)
		else:
			recommendations.append(
				f"Track upstream patches for {package_name}; temporarily pin to the safest available version and monitor advisories."
			)

		recommendations.append(
			f"Remove unnecessary package {package_name} from the Docker image if it is not required at runtime to reduce attack surface."
		)

		if has_critical_cve:
			recommendations.append(
				"Treat this as a release blocker: rebuild and redeploy the image only after critical CVE remediation is validated."
			)

		return recommendations

	def _merge_recommendations(self, analyses: Sequence[DockerImageAnalysis]) -> List[str]:
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

	def _confidence_from_analyses(self, analyses: Sequence[DockerImageAnalysis]) -> float:
		if not analyses:
			return 0.0

		confidence = 0.72
		if any(item.base_image_status in {"outdated", "current", "pinned_digest"} for item in analyses):
			confidence += 0.08
		if any(item.has_critical_cve for item in analyses):
			confidence += 0.1
		if any(item.in_changed_files for item in analyses):
			confidence += 0.05
		return min(1.0, round(confidence, 2))
