from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath
from typing import Dict, List, Optional, Sequence

from .base_agent import AgentConfig, BaseSecurityAgent
from ..domain import AgentResult, Finding, GitContext, RiskLevel, ScannerType, Severity
from .prompts import get_agent_prompt
from .tools import create_read_only_tools


@dataclass(slots=True)
class MaliciousIntentAnalysis:
	"""Internal triage details for potentially malicious code intent."""

	finding: Finding
	signals: List[str]
	in_changed_files: bool
	in_git_diff: bool
	risk_score: float
	evidence: List[str]
	recommendations: List[str]


class MaliciousIntentAgent(BaseSecurityAgent):
	"""Analyze scanner findings and git diff for signs of malicious intent patterns."""

	def __init__(self, llm_model: str = "gemini-2.5-flash-lite", tools: Optional[List[object]] = None) -> None:
		resolved_tools = tools if tools is not None else [create_read_only_tools()]
		super().__init__(
			AgentConfig(
				agent_name="malicious_intent_agent",
				role="Malicious Intent Threat Analyst",
				goal="Detect suspicious intent indicators from code changes and scanner findings with concrete evidence.",
				backstory=(
					"You specialize in insider-threat and supply-chain abuse signals. You correlate scanner alerts with "
					"git diffs to detect likely backdoors, exfiltration logic, privilege escalation paths, obfuscated payloads, "
					"disabled security controls, and suspicious dependency behavior."
				),
				llm_model=llm_model,
				prompt=get_agent_prompt("malicious_intent_agent"),
				tools=resolved_tools,
			)
		)

	def analyze(self, findings: Sequence[Finding], git_context: Optional[GitContext] = None) -> AgentResult:
		analyses = [self._analyze_finding(finding, git_context) for finding in findings]
		analyses = [analysis for analysis in analyses if analysis.signals]

		if not analyses:
			return AgentResult(
				agent_name=self.agent_name,
				risk_score=0.0,
				risk_level=RiskLevel.NONE,
				findings=[],
				recommendations=[
					"No malicious-intent indicators were identified from the provided findings and git diff context."
				],
				summary="No suspicious intent signals detected.",
				confidence=0.85,
				evidence=["No indicator pattern matched findings metadata, finding text, or diff content."],
			)

		average_risk = sum(item.risk_score for item in analyses) / len(analyses)
		risk_level = self._risk_level_from_score(average_risk)
		recommendations = self._merge_recommendations(analyses)
		evidence = [detail for item in analyses for detail in item.evidence]
		confidence = self._confidence_from_analyses(analyses)

		signal_counts = self._count_signals(analyses)
		summary = (
			f"Detected malicious-intent indicators across {len(analyses)} findings. "
			f"Signal distribution: {signal_counts}. "
			f"Overall suspicious-intent risk is {risk_level.value.lower()}. "
			"This output is analytical only and does not decide pass or fail."
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

	def _analyze_finding(self, finding: Finding, git_context: Optional[GitContext]) -> MaliciousIntentAnalysis:
		signals = self._detect_signals(finding, git_context)
		in_changed_files = self._is_in_changed_files(finding, git_context)
		in_git_diff = self._is_in_git_diff(finding, git_context)
		risk_score = self._score_finding(finding, signals, in_changed_files, in_git_diff)
		evidence = self._build_evidence(finding, signals, git_context, in_changed_files, in_git_diff)
		recommendations = self._build_recommendations(signals)

		finding.metadata["intent_signals"] = signals
		finding.metadata["in_changed_files"] = in_changed_files
		finding.metadata["in_git_diff"] = in_git_diff
		finding.metadata["malicious_intent_risk_score"] = round(risk_score, 2)

		return MaliciousIntentAnalysis(
			finding=finding,
			signals=signals,
			in_changed_files=in_changed_files,
			in_git_diff=in_git_diff,
			risk_score=risk_score,
			evidence=evidence,
			recommendations=recommendations,
		)

	def _detect_signals(self, finding: Finding, git_context: Optional[GitContext]) -> List[str]:
		text = self._finding_text(finding)
		diff = (git_context.diff.lower() if git_context and git_context.diff else "")
		tokens = f"{text} {diff}"

		signals: List[str] = []

		if self._contains_any(
			tokens,
			(
				"backdoor",
				"hidden admin",
				"hardcoded token",
				"reverse shell",
				"webshell",
				"bind shell",
				"unauthorized endpoint",
			),
		):
			signals.append("backdoor")

		if self._contains_any(
			tokens,
			(
				"exfil",
				"exfiltration",
				"curl -x",
				"wget",
				"http post",
				"upload",
				"sendfile",
				"base64 --decode",
				"dns tunneling",
			),
		):
			signals.append("exfiltration")

		if self._contains_any(
			tokens,
			(
				"sudo",
				"setuid",
				"setcap",
				"chmod 777",
				"chown root",
				"run as root",
				"privilege escalation",
			),
		):
			signals.append("privilege_escalation")

		if self._contains_any(
			tokens,
			(
				"eval(",
				"exec(",
				"fromcharcode",
				"obfus",
				"xor",
				"rot13",
				"decode",
				"unpack",
				"powershell -enc",
			),
		):
			signals.append("obfuscated_payload")

		if self._contains_any(
			tokens,
			(
				"nosemgrep",
				"skip security",
				"disable auth",
				"verify=false",
				"strict=false",
				"tls insecure",
				"ignore cert",
				"disable security",
			),
		):
			signals.append("disabling_security_checks")

		if self._contains_any(
			tokens,
			(
				"typosquat",
				"postinstall",
				"preinstall",
				"install script",
				"unknown registry",
				"crypto miner",
				"dependency confusion",
			),
		):
			signals.append("suspicious_dependency")

		# Trivy dependency findings with critical CVEs can indicate suspicious package risk.
		if (
			finding.tool == ScannerType.TRIVY
			and str(finding.metadata.get("category") or "").lower() == "dependency"
			and finding.severity == Severity.CRITICAL
		):
			if "suspicious_dependency" not in signals:
				signals.append("suspicious_dependency")

		return signals

	def _score_finding(self, finding: Finding, signals: Sequence[str], in_changed_files: bool, in_git_diff: bool) -> float:
		score = 10.0

		if finding.severity == Severity.CRITICAL:
			score += 45.0
		elif finding.severity == Severity.HIGH:
			score += 30.0
		elif finding.severity == Severity.MEDIUM:
			score += 18.0
		elif finding.severity == Severity.LOW:
			score += 8.0

		signal_weight: Dict[str, float] = {
			"backdoor": 28.0,
			"exfiltration": 24.0,
			"privilege_escalation": 22.0,
			"obfuscated_payload": 20.0,
			"disabling_security_checks": 18.0,
			"suspicious_dependency": 15.0,
		}
		for signal in signals:
			score += signal_weight.get(signal, 10.0)

		if in_changed_files:
			score += 8.0
		if in_git_diff:
			score += 10.0
		if finding.is_new:
			score += 5.0

		return max(0.0, min(100.0, score))

	def _build_evidence(
		self,
		finding: Finding,
		signals: Sequence[str],
		git_context: Optional[GitContext],
		in_changed_files: bool,
		in_git_diff: bool,
	) -> List[str]:
		evidence = [
			f"Finding {finding.id} generated malicious-intent signals: {', '.join(signals)}.",
			f"Source tool: {finding.tool.value}; file or target: {finding.file_path}.",
		]
		if finding.rule_id:
			evidence.append(f"Scanner rule indicator: {finding.rule_id}.")
		if finding.cve:
			evidence.append(f"Associated CVE indicator: {finding.cve}.")

		if in_changed_files:
			evidence.append("The affected file/target is present in the current changed file list.")
		if in_git_diff:
			evidence.append("Suspicious tokens are present in git diff hunks for this finding context.")

		snippets = self._extract_diff_evidence_snippets(signals, git_context.diff if git_context else "")
		for snippet in snippets:
			evidence.append(f"Diff evidence: {snippet}")

		return evidence

	def _build_recommendations(self, signals: Sequence[str]) -> List[str]:
		recommendations: List[str] = [
			"Perform manual security review of the commit with two-person approval before merge.",
			"Capture forensic context (author, commit hash, changed files) and preserve logs for investigation.",
		]

		if "backdoor" in signals:
			recommendations.append("Remove unauthorized access paths or hidden endpoints and rotate any exposed credentials.")
		if "exfiltration" in signals:
			recommendations.append("Block outbound exfiltration channels and verify egress controls for the affected service.")
		if "privilege_escalation" in signals:
			recommendations.append("Drop elevated privileges, remove dangerous capabilities, and enforce least privilege execution.")
		if "obfuscated_payload" in signals:
			recommendations.append("Deobfuscate and review payload logic; ban dynamic execution primitives unless explicitly justified.")
		if "disabling_security_checks" in signals:
			recommendations.append("Re-enable all disabled security checks and prohibit suppression without approved justification.")
		if "suspicious_dependency" in signals:
			recommendations.append("Audit dependency provenance, lock trusted registries, and remove suspicious or unmaintained packages.")

		return recommendations

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

	def _is_in_git_diff(self, finding: Finding, git_context: Optional[GitContext]) -> bool:
		if git_context is None or not git_context.diff:
			return False

		diff_text = git_context.diff.lower()
		file_tokens = [finding.file_path.lower(), str(finding.metadata.get("target") or "").lower()]
		if not any(token and token in diff_text for token in file_tokens):
			return False

		signal_tokens = self._signal_tokens()
		return any(token in diff_text for token in signal_tokens)

	def _extract_diff_evidence_snippets(self, signals: Sequence[str], diff_text: str) -> List[str]:
		if not diff_text:
			return []

		lower_lines = [line.strip() for line in diff_text.splitlines() if line.strip().startswith(("+", "-"))]
		token_map = {
			"backdoor": ["backdoor", "reverse shell", "webshell", "hidden admin"],
			"exfiltration": ["exfil", "upload", "wget", "curl", "sendfile"],
			"privilege_escalation": ["sudo", "setuid", "setcap", "chmod 777", "run as root"],
			"obfuscated_payload": ["eval(", "exec(", "fromcharcode", "powershell -enc", "obfus"],
			"disabling_security_checks": ["nosemgrep", "disable", "verify=false", "strict=false"],
			"suspicious_dependency": ["postinstall", "preinstall", "typosquat", "unknown registry"],
		}

		snippets: List[str] = []
		for signal in signals:
			for needle in token_map.get(signal, []):
				for line in lower_lines:
					if needle in line.lower():
						snippets.append(line[:180])
						break

		# De-duplicate while preserving order.
		ordered: List[str] = []
		seen = set()
		for snippet in snippets:
			if snippet in seen:
				continue
			seen.add(snippet)
			ordered.append(snippet)
		return ordered[:8]

	def _merge_recommendations(self, analyses: Sequence[MaliciousIntentAnalysis]) -> List[str]:
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

	def _confidence_from_analyses(self, analyses: Sequence[MaliciousIntentAnalysis]) -> float:
		if not analyses:
			return 0.0

		confidence = 0.7
		if any(item.in_changed_files for item in analyses):
			confidence += 0.1
		if any(item.in_git_diff for item in analyses):
			confidence += 0.1
		if all(item.signals for item in analyses):
			confidence += 0.05
		return min(1.0, round(confidence, 2))

	def _count_signals(self, analyses: Sequence[MaliciousIntentAnalysis]) -> str:
		counts: Dict[str, int] = {}
		for analysis in analyses:
			for signal in analysis.signals:
				counts[signal] = counts.get(signal, 0) + 1
		return ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))

	def _finding_text(self, finding: Finding) -> str:
		parts = [
			finding.title,
			finding.description,
			finding.file_path,
			str(finding.rule_id or ""),
			str(finding.package_name or ""),
			str(finding.metadata.get("target") or ""),
			str(finding.metadata.get("message") or ""),
			str(finding.metadata.get("match") or ""),
		]
		return " ".join(parts).lower()

	def _contains_any(self, text: str, needles: Sequence[str]) -> bool:
		return any(needle in text for needle in needles)

	def _signal_tokens(self) -> List[str]:
		return [
			"backdoor",
			"reverse shell",
			"webshell",
			"exfil",
			"upload",
			"setuid",
			"setcap",
			"eval(",
			"exec(",
			"nosemgrep",
			"verify=false",
			"postinstall",
			"preinstall",
		]
