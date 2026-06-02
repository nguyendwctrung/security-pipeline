from __future__ import annotations

import re
from typing import Sequence

from ...domain import AgentResult, Finding, GitContext, ScanSummary, Severity
from .base_rule import BaseRule, RuleResult


class MaliciousIntentRule(BaseRule):
	"""Policy rule driven by malicious_intent_agent confidence and evidence quality."""

	HIGH_CONFIDENCE_THRESHOLD = 0.75
	MEDIUM_CONFIDENCE_THRESHOLD = 0.5
	HIGH_RISK_SCORE_THRESHOLD = 70.0
	RISKY_SIGNAL_PATTERNS = {
		"backdoor",
		"exfiltration",
		"privilege_escalation",
		"obfuscated_payload",
		"disabling_security_checks",
		"suspicious_dependency",
	}

	def evaluate(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		agent_outputs: Sequence[AgentResult],
		git_context: GitContext,
	) -> RuleResult:
		_ = (summary, findings, git_context)

		result = self._find_malicious_intent_output(agent_outputs)
		if result is None:
			return self.pass_result(
				reason="No malicious_intent_agent output found.",
				severity=Severity.INFO,
				metadata={
					"rule": "malicious_intent_rule",
					"agent_present": False,
				},
			)

		confidence = float(result.confidence)
		has_evidence = len(result.evidence) > 0
		has_specific_evidence = self._has_specific_evidence(result.evidence)
		has_file_line_evidence = self._has_file_line_evidence(result.evidence)
		has_scanner_findings = len(result.findings) > 0
		has_risky_pattern = self._has_risky_pattern(result)
		is_malicious = self._is_malicious(result, has_risky_pattern)
		is_parse_error = self._looks_like_parse_error(result)

		metadata = {
			"rule": "malicious_intent_rule",
			"agent_name": result.agent_name,
			"confidence": confidence,
			"risk_score": result.risk_score,
			"is_malicious": is_malicious,
			"has_scanner_findings": has_scanner_findings,
			"has_evidence": has_evidence,
			"evidence_count": len(result.evidence),
			"specific_evidence_count": self._specific_evidence_count(result.evidence),
			"has_file_line_evidence": has_file_line_evidence,
			"has_risky_pattern": has_risky_pattern,
			"recommendations": result.recommendations,
		}

		if is_parse_error:
			return self.warn_result(
				reason="Malicious intent agent output parse error; using non-blocking fallback.",
				severity=Severity.MEDIUM,
				metadata=metadata,
			)

		if confidence >= self.HIGH_CONFIDENCE_THRESHOLD and not has_scanner_findings:
			return self.warn_result(
				reason="Malicious intent confidence is high but there are no scanner findings to support a blocking decision.",
				severity=Severity.HIGH,
				metadata=metadata,
			)

		if result.risk_score >= self.HIGH_RISK_SCORE_THRESHOLD and not has_file_line_evidence:
			return self.warn_result(
				reason="Malicious intent risk score is high but evidence quality is low (missing specific file/line context).",
				severity=Severity.MEDIUM,
				metadata=metadata,
			)

		# FAIL only when all strict conditions are satisfied.
		if (
			is_malicious
			and confidence >= self.HIGH_CONFIDENCE_THRESHOLD
			and has_evidence
			and has_file_line_evidence
			and has_risky_pattern
		):
			return self.fail_result(
				reason=(
					"Malicious intent is confirmed with high confidence, matched risky pattern, and concrete file/line evidence."
				),
				severity=Severity.CRITICAL,
				metadata=metadata,
			)

		if confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD:
			return self.warn_result(
				reason=(
					"Malicious intent confidence is medium/high, but strict blocking conditions are not fully satisfied."
				),
				severity=Severity.HIGH if has_specific_evidence else Severity.MEDIUM,
				metadata=metadata,
			)

		return self.pass_result(
			reason="Malicious intent confidence is low.",
			severity=Severity.INFO,
			metadata={
				"rule": "malicious_intent_rule",
				"agent_name": result.agent_name,
				"confidence": confidence,
				"risk_score": result.risk_score,
			},
		)

	def _find_malicious_intent_output(self, agent_outputs: Sequence[AgentResult]) -> AgentResult | None:
		for output in agent_outputs:
			if output.agent_name == "malicious_intent_agent":
				return output
		return None

	def _is_malicious(self, result: AgentResult, has_risky_pattern: bool) -> bool:
		for finding in result.findings:
			flag = finding.metadata.get("is_malicious")
			if isinstance(flag, bool):
				return flag

		# Safe inference fallback: require risky pattern + high risk score + at least one scanner finding.
		return has_risky_pattern and result.risk_score >= self.HIGH_RISK_SCORE_THRESHOLD and len(result.findings) > 0

	def _has_risky_pattern(self, result: AgentResult) -> bool:
		for finding in result.findings:
			raw_signals = finding.metadata.get("intent_signals")
			if isinstance(raw_signals, list):
				normalized = {str(item).strip().lower() for item in raw_signals}
				if normalized.intersection(self.RISKY_SIGNAL_PATTERNS):
					return True

		text = " ".join(result.evidence).lower()
		return any(pattern.replace("_", " ") in text or pattern in text for pattern in self.RISKY_SIGNAL_PATTERNS)

	def _has_file_line_evidence(self, evidence_items: Sequence[str]) -> bool:
		for item in evidence_items:
			text = str(item).strip()
			if not text:
				continue
			lower = text.lower()

			has_file_hint = any(token in lower for token in ("file", "path", ".js", ".py", ".ts", ".java", ".go", ".rs"))
			has_line_hint = bool(re.search(r"\bline\s*\d+\b", lower)) or bool(re.search(r":\d+\b", text))
			if has_file_hint and has_line_hint:
				return True
		return False

	def _looks_like_parse_error(self, result: AgentResult) -> bool:
		combined = " ".join([result.summary, *result.evidence, *result.recommendations]).lower()
		return any(
			token in combined
			for token in (
				"parse error",
				"failed to parse",
				"json decode",
				"fallback",
				"malformed",
			)
		)

	def _has_specific_evidence(self, evidence_items: Sequence[str]) -> bool:
		return self._specific_evidence_count(evidence_items) > 0

	def _specific_evidence_count(self, evidence_items: Sequence[str]) -> int:
		keywords = (
			"finding ",
			"cve-",
			"rule",
			"file",
			"path",
			"diff evidence",
			"in_changed_files",
			"in_git_diff",
			"signal",
		)

		count = 0
		for item in evidence_items:
			text = str(item).strip().lower()
			if not text:
				continue
			if any(token in text for token in keywords) and len(text) >= 20:
				count += 1
		return count
