from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..domain import AgentResult, Finding, RiskLevel, Severity
from .base_agent import AgentConfig, BaseSecurityAgent
from .prompts import get_agent_prompt
from .tools import create_read_only_tools


@dataclass(slots=True)
class AggregatedAgentResult:
	"""Aggregated cross-agent risk output with extra reporting context."""

	agent_name: str
	risk_score: float
	risk_level: RiskLevel
	findings: List[Finding] = field(default_factory=list)
	recommendations: List[str] = field(default_factory=list)
	summary: str = ""
	confidence: float = 0.0
	evidence: List[str] = field(default_factory=list)
	developer_summary: str = ""
	top_risks: List[str] = field(default_factory=list)
	duplicate_groups: List[Dict[str, Any]] = field(default_factory=list)
	source_agents: List[str] = field(default_factory=list)

	def to_dict(self) -> Dict[str, Any]:
		return {
			"agent_name": self.agent_name,
			"risk_score": self.risk_score,
			"risk_level": self.risk_level.value,
			"findings": [finding.to_dict() for finding in self.findings],
			"recommendations": self.recommendations,
			"summary": self.summary,
			"confidence": self.confidence,
			"evidence": self.evidence,
			"developer_summary": self.developer_summary,
			"top_risks": self.top_risks,
			"duplicate_groups": self.duplicate_groups,
			"source_agents": self.source_agents,
		}

	def to_agent_result(self) -> AgentResult:
		return AgentResult(
			agent_name=self.agent_name,
			risk_score=self.risk_score,
			risk_level=self.risk_level,
			findings=self.findings,
			recommendations=self.recommendations,
			summary=self.summary,
			confidence=self.confidence,
			evidence=self.evidence,
		)


class RiskAggregatorAgent(BaseSecurityAgent):
	"""Aggregate multi-agent outputs into one prioritized risk view."""

	def __init__(self, llm_model: str = "gemini-2.5-flash-lite", tools: Optional[List[object]] = None) -> None:
		resolved_tools = tools if tools is not None else [create_read_only_tools()]
		super().__init__(
			AgentConfig(
				agent_name="risk_aggregator_agent",
				role="Security Risk Aggregator",
				goal="Merge agent outputs, deduplicate findings, summarize top risks, and provide final recommendations.",
				backstory=(
					"You synthesize outputs from specialized security agents into one developer-focused risk view. "
					"You highlight duplicate findings, prioritize the highest impact risks, and provide clear next actions "
					"without directly enforcing policy decisions."
				),
				llm_model=llm_model,
				prompt=get_agent_prompt("risk_aggregator_agent"),
				tools=resolved_tools,
			)
		)

	def analyze(
		self,
		agent_outputs: Sequence[AgentResult],
	) -> AggregatedAgentResult:
		source_agents = [output.agent_name for output in agent_outputs]

		if not agent_outputs:
			return AggregatedAgentResult(
				agent_name=self.agent_name,
				risk_score=0.0,
				risk_level=RiskLevel.NONE,
				findings=[],
				recommendations=["No agent outputs were provided for aggregation."],
				summary="No agent outputs to aggregate.",
				confidence=1.0,
				evidence=["Aggregation input was an empty agent output list."],
				developer_summary="No security findings were provided by upstream agents.",
				top_risks=[],
				duplicate_groups=[],
				source_agents=[],
			)

		all_findings: List[Finding] = []
		for output in agent_outputs:
			all_findings.extend(output.findings)

		grouped_findings = self._group_duplicate_findings(all_findings)
		representative_findings, duplicate_groups = self._build_representative_findings(grouped_findings)
		top_risks = self._summarize_top_risks(grouped_findings)
		developer_summary = self._build_developer_summary(agent_outputs, grouped_findings, representative_findings)
		recommendations = self._build_final_recommendations(agent_outputs, grouped_findings)
		evidence = self._build_aggregation_evidence(agent_outputs, grouped_findings)

		overall_score = self._compute_overall_score(agent_outputs, representative_findings)
		overall_level = self._risk_level_from_score(overall_score)
		confidence = self._compute_confidence(agent_outputs, grouped_findings)

		summary = (
			f"Aggregated {len(agent_outputs)} agent outputs with {len(all_findings)} total findings, "
			f"collapsed to {len(representative_findings)} unique findings. "
			f"Overall aggregated risk is {overall_level.value.lower()}."
		)

		return AggregatedAgentResult(
			agent_name=self.agent_name,
			risk_score=round(overall_score, 2),
			risk_level=overall_level,
			findings=representative_findings,
			recommendations=recommendations,
			summary=summary,
			confidence=confidence,
			evidence=evidence,
			developer_summary=developer_summary,
			top_risks=top_risks,
			duplicate_groups=duplicate_groups,
			source_agents=source_agents,
		)

	def _group_duplicate_findings(self, findings: Sequence[Finding]) -> Dict[str, List[Finding]]:
		groups: Dict[str, List[Finding]] = {}
		for finding in findings:
			key = self._finding_dedup_key(finding)
			groups.setdefault(key, []).append(finding)
		return groups

	def _finding_dedup_key(self, finding: Finding) -> str:
		parts = [
			finding.file_path.strip().lower(),
			str(finding.rule_id or "").strip().lower(),
			str(finding.cve or "").strip().lower(),
			str(finding.package_name or "").strip().lower(),
			finding.title.strip().lower(),
		]
		return "|".join(parts)

	def _build_representative_findings(
		self,
		grouped_findings: Dict[str, List[Finding]],
	) -> Tuple[List[Finding], List[Dict[str, Any]]]:
		representatives: List[Finding] = []
		duplicate_groups: List[Dict[str, Any]] = []

		for key, group in grouped_findings.items():
			representative = sorted(group, key=lambda item: self._severity_rank(item.severity), reverse=True)[0]
			representative.metadata["duplicate_count"] = len(group)
			representative.metadata["duplicate_ids"] = [item.id for item in group]
			representatives.append(representative)

			if len(group) > 1:
				duplicate_groups.append(
					{
						"dedup_key": key,
						"count": len(group),
						"finding_ids": [item.id for item in group],
						"rule_id": representative.rule_id,
						"cve": representative.cve,
						"file_path": representative.file_path,
					}
				)

		representatives.sort(key=lambda item: self._severity_rank(item.severity), reverse=True)
		return representatives, duplicate_groups

	def _summarize_top_risks(self, grouped_findings: Dict[str, List[Finding]], limit: int = 5) -> List[str]:
		scored: List[Tuple[float, str]] = []
		for group in grouped_findings.values():
			representative = sorted(group, key=lambda item: self._severity_rank(item.severity), reverse=True)[0]
			severity_score = float(self._severity_rank(representative.severity))
			dup_bonus = float(len(group)) * 0.5
			risk_score = severity_score + dup_bonus
			label = (
				f"{representative.severity.value}: {representative.title} "
				f"(file={representative.file_path}, occurrences={len(group)})"
			)
			scored.append((risk_score, label))

		scored.sort(key=lambda item: item[0], reverse=True)
		return [item[1] for item in scored[:limit]]

	def _build_developer_summary(
		self,
		agent_outputs: Sequence[AgentResult],
		grouped_findings: Dict[str, List[Finding]],
		representative_findings: Sequence[Finding],
	) -> str:
		severity_counts = self._severity_counts(representative_findings)
		duplicates = sum(max(0, len(group) - 1) for group in grouped_findings.values())
		avg_score = sum(item.risk_score for item in agent_outputs) / len(agent_outputs)
		agents = ", ".join(sorted({item.agent_name for item in agent_outputs}))

		return (
			f"Agent inputs: {agents}. "
			f"Unique findings: {len(representative_findings)}; duplicate collapses: {duplicates}. "
			f"Severity mix: CRITICAL={severity_counts['CRITICAL']}, HIGH={severity_counts['HIGH']}, "
			f"MEDIUM={severity_counts['MEDIUM']}, LOW={severity_counts['LOW']}, OTHER={severity_counts['OTHER']}. "
			f"Average upstream agent score: {avg_score:.2f}."
		)

	def _build_final_recommendations(
		self,
		agent_outputs: Sequence[AgentResult],
		grouped_findings: Dict[str, List[Finding]],
	) -> List[str]:
		ordered: List[str] = []
		seen = set()

		for output in agent_outputs:
			for recommendation in output.recommendations:
				if recommendation in seen:
					continue
				seen.add(recommendation)
				ordered.append(recommendation)

		if any(len(group) > 1 for group in grouped_findings.values()):
			msg = "Consolidate duplicate findings into single remediation tickets to avoid fragmented fixes."
			if msg not in seen:
				ordered.append(msg)
		if any(
			item.severity in {Severity.CRITICAL, Severity.HIGH}
			for group in grouped_findings.values()
			for item in group
		):
			msg = "Prioritize critical and high findings first, then sequence medium and low remediation work."
			if msg not in seen:
				ordered.append(msg)

		return ordered[:20]

	def _build_aggregation_evidence(
		self,
		agent_outputs: Sequence[AgentResult],
		grouped_findings: Dict[str, List[Finding]],
	) -> List[str]:
		evidence = [
			f"Aggregated agent count: {len(agent_outputs)}.",
			f"Raw finding count: {sum(len(output.findings) for output in agent_outputs)}.",
			f"Unique finding groups after deduplication: {len(grouped_findings)}.",
		]
		for output in agent_outputs:
			evidence.append(
				f"Agent {output.agent_name} contributed {len(output.findings)} findings with score {output.risk_score:.2f} "
				f"and level {output.risk_level.value}."
			)
		return evidence

	def _compute_overall_score(self, agent_outputs: Sequence[AgentResult], findings: Sequence[Finding]) -> float:
		if not agent_outputs:
			return 0.0

		agent_component = sum(item.risk_score for item in agent_outputs) / len(agent_outputs)
		if not findings:
			return max(0.0, min(100.0, agent_component))

		severity_component = sum(self._severity_to_score(item.severity) for item in findings) / len(findings)
		total = (agent_component * 0.6) + (severity_component * 0.4)
		return max(0.0, min(100.0, total))

	def _compute_confidence(self, agent_outputs: Sequence[AgentResult], grouped_findings: Dict[str, List[Finding]]) -> float:
		if not agent_outputs:
			return 0.0

		confidence = 0.65
		if len(agent_outputs) >= 3:
			confidence += 0.1
		if grouped_findings:
			confidence += 0.1
		if any(len(group) > 1 for group in grouped_findings.values()):
			confidence += 0.05
		if any(item.confidence >= 0.8 for item in agent_outputs):
			confidence += 0.05
		return min(1.0, round(confidence, 2))

	def _severity_counts(self, findings: Sequence[Finding]) -> Dict[str, int]:
		counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
		for finding in findings:
			if finding.severity == Severity.CRITICAL:
				counts["CRITICAL"] += 1
			elif finding.severity == Severity.HIGH:
				counts["HIGH"] += 1
			elif finding.severity == Severity.MEDIUM:
				counts["MEDIUM"] += 1
			elif finding.severity == Severity.LOW:
				counts["LOW"] += 1
			else:
				counts["OTHER"] += 1
		return counts

	def _severity_to_score(self, severity: Severity) -> float:
		mapping = {
			Severity.CRITICAL: 95.0,
			Severity.HIGH: 75.0,
			Severity.MEDIUM: 50.0,
			Severity.LOW: 25.0,
			Severity.INFO: 10.0,
			Severity.UNKNOWN: 20.0,
		}
		return mapping.get(severity, 20.0)

	def _severity_rank(self, severity: Severity) -> int:
		ranking = {
			Severity.CRITICAL: 6,
			Severity.HIGH: 5,
			Severity.MEDIUM: 4,
			Severity.LOW: 3,
			Severity.INFO: 2,
			Severity.UNKNOWN: 1,
		}
		return ranking.get(severity, 1)

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
