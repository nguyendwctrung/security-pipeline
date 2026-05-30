from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .enums import RiskLevel
from .finding import Finding


@dataclass(slots=True)
class AgentResult:
	"""Structured output from a CrewAI agent for downstream aggregation and reporting."""

	agent_name: str
	risk_score: float
	risk_level: RiskLevel
	findings: List[Finding] = field(default_factory=list)
	recommendations: List[str] = field(default_factory=list)
	summary: str = ""
	confidence: float = 0.0
	evidence: List[str] = field(default_factory=list)

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
		}

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "AgentResult":
		return cls(
			agent_name=str(data.get("agent_name") or ""),
			risk_score=float(data.get("risk_score") or 0.0),
			risk_level=cls._coerce_risk_level(data.get("risk_level")),
			findings=[Finding.from_dict(item) for item in data.get("findings", []) if isinstance(item, dict)],
			recommendations=[str(item) for item in data.get("recommendations", []) if item is not None],
			summary=str(data.get("summary") or ""),
			confidence=float(data.get("confidence") or 0.0),
			evidence=[str(item) for item in data.get("evidence", []) if item is not None],
		)

	@staticmethod
	def _coerce_risk_level(value: Any) -> RiskLevel:
		if isinstance(value, RiskLevel):
			return value
		if value is None:
			return RiskLevel.NONE
		return RiskLevel(str(value).upper())
