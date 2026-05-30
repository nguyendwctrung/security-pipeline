from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from .enums import DecisionStatus


@dataclass(slots=True)
class Decision:
	"""Final policy decision shared by policy engine, CI reporting, and dashboard views."""

	status: DecisionStatus
	blocking_reasons: List[str] = field(default_factory=list)
	warnings: List[str] = field(default_factory=list)
	recommendations: List[str] = field(default_factory=list)
	final_score: float = 0.0
	timestamp: datetime = field(default_factory=datetime.utcnow)

	def to_dict(self) -> Dict[str, Any]:
		return {
			"status": self.status.value,
			"blocking_reasons": self.blocking_reasons,
			"warnings": self.warnings,
			"recommendations": self.recommendations,
			"final_score": self.final_score,
			"timestamp": self.timestamp.isoformat(),
		}

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "Decision":
		timestamp_raw = data.get("timestamp")
		timestamp = datetime.fromisoformat(str(timestamp_raw)) if timestamp_raw else datetime.utcnow()
		blocking_reasons_raw = data.get("blocking_reasons")
		warnings_raw = data.get("warnings")
		recommendations_raw = data.get("recommendations")
		blocking_reasons = blocking_reasons_raw if isinstance(blocking_reasons_raw, list) else []
		warnings = warnings_raw if isinstance(warnings_raw, list) else []
		recommendations = recommendations_raw if isinstance(recommendations_raw, list) else []
		return cls(
			status=cls._coerce_status(data.get("status")),
			blocking_reasons=[str(item) for item in blocking_reasons],
			warnings=[str(item) for item in warnings],
			recommendations=[str(item) for item in recommendations],
			final_score=float(data.get("final_score") or 0.0),
			timestamp=timestamp,
		)

	@staticmethod
	def _coerce_status(value: Any) -> DecisionStatus:
		if isinstance(value, DecisionStatus):
			return value
		if value is None:
			return DecisionStatus.WARN
		return DecisionStatus(str(value).upper())
