from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from .enums import ScannerType
from .finding import Finding


@dataclass(slots=True)
class ScanReport:
	"""Shared per-tool scan report model for parsers, services, and dashboard views."""

	tool: ScannerType
	findings: List[Finding] = field(default_factory=list)
	scan_time: datetime = field(default_factory=datetime.utcnow)
	metadata: Dict[str, Any] = field(default_factory=dict)
	total_findings: int = field(init=False)

	def __post_init__(self) -> None:
		self.total_findings = len(self.findings)

	def add_finding(self, finding: Finding) -> None:
		self.findings.append(finding)
		self.total_findings = len(self.findings)

	def to_dict(self) -> Dict[str, Any]:
		return {
			"tool": self.tool.value,
			"findings": [finding.to_dict() for finding in self.findings],
			"total_findings": self.total_findings,
			"scan_time": self.scan_time.isoformat(),
			"metadata": self.metadata,
		}

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "ScanReport":
		scan_time_raw = data.get("scan_time")
		scan_time = datetime.fromisoformat(str(scan_time_raw)) if scan_time_raw else datetime.utcnow()
		return cls(
			tool=cls._coerce_tool(data.get("tool")),
			findings=[Finding.from_dict(item) for item in data.get("findings", [])],
			scan_time=scan_time,
			metadata=dict(data.get("metadata") or {}),
		)

	@staticmethod
	def _coerce_tool(value: Any) -> ScannerType:
		if isinstance(value, ScannerType):
			return value
		if value is None:
			raise ValueError("ScanReport.tool is required")
		return ScannerType(str(value).lower())
