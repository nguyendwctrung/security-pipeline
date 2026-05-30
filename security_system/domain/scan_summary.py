from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from .enums import Severity
from .finding import Finding
from .scan_report import ScanReport


@dataclass(slots=True)
class ScanSummary:
	"""Aggregate summary across all scanner reports for reporting and dashboard use."""

	reports: List[ScanReport] = field(default_factory=list)
	findings: List[Finding] = field(default_factory=list)
	created_at: datetime = field(default_factory=datetime.utcnow)
	metadata: Dict[str, Any] = field(default_factory=dict)
	total_findings: int = field(init=False)
	severity_counts: Dict[str, int] = field(init=False)

	def __post_init__(self) -> None:
		if not self.findings:
			self.findings = [finding for report in self.reports for finding in report.findings]
		self.total_findings = len(self.findings)
		self.severity_counts = {severity.value: 0 for severity in Severity}
		for finding in self.findings:
			self.severity_counts[finding.severity.value] = self.severity_counts.get(finding.severity.value, 0) + 1

	def to_dict(self) -> Dict[str, Any]:
		return {
			"reports": [report.to_dict() for report in self.reports],
			"findings": [finding.to_dict() for finding in self.findings],
			"created_at": self.created_at.isoformat(),
			"metadata": self.metadata,
			"total_findings": self.total_findings,
			"severity_counts": self.severity_counts,
		}

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "ScanSummary":
		created_at_raw = data.get("created_at")
		created_at = datetime.fromisoformat(str(created_at_raw)) if created_at_raw else datetime.utcnow()
		reports_raw_value = data.get("reports")
		reports_raw = reports_raw_value if isinstance(reports_raw_value, list) else []
		findings_raw_value = data.get("findings")
		findings_raw = findings_raw_value if isinstance(findings_raw_value, list) else []
		return cls(
			reports=[ScanReport.from_dict(item) for item in reports_raw if isinstance(item, dict)],
			findings=[Finding.from_dict(item) for item in findings_raw if isinstance(item, dict)],
			created_at=created_at,
			metadata=dict(data.get("metadata") or {}),
		)