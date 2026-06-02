from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from .enums import ScannerType, Severity


@dataclass(slots=True)
class Finding:
	"""Canonical finding model shared by parsers, agents, policies, and dashboard views."""

	id: str
	tool: ScannerType
	severity: Severity
	title: str
	description: str
	file_path: str
	line: Optional[int] = None
	rule_id: Optional[str] = None
	cve: Optional[str] = None
	package_name: Optional[str] = None
	fixed_version: Optional[str] = None
	is_new: bool = True
	metadata: Dict[str, Any] = field(default_factory=dict)

	def to_dict(self) -> Dict[str, Any]:
		payload = asdict(self)
		payload["tool"] = self.tool.value
		payload["severity"] = self.severity.value
		return payload

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "Finding":
		return cls(
			id=str(data["id"]),
			tool=cls._coerce_tool(data.get("tool")),
			severity=cls._coerce_severity(data.get("severity")),
			title=str(data.get("title") or ""),
			description=str(data.get("description") or ""),
			file_path=str(data.get("file_path") or ""),
			line=data.get("line") if isinstance(data.get("line"), int) else None,
			rule_id=str(data["rule_id"]) if data.get("rule_id") is not None else None,
			cve=str(data["cve"]) if data.get("cve") is not None else None,
			package_name=str(data["package_name"]) if data.get("package_name") is not None else None,
			fixed_version=str(data["fixed_version"]) if data.get("fixed_version") is not None else None,
			is_new=bool(data.get("is_new", True)),
			metadata=dict(data.get("metadata") or {}),
		)

	@staticmethod
	def _coerce_tool(value: Any) -> ScannerType:
		if isinstance(value, ScannerType):
			return value
		if value is None:
			raise ValueError("Finding.tool is required")
		return ScannerType(str(value).lower())

	@staticmethod
	def _coerce_severity(value: Any) -> Severity:
		if isinstance(value, Severity):
			return value
		if value is None:
			return Severity.UNKNOWN
		return Severity(str(value).upper())
