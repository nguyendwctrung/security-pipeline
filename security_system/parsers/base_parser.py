from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from hashlib import sha256
from typing import Any, Dict, List, Optional


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


@dataclass
class Finding:
    source_tool: str
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    confidence: Optional[str]
    remediation: Optional[str]
    references: List[str]
    metadata: Dict[str, Any]
    fingerprint: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseParser(ABC):
    tool_name: str = "base"

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Finding]:
        raise NotImplementedError

    def normalize_severity(self, value: Optional[str]) -> str:
        if not value:
            return "UNKNOWN"

        sev = str(value).strip().upper()
        aliases = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "WARN": "MEDIUM",
            "NOTE": "LOW",
        }
        sev = aliases.get(sev, sev)
        return sev if sev in SEVERITY_ORDER else "UNKNOWN"

    def build_fingerprint(
        self,
        rule_id: str,
        file_path: str,
        line_start: Optional[int],
        title: str,
    ) -> str:
        payload = f"{self.tool_name}|{rule_id}|{file_path}|{line_start}|{title}".encode("utf-8")
        return sha256(payload).hexdigest()[:20]

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for finding in findings:
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            unique.append(finding)
        return unique

    def summarize(self, findings: List[Finding]) -> Dict[str, Any]:
        severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
        tool_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}

        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            tool_counts[finding.source_tool] = tool_counts.get(finding.source_tool, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            file_counts[finding.file_path] = file_counts.get(finding.file_path, 0) + 1

        top_files = sorted(file_counts.items(), key=lambda item: item[1], reverse=True)[:10]

        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "tool_counts": tool_counts,
            "category_counts": category_counts,
            "top_files": [{"file": path, "count": count} for path, count in top_files],
        }