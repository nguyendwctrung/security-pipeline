from __future__ import annotations

from abc import ABC, abstractmethod
from hashlib import sha256
from typing import Any, Dict, List, Optional

from ..domain import Finding, ScanReport, ScannerType, Severity


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


class BaseParser(ABC):
    tool_name: str = "base"
    scanner_type: ScannerType

    @abstractmethod
    def parse(self, raw_data: Any) -> ScanReport:
        raise NotImplementedError

    def normalize_severity(self, value: Optional[str]) -> Severity:
        if not value:
            return Severity.UNKNOWN

        sev = str(value).strip().upper()
        aliases = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "WARN": Severity.MEDIUM,
            "NOTE": Severity.LOW,
        }
        if sev in aliases:
            return aliases[sev]

        try:
            return Severity(sev)
        except ValueError:
            return Severity.UNKNOWN

    def build_fingerprint(
        self,
        rule_id: str,
        file_path: str,
        line_start: Optional[int],
        title: str,
    ) -> str:
        payload = f"{self.tool_name}|{rule_id}|{file_path}|{line_start}|{title}".encode("utf-8")
        return sha256(payload).hexdigest()[:20]

    def build_finding(
        self,
        *,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        file_path: str,
        line: Optional[int] = None,
        cve: Optional[str] = None,
        package_name: Optional[str] = None,
        fixed_version: Optional[str] = None,
        is_new: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        finding_id = self.build_fingerprint(rule_id, file_path, line, title)
        return Finding(
            id=finding_id,
            tool=self.scanner_type,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line=line,
            rule_id=rule_id,
            cve=cve,
            package_name=package_name,
            fixed_version=fixed_version,
            is_new=is_new,
            metadata=metadata or {},
        )

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for finding in findings:
            if finding.id in seen:
                continue
            seen.add(finding.id)
            unique.append(finding)
        return unique

    def summarize(self, findings: List[Finding]) -> Dict[str, Any]:
        severity_counts = {sev.value: 0 for sev in SEVERITY_ORDER}
        file_counts: Dict[str, int] = {}
        new_findings = 0

        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            file_counts[finding.file_path] = file_counts.get(finding.file_path, 0) + 1
            if finding.is_new:
                new_findings += 1

        top_files = sorted(file_counts.items(), key=lambda item: item[1], reverse=True)[:10]

        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "tool": self.scanner_type.value,
            "new_findings": new_findings,
            "top_files": [{"file": path, "count": count} for path, count in top_files],
        }

    def build_report(self, findings: List[Finding], metadata: Optional[Dict[str, Any]] = None) -> ScanReport:
        unique_findings = self.deduplicate(findings)
        report_metadata = metadata.copy() if metadata else {}
        report_metadata.update(self.summarize(unique_findings))
        return ScanReport(tool=self.scanner_type, findings=unique_findings, metadata=report_metadata)