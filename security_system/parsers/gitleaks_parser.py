from __future__ import annotations

from typing import Any, List

from ..domain import ScanReport, ScannerType, Severity
from .base_parser import BaseParser


class GitleaksParser(BaseParser):
    tool_name = "gitleaks"
    scanner_type = ScannerType.GITLEAKS

    def parse(self, raw_data: Any) -> ScanReport:
        findings = []

        if not isinstance(raw_data, list):
            return self.build_report([], {"raw_type": type(raw_data).__name__})

        for item in raw_data:
            if not isinstance(item, dict):
                continue

            rule_id = str(item.get("RuleID") or "GITLEAKS_GENERIC")
            file_path = str(item.get("File") or "")
            line_start = item.get("StartLine") if isinstance(item.get("StartLine"), int) else None
            title = f"Secret leak: {rule_id}"
            description = str(item.get("Description") or "Potential secret detected")

            references = []
            commit = item.get("Commit")
            if commit:
                references.append(f"commit:{commit}")

            metadata = {
                "category": "secret",
                "line_end": item.get("EndLine") if isinstance(item.get("EndLine"), int) else None,
                "confidence": "HIGH",
                "remediation": "Remove the secret, rotate credentials, and move secrets to a secret manager.",
                "references": references,
                "match": item.get("Match"),
                "secret_length": len(str(item.get("Secret", ""))) if item.get("Secret") else 0,
                "entropy": item.get("Entropy"),
                "author": item.get("Author"),
                "email": item.get("Email"),
                "date": item.get("Date"),
            }

            finding = self.build_finding(
                rule_id=rule_id,
                title=title,
                description=description,
                severity=Severity.CRITICAL,
                file_path=file_path,
                line=line_start,
                metadata=metadata,
            )
            findings.append(finding)

        return self.build_report(findings, {"raw_entries": len(raw_data)})