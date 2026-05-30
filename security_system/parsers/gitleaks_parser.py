from __future__ import annotations

from typing import Any, List

from .base_parser import BaseParser, Finding


class GitleaksParser(BaseParser):
    tool_name = "gitleaks"

    def parse(self, raw_data: Any) -> List[Finding]:
        findings: List[Finding] = []

        if not isinstance(raw_data, list):
            return findings

        for item in raw_data:
            if not isinstance(item, dict):
                continue

            rule_id = str(item.get("RuleID") or "GITLEAKS_GENERIC")
            file_path = str(item.get("File") or "")
            line_start = item.get("StartLine") if isinstance(item.get("StartLine"), int) else None
            line_end = item.get("EndLine") if isinstance(item.get("EndLine"), int) else None
            title = f"Secret leak: {rule_id}"
            description = str(item.get("Description") or "Potential secret detected")
            severity = "CRITICAL"
            confidence = "HIGH"

            references = []
            commit = item.get("Commit")
            if commit:
                references.append(f"commit:{commit}")

            metadata = {
                "match": item.get("Match"),
                "secret_length": len(str(item.get("Secret", ""))) if item.get("Secret") else 0,
                "entropy": item.get("Entropy"),
                "author": item.get("Author"),
                "email": item.get("Email"),
                "date": item.get("Date"),
            }

            finding = Finding(
                source_tool=self.tool_name,
                rule_id=rule_id,
                title=title,
                description=description,
                severity=severity,
                category="secret",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                confidence=confidence,
                remediation="Remove the secret, rotate credentials, and move secrets to a secret manager.",
                references=references,
                metadata=metadata,
                fingerprint=self.build_fingerprint(rule_id, file_path, line_start, title),
            )
            findings.append(finding)

        return self.deduplicate(findings)