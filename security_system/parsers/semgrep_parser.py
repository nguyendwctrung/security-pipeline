from __future__ import annotations

from typing import Any, Dict, List

from .base_parser import BaseParser, Finding


class SemgrepParser(BaseParser):
    tool_name = "semgrep"

    def parse(self, raw_data: Any) -> List[Finding]:
        findings: List[Finding] = []

        if not isinstance(raw_data, dict):
            return findings

        results = raw_data.get("results", [])
        if not isinstance(results, list):
            return findings

        for item in results:
            if not isinstance(item, dict):
                continue

            extra = item.get("extra", {})
            start = item.get("start", {})
            end = item.get("end", {})
            metadata_block = extra.get("metadata", {}) if isinstance(extra, dict) else {}

            rule_id = str(item.get("check_id") or "SEMGREP_GENERIC")
            file_path = str(item.get("path") or "")
            line_start = start.get("line") if isinstance(start, dict) and isinstance(start.get("line"), int) else None
            line_end = end.get("line") if isinstance(end, dict) and isinstance(end.get("line"), int) else None
            title = str(extra.get("message") or f"Semgrep rule violation: {rule_id}")
            description = str(extra.get("message") or "Code pattern matched a security rule")
            severity = self.normalize_severity(extra.get("severity"))
            confidence = str(metadata_block.get("confidence")) if metadata_block.get("confidence") else None

            references = []
            for key in ("cwe", "owasp", "technology"):
                if isinstance(metadata_block, dict) and key in metadata_block:
                    references.append(f"{key}:{metadata_block[key]}")

            remediation = None
            if isinstance(extra, dict) and extra.get("fix"):
                remediation = str(extra.get("fix"))

            metadata: Dict[str, object] = {
                "engine_kind": item.get("engine_kind"),
                "lines": item.get("lines"),
                "validation_state": item.get("validation_state"),
                "metadata": metadata_block,
            }

            finding = Finding(
                source_tool=self.tool_name,
                rule_id=rule_id,
                title=title,
                description=description,
                severity=severity,
                category=str(metadata_block.get("category", "code")) if isinstance(metadata_block, dict) else "code",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                confidence=confidence,
                remediation=remediation,
                references=references,
                metadata=metadata,
                fingerprint=self.build_fingerprint(rule_id, file_path, line_start, title),
            )
            findings.append(finding)

        return self.deduplicate(findings)