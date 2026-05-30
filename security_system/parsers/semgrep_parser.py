from __future__ import annotations

from typing import Any, Dict, List

from ..domain import ScanReport, ScannerType
from .base_parser import BaseParser


class SemgrepParser(BaseParser):
    tool_name = "semgrep"
    scanner_type = ScannerType.SEMGREP

    def parse(self, raw_data: Any) -> ScanReport:
        findings = []

        if not isinstance(raw_data, dict):
            return self.build_report([], {"raw_type": type(raw_data).__name__})

        results = raw_data.get("results", [])
        if not isinstance(results, list):
            return self.build_report([], {"raw_type": type(raw_data).__name__, "results_type": type(results).__name__})

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
                "category": str(metadata_block.get("category", "code")) if isinstance(metadata_block, dict) else "code",
                "line_end": end.get("line") if isinstance(end, dict) and isinstance(end.get("line"), int) else None,
                "confidence": confidence,
                "remediation": remediation,
                "references": references,
                "engine_kind": item.get("engine_kind"),
                "lines": item.get("lines"),
                "validation_state": item.get("validation_state"),
                "metadata": metadata_block,
            }

            finding = self.build_finding(
                rule_id=rule_id,
                title=title,
                description=description,
                severity=severity,
                file_path=file_path,
                line=line_start,
                metadata=metadata,
            )
            findings.append(finding)

        return self.build_report(
            findings,
            {
                "raw_results": len(results),
                "errors": raw_data.get("errors", []) if isinstance(raw_data.get("errors"), list) else [],
            },
        )