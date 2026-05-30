from __future__ import annotations

from typing import Any, Dict, List

from ..domain import ScanReport, ScannerType
from .base_parser import BaseParser


class TrivyParser(BaseParser):
    tool_name = "trivy"
    scanner_type = ScannerType.TRIVY

    def parse(self, raw_data: Any) -> ScanReport:
        findings = []
        metadata: Dict[str, Any] = {"scan_modes": []}

        if not isinstance(raw_data, dict):
            return self.build_report([], {"raw_type": type(raw_data).__name__})

        if "filesystem" in raw_data or "image" in raw_data:
            filesystem_data = raw_data.get("filesystem")
            image_data = raw_data.get("image")

            if isinstance(filesystem_data, dict):
                findings.extend(self._parse_results(filesystem_data, "filesystem"))
                metadata["scan_modes"].append("filesystem")

            if isinstance(image_data, dict):
                if image_data.get("skipped"):
                    metadata["image_scan"] = image_data
                else:
                    findings.extend(self._parse_results(image_data, "image"))
                    metadata["scan_modes"].append("image")

            return self.build_report(findings, metadata)

        findings.extend(self._parse_results(raw_data, "filesystem"))
        metadata["scan_modes"].append("filesystem")
        return self.build_report(findings, metadata)

    def _parse_results(self, raw_data: Dict[str, Any], scan_type: str) -> List:
        findings = []

        results = raw_data.get("Results", [])
        if not isinstance(results, list):
            return findings

        for result in results:
            if not isinstance(result, dict):
                continue

            target = str(result.get("Target") or "")

            vulnerabilities = result.get("Vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                for vul in vulnerabilities:
                    if not isinstance(vul, dict):
                        continue

                    rule_id = str(vul.get("VulnerabilityID") or "TRIVY_VULN")
                    pkg_name = str(vul.get("PkgName") or "")
                    installed_version = str(vul.get("InstalledVersion") or "")
                    fixed_version = str(vul.get("FixedVersion") or "")
                    title = str(vul.get("Title") or f"Dependency vulnerability: {rule_id}")
                    description = str(vul.get("Description") or "Dependency vulnerability detected")
                    severity = self.normalize_severity(vul.get("Severity"))
                    cve = rule_id if rule_id.startswith("CVE-") else None

                    remediation = "Apply the vendor patch or upgrade the dependency."
                    if pkg_name and fixed_version:
                        remediation = f"Upgrade {pkg_name} from {installed_version} to {fixed_version}."

                    metadata: Dict[str, object] = {
                        "category": "dependency",
                        "scan_type": scan_type,
                        "confidence": "HIGH",
                        "remediation": remediation,
                        "references": vul.get("References", []) if isinstance(vul.get("References", []), list) else [],
                        "target": target,
                        "pkg_name": pkg_name,
                        "installed_version": installed_version,
                        "fixed_version": fixed_version,
                        "primary_url": vul.get("PrimaryURL"),
                        "cvss": vul.get("CVSS"),
                    }

                    finding = self.build_finding(
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        file_path=target,
                        cve=cve,
                        package_name=pkg_name or None,
                        fixed_version=fixed_version or None,
                        metadata=metadata,
                    )
                    findings.append(finding)

            misconfigurations = result.get("Misconfigurations", [])
            if isinstance(misconfigurations, list):
                for mis in misconfigurations:
                    if not isinstance(mis, dict):
                        continue

                    rule_id = str(mis.get("ID") or "TRIVY_MISCONFIG")
                    title = str(mis.get("Title") or f"Misconfiguration: {rule_id}")
                    description = str(mis.get("Description") or "Infrastructure misconfiguration detected")
                    severity = self.normalize_severity(mis.get("Severity"))

                    metadata = {
                        "category": "misconfiguration",
                        "scan_type": scan_type,
                        "confidence": "MEDIUM",
                        "remediation": str(mis.get("Resolution") or "Apply the recommended secure configuration."),
                        "references": mis.get("References", []) if isinstance(mis.get("References", []), list) else [],
                        "target": target,
                        "type": result.get("Type"),
                        "namespace": result.get("Namespace"),
                        "message": mis.get("Message"),
                    }

                    finding = self.build_finding(
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        file_path=target,
                        metadata=metadata,
                    )
                    findings.append(finding)

            secrets = result.get("Secrets", [])
            if isinstance(secrets, list):
                for sec in secrets:
                    if not isinstance(sec, dict):
                        continue

                    rule_id = str(sec.get("RuleID") or "TRIVY_SECRET")
                    file_path = target
                    line_start = sec.get("StartLine") if isinstance(sec.get("StartLine"), int) else None
                    line_end = sec.get("EndLine") if isinstance(sec.get("EndLine"), int) else None
                    title = str(sec.get("Title") or f"Secret exposure: {rule_id}")
                    description = str(sec.get("Description") or "Potential secret found by Trivy")
                    severity = self.normalize_severity(sec.get("Severity") or "CRITICAL")

                    finding = self.build_finding(
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        file_path=file_path,
                        line=line_start,
                        metadata={
                            "category": "secret",
                            "scan_type": scan_type,
                            "line_end": line_end,
                            "confidence": "HIGH",
                            "remediation": "Remove the secret from code/history and rotate it immediately.",
                            "references": [],
                            "target": target,
                            "match": sec.get("Match"),
                        },
                    )
                    findings.append(finding)

        return findings