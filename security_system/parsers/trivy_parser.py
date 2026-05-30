from __future__ import annotations

from typing import Any, Dict, List

from .base_parser import BaseParser, Finding


class TrivyParser(BaseParser):
    tool_name = "trivy"

    def parse(self, raw_data: Any) -> List[Finding]:
        findings: List[Finding] = []

        if not isinstance(raw_data, dict):
            return findings

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

                    remediation = "Apply the vendor patch or upgrade the dependency."
                    if pkg_name and fixed_version:
                        remediation = f"Upgrade {pkg_name} from {installed_version} to {fixed_version}."

                    metadata: Dict[str, object] = {
                        "target": target,
                        "pkg_name": pkg_name,
                        "installed_version": installed_version,
                        "fixed_version": fixed_version,
                        "primary_url": vul.get("PrimaryURL"),
                        "cvss": vul.get("CVSS"),
                    }

                    finding = Finding(
                        source_tool=self.tool_name,
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        category="dependency",
                        file_path=target,
                        line_start=None,
                        line_end=None,
                        confidence="HIGH",
                        remediation=remediation,
                        references=vul.get("References", []) if isinstance(vul.get("References", []), list) else [],
                        metadata=metadata,
                        fingerprint=self.build_fingerprint(rule_id, target, None, title),
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
                        "target": target,
                        "type": result.get("Type"),
                        "namespace": result.get("Namespace"),
                        "message": mis.get("Message"),
                    }

                    finding = Finding(
                        source_tool=self.tool_name,
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        category="misconfiguration",
                        file_path=target,
                        line_start=None,
                        line_end=None,
                        confidence="MEDIUM",
                        remediation=str(mis.get("Resolution") or "Apply the recommended secure configuration."),
                        references=mis.get("References", []) if isinstance(mis.get("References", []), list) else [],
                        metadata=metadata,
                        fingerprint=self.build_fingerprint(rule_id, target, None, title),
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
                        confidence="HIGH",
                        remediation="Remove the secret from code/history and rotate it immediately.",
                        references=[],
                        metadata={"target": target, "match": sec.get("Match")},
                        fingerprint=self.build_fingerprint(rule_id, file_path, line_start, title),
                    )
                    findings.append(finding)

        return self.deduplicate(findings)