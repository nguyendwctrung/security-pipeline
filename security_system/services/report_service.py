from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from ..domain import Decision, Finding, ScanReport, ScanSummary, ScannerType
from ..parsers import GitleaksParser, SemgrepParser, TrivyParser
from ..repositories import ArtifactRepository, ReportRepository


class ReportService:
	"""Read raw scanner reports, parse them into domain reports, and persist a combined summary."""

	def __init__(
		self,
		report_repository: Optional[ReportRepository] = None,
		artifact_repository: Optional[ArtifactRepository] = None,
		gitleaks_parser: Optional[GitleaksParser] = None,
		semgrep_parser: Optional[SemgrepParser] = None,
		trivy_parser: Optional[TrivyParser] = None,
	) -> None:
		self.report_repository = report_repository or ReportRepository()
		self.artifact_repository = artifact_repository or ArtifactRepository(base_dir=self.report_repository.base_dir)
		self.gitleaks_parser = gitleaks_parser or GitleaksParser()
		self.semgrep_parser = semgrep_parser or SemgrepParser()
		self.trivy_parser = trivy_parser or TrivyParser()

	def build_summary(self, report_paths: Iterable[Path | str], output_dir: Optional[Path | str] = None) -> ScanSummary:
		scan_reports: List[ScanReport] = []
		findings: List[Finding] = []

		for report_path in report_paths:
			path = Path(report_path)
			raw_report = self.report_repository.read_raw_report_json(path)
			scan_report = self._parse_report(path, raw_report)
			scan_reports.append(scan_report)
			findings.extend(scan_report.findings)

		summary = ScanSummary(
			reports=scan_reports,
			findings=findings,
			metadata={
				"report_count": len(scan_reports),
				"tools": [report.tool.value for report in scan_reports],
			},
		)
		self.report_repository.write_summary(summary, output_dir=output_dir)
		return summary

	def _parse_report(self, report_path: Path, raw_report: object) -> ScanReport:
		tool = self._detect_tool(report_path)
		if tool == ScannerType.GITLEAKS:
			return self.gitleaks_parser.parse(raw_report)
		if tool == ScannerType.SEMGREP:
			return self.semgrep_parser.parse(raw_report)
		if tool == ScannerType.TRIVY:
			return self.trivy_parser.parse(raw_report)
		fallback_report = ScanReport(ScannerType.GITLEAKS)
		fallback_report.metadata["unknown_report_path"] = str(report_path)
		return fallback_report

	def _detect_tool(self, report_path: Path) -> ScannerType:
		name = report_path.name.lower()
		if "gitleaks" in name:
			return ScannerType.GITLEAKS
		if "semgrep" in name:
			return ScannerType.SEMGREP
		if "trivy" in name:
			return ScannerType.TRIVY
		raise ValueError(f"Unsupported report file for parser routing: {report_path}")

	def create_pr_comment_from_decision_report(
		self,
		decision_report_path: Optional[Path | str] = None,
		summary_path: Optional[Path | str] = None,
		output_dir: Optional[Path | str] = None,
		create_summary_report: bool = False,
	) -> Path:
		"""Create pr_comment.md from decision_report.json and optional summary.json."""

		decision = self.report_repository.read_decision_report(decision_report_path)
		summary = self._read_optional_summary(summary_path)
		pr_comment = self.format_github_actions_comment(decision=decision, summary=summary)
		pr_comment_path = self.artifact_repository.write_pr_comment(pr_comment, output_dir=output_dir)

		if create_summary_report and summary is not None:
			self.create_summary_report(summary=summary, output_dir=output_dir)

		return pr_comment_path

	def create_summary_report(
		self,
		summary: Optional[ScanSummary] = None,
		summary_path: Optional[Path | str] = None,
		output_dir: Optional[Path | str] = None,
	) -> Path:
		"""Create summary_report.md from summary.json when markdown artifact is needed."""

		resolved_summary = summary or self.report_repository.read_summary(summary_path)
		content = self._format_summary_report_markdown(resolved_summary)

		target_dir = Path(output_dir) if output_dir is not None else self.report_repository.processed_dir
		target_dir.mkdir(parents=True, exist_ok=True)
		target_path = target_dir / "summary_report.md"
		target_path.write_text(content, encoding="utf-8")
		return target_path

	def format_github_actions_comment(self, decision: Decision, summary: Optional[ScanSummary] = None) -> str:
		"""Format decision/summary as markdown suitable for GitHub Actions PR comments."""

		lines = [
			"## Security Check Result",
			"",
			f"- Status: **{decision.status.value}**",
			f"- Final score: {decision.final_score:.2f}",
		]

		if summary is not None:
			lines.extend(
				[
					"",
					"### Scan Summary",
					f"- Reports: {len(summary.reports)}",
					f"- Total findings: {summary.total_findings}",
					f"- Critical: {summary.severity_counts.get('CRITICAL', 0)}",
					f"- High: {summary.severity_counts.get('HIGH', 0)}",
					f"- Medium: {summary.severity_counts.get('MEDIUM', 0)}",
					f"- Low: {summary.severity_counts.get('LOW', 0)}",
				]
			)

		if decision.blocking_reasons:
			lines.append("")
			lines.append("### Blocking Reasons")
			for reason in decision.blocking_reasons:
				lines.append(f"- {reason}")

		if decision.warnings:
			lines.append("")
			lines.append("### Warnings")
			for warning in decision.warnings:
				lines.append(f"- {warning}")

		if decision.recommendations:
			lines.append("")
			lines.append("### Recommendations")
			for recommendation in decision.recommendations:
				lines.append(f"- {recommendation}")

		return "\n".join(lines) + "\n"

	def _read_optional_summary(self, summary_path: Optional[Path | str]) -> Optional[ScanSummary]:
		try:
			return self.report_repository.read_summary(summary_path)
		except FileNotFoundError:
			return None

	def _format_summary_report_markdown(self, summary: ScanSummary) -> str:
		lines = [
			"## Security Scan Summary",
			"",
			f"- Total findings: {summary.total_findings}",
			f"- Reports: {len(summary.reports)}",
			"",
			"### Severity Distribution",
			f"- Critical: {summary.severity_counts.get('CRITICAL', 0)}",
			f"- High: {summary.severity_counts.get('HIGH', 0)}",
			f"- Medium: {summary.severity_counts.get('MEDIUM', 0)}",
			f"- Low: {summary.severity_counts.get('LOW', 0)}",
			f"- Info: {summary.severity_counts.get('INFO', 0)}",
			f"- Unknown: {summary.severity_counts.get('UNKNOWN', 0)}",
		]

		if summary.reports:
			lines.append("")
			lines.append("### Tools")
			for report in summary.reports:
				lines.append(f"- {report.tool.value}: {report.total_findings} findings")

		return "\n".join(lines) + "\n"
