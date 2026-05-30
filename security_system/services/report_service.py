from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from ..domain import Finding, ScanReport, ScanSummary, ScannerType
from ..parsers import GitleaksParser, SemgrepParser, TrivyParser
from ..repositories import ReportRepository


class ReportService:
	"""Read raw scanner reports, parse them into domain reports, and persist a combined summary."""

	def __init__(
		self,
		report_repository: Optional[ReportRepository] = None,
		gitleaks_parser: Optional[GitleaksParser] = None,
		semgrep_parser: Optional[SemgrepParser] = None,
		trivy_parser: Optional[TrivyParser] = None,
	) -> None:
		self.report_repository = report_repository or ReportRepository()
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
		return ScanReport(tool=ScannerType.GITLEAKS, metadata={"unknown_report_path": str(report_path)})

	def _detect_tool(self, report_path: Path) -> ScannerType:
		name = report_path.name.lower()
		if "gitleaks" in name:
			return ScannerType.GITLEAKS
		if "semgrep" in name:
			return ScannerType.SEMGREP
		if "trivy" in name:
			return ScannerType.TRIVY
		raise ValueError(f"Unsupported report file for parser routing: {report_path}")
