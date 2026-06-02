from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..scanners import GitleaksScanner, ScannerError, SemgrepScanner, TrivyScanner


@dataclass(slots=True)
class ScanServiceResult:
	"""Result of running the scanner stage across all configured tools."""

	report_paths: List[Path] = field(default_factory=list)
	errors: Dict[str, str] = field(default_factory=dict)


class ScanService:
	"""Run all security scanners and collect raw report artifacts."""

	def __init__(
		self,
		reports_dir: Optional[Path | str] = None,
		gitleaks_scanner: Optional[GitleaksScanner] = None,
		semgrep_scanner: Optional[SemgrepScanner] = None,
		trivy_scanner: Optional[TrivyScanner] = None,
	) -> None:
		self.reports_dir = Path(reports_dir) if reports_dir is not None else Path("security_system/reports")
		self.reports_dir.mkdir(parents=True, exist_ok=True)
		self.gitleaks_scanner = gitleaks_scanner or GitleaksScanner(output_dir=self.reports_dir)
		self.semgrep_scanner = semgrep_scanner or SemgrepScanner(output_dir=self.reports_dir)
		self.trivy_scanner = trivy_scanner or TrivyScanner(output_dir=self.reports_dir)
		self.last_errors: Dict[str, str] = {}

	def run_all(
		self,
		target_path: Path | str,
		image_name: Optional[str] = None,
	) -> List[Path]:
		"""Run all scanners and return the list of raw report paths that were produced successfully."""

		result = self.run_all_with_result(target_path=target_path, image_name=image_name)
		return result.report_paths

	def run_all_with_result(
		self,
		target_path: Path | str,
		image_name: Optional[str] = None,
	) -> ScanServiceResult:
		"""Run all scanners and keep per-scanner failures from aborting the pipeline."""

		resolved_target = Path(target_path)
		result = ScanServiceResult()

		self._run_gitleaks(result, resolved_target)
		self._run_semgrep(result, resolved_target)
		self._run_trivy(result, resolved_target, image_name)

		self.last_errors = result.errors.copy()
		return result

	def _run_gitleaks(self, result: ScanServiceResult, target_path: Path) -> None:
		try:
			report_path = self.gitleaks_scanner.run(
				target_path=target_path,
				report_path=self.reports_dir / "gitleaks_report.json",
			)
		except ScannerError as exc:
			result.errors["gitleaks"] = str(exc)
			return
		result.report_paths.append(Path(report_path))

	def _run_semgrep(self, result: ScanServiceResult, target_path: Path) -> None:
		try:
			report_path = self.semgrep_scanner.run(
				target_path=target_path,
				report_path=self.reports_dir / "semgrep_report.json",
			)
		except ScannerError as exc:
			result.errors["semgrep"] = str(exc)
			return
		result.report_paths.append(Path(report_path))

	def _run_trivy(self, result: ScanServiceResult, target_path: Path, image_name: Optional[str]) -> None:
		try:
			report_path = self.trivy_scanner.run(
				target_path=target_path,
				report_path=self.reports_dir / "trivy_report.json",
				image_name=image_name,
			)
		except ScannerError as exc:
			result.errors["trivy"] = str(exc)
			return
		result.report_paths.append(Path(report_path))
