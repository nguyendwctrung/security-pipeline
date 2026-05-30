from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional, Sequence

from .base_scanner import BaseScanner, ScannerError


class GitleaksScanner(BaseScanner):
	"""Scanner adapter for running Gitleaks and exporting JSON findings."""

	tool_name = "gitleaks"

	def __init__(
		self,
		tool_executable: Optional[str] = None,
		config_path: Optional[Path | str] = None,
		output_dir: Optional[Path | str] = None,
		working_dir: Optional[Path | str] = None,
		env: Optional[dict[str, str]] = None,
		timeout_seconds: int = 300,
	) -> None:
		super().__init__(
			tool_executable=tool_executable or "gitleaks",
			output_dir=output_dir or Path("security_system/reports"),
			working_dir=working_dir,
			env=env,
			timeout_seconds=timeout_seconds,
		)
		self.config_path = Path(config_path) if config_path is not None else Path(".gitleaks.toml")

	def validate_tool_installed(self) -> None:
		self._require_executable()
		if not self.config_path.exists():
			raise ScannerError(f"gitleaks config file not found: {self.config_path}")

	def build_command(self, target_path: Path | str, report_path: Path) -> Sequence[str]:
		resolved_target = Path(target_path)
		return [
			self.tool_executable,
			"dir",
			"--source",
			str(resolved_target),
			"--config",
			str(self.config_path),
			"--report-format",
			"json",
			"--report-path",
			str(report_path),
			"--no-banner",
		]

	def run(self, target_path: Path | str, report_path: Optional[Path | str] = None) -> Path:
		resolved_report_path = super().run(target_path, report_path)
		if not resolved_report_path.exists() or resolved_report_path.stat().st_size == 0:
			self._write_empty_report(resolved_report_path)
		return resolved_report_path

	def _resolve_report_path(self, report_path: Optional[Path | str]) -> Path:
		if report_path is not None:
			resolved_path = Path(report_path)
		else:
			resolved_path = self.output_dir / "gitleaks_report.json"

		resolved_path.parent.mkdir(parents=True, exist_ok=True)
		return resolved_path

	def _check_exit_code(self, completed_process: subprocess.CompletedProcess[str], report_path: Path) -> None:
		if completed_process.returncode == 0:
			if not report_path.exists():
				self._write_empty_report(report_path)
			return

		if completed_process.returncode == 1:
			if not report_path.exists() or report_path.stat().st_size == 0:
				stdout = completed_process.stdout.strip()
				if stdout.startswith("[") or stdout.startswith("{"):
					report_path.write_text(stdout, encoding="utf-8")
				else:
					raise ScannerError(
						"gitleaks detected secrets but did not create a JSON report"
					)
			return

		super()._check_exit_code(completed_process, report_path)

	def _write_empty_report(self, report_path: Path) -> None:
		report_path.parent.mkdir(parents=True, exist_ok=True)
		with report_path.open("w", encoding="utf-8") as file:
			json.dump([], file, indent=2)
