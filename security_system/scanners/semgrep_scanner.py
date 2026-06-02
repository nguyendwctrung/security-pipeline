from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .base_scanner import BaseScanner, ScannerError


class SemgrepScanner(BaseScanner):
	"""Scanner adapter for running Semgrep against the source tree or changed files."""

	tool_name = "semgrep"

	def __init__(
		self,
		tool_executable: Optional[str] = None,
		config_path: Optional[Path | str] = None,
		rule_profile: str = "p/owasp-top-ten",
		output_dir: Optional[Path | str] = None,
		working_dir: Optional[Path | str] = None,
		env: Optional[Mapping[str, str]] = None,
		timeout_seconds: int = 300,
	) -> None:
		super().__init__(
			tool_executable=tool_executable or "semgrep",
			output_dir=output_dir or Path("security_system/reports"),
			working_dir=working_dir or Path("PokeMap"),
			env=env,
			timeout_seconds=timeout_seconds,
		)
		self.config_path = Path(config_path) if config_path is not None else Path(".semgrep.yml")
		self.rule_profile = rule_profile

	def validate_tool_installed(self) -> None:
		self._require_executable()
		if not self.config_path.exists():
			raise ScannerError(f"semgrep config file not found: {self.config_path}")

	def build_command(self, target_path: Path | str, report_path: Path) -> Sequence[str]:
		resolved_target = Path(target_path)
		command = [
			self.tool_executable,
			"scan",
			"--config",
			str(self.config_path),
			"--config",
			self.rule_profile,
			"--json",
			"--output",
			str(report_path),
			"--error",
		]

		command.append(str(resolved_target))
		return command

	def run(self, target_path: Path | str, report_path: Optional[Path | str] = None) -> Path:
		resolved_report_path = super().run(target_path, report_path)
		if not resolved_report_path.exists() or resolved_report_path.stat().st_size == 0:
			self._write_empty_report(resolved_report_path)
		return resolved_report_path

	def _resolve_report_path(self, report_path: Optional[Path | str]) -> Path:
		if report_path is not None:
			resolved_path = Path(report_path)
		else:
			resolved_path = self.output_dir / "semgrep_report.json"

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
				if stdout.startswith("{"):
					report_path.write_text(stdout, encoding="utf-8")
				else:
					self._write_empty_report(report_path)
			return

		stderr = completed_process.stderr.strip()
		stdout = completed_process.stdout.strip()
		failure_output = f"{stderr} {stdout}".strip().lower()
		if "invalid configuration file" in failure_output or "invalid yaml" in failure_output or "rule parse error" in failure_output:
			raise ScannerError(
				f"semgrep configuration or rules are invalid | report path: {report_path} | details: {stderr or stdout}"
			)

		super()._check_exit_code(completed_process, report_path)

	def _write_empty_report(self, report_path: Path) -> None:
		empty_report = {
			"version": "",
			"results": [],
			"errors": [],
			"paths": {"scanned": [], "skipped": []},
		}
		report_path.parent.mkdir(parents=True, exist_ok=True)
		with report_path.open("w", encoding="utf-8") as file:
			json.dump(empty_report, file, indent=2)
