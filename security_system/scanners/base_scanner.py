from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Mapping, Optional, Sequence


class ScannerError(Exception):
	"""Raised when a scanner cannot be executed successfully."""


class BaseScanner(ABC):
	"""Common interface and execution flow for all security scanners."""

	tool_name = "base"

	def __init__(
		self,
		tool_executable: Optional[str] = None,
		output_dir: Optional[Path | str] = None,
		working_dir: Optional[Path | str] = None,
		env: Optional[Mapping[str, str]] = None,
		timeout_seconds: int = 300,
	) -> None:
		self.tool_executable = tool_executable or self.tool_name
		self.output_dir = Path(output_dir) if output_dir is not None else Path("security_system/reports/artifacts/raw")
		self.working_dir = Path(working_dir) if working_dir is not None else Path.cwd()
		self.env = dict(env) if env is not None else None
		self.timeout_seconds = timeout_seconds

	@abstractmethod
	def build_command(self, target_path: Path | str, report_path: Path) -> Sequence[str]:
		"""Build the subprocess command that runs the scanner and writes a raw report."""

	@abstractmethod
	def validate_tool_installed(self) -> None:
		"""Raise ScannerError when the scanner executable is not available."""

	def run(self, target_path: Path | str, report_path: Optional[Path | str] = None) -> Path:
		"""Execute the scanner and return the raw report path on success."""

		self.validate_tool_installed()
		resolved_report_path = self._resolve_report_path(report_path)
		command = list(self.build_command(target_path, resolved_report_path))

		try:
			completed_process = subprocess.run(
				command,
				cwd=self.working_dir,
				env=self.env,
				capture_output=True,
				text=True,
				check=False,
				timeout=self.timeout_seconds,
			)
		except FileNotFoundError as exc:
			raise ScannerError(f"{self.tool_name} executable not found: {self.tool_executable}") from exc
		except subprocess.TimeoutExpired as exc:
			raise ScannerError(f"{self.tool_name} scan timed out after {self.timeout_seconds} seconds") from exc

		self._check_exit_code(completed_process, resolved_report_path)

		if not resolved_report_path.exists():
			raise ScannerError(
				f"{self.tool_name} completed without creating expected report: {resolved_report_path}"
			)

		return resolved_report_path

	def _resolve_report_path(self, report_path: Optional[Path | str]) -> Path:
		if report_path is not None:
			resolved_path = Path(report_path)
		else:
			resolved_path = self.output_dir / f"{self.tool_name}.json"

		resolved_path.parent.mkdir(parents=True, exist_ok=True)
		return resolved_path

	def _check_exit_code(self, completed_process: subprocess.CompletedProcess[str], report_path: Path) -> None:
		if completed_process.returncode == 0:
			return

		stderr = completed_process.stderr.strip()
		stdout = completed_process.stdout.strip()
		message_parts = [
			f"{self.tool_name} exited with code {completed_process.returncode}",
			f"report path: {report_path}",
		]
		if stderr:
			message_parts.append(f"stderr: {stderr}")
		elif stdout:
			message_parts.append(f"stdout: {stdout}")

		raise ScannerError(" | ".join(message_parts))

	def _require_executable(self) -> None:
		if shutil.which(self.tool_executable) is None:
			raise ScannerError(f"{self.tool_name} is not installed or not found in PATH: {self.tool_executable}")
