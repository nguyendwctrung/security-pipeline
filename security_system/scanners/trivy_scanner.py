from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from .base_scanner import BaseScanner, ScannerError


class TrivyScanner(BaseScanner):
	"""Scanner adapter for running Trivy on the filesystem and optional Docker images."""

	tool_name = "trivy"

	def __init__(
		self,
		tool_executable: Optional[str] = None,
		config_path: Optional[Path | str] = None,
		output_dir: Optional[Path | str] = None,
		working_dir: Optional[Path | str] = None,
		env: Optional[Mapping[str, str]] = None,
		timeout_seconds: int = 300,
	) -> None:
		super().__init__(
			tool_executable=tool_executable or "trivy",
			output_dir=output_dir or Path("security_system/reports"),
			working_dir=working_dir,
			env=env,
			timeout_seconds=timeout_seconds,
		)
		self.config_path = Path(config_path) if config_path is not None else Path(".trivy.yaml")

	def validate_tool_installed(self) -> None:
		self._require_executable()
		if not self.config_path.exists():
			raise ScannerError(f"trivy config file not found: {self.config_path}")

	def build_command(self, target_path: Path | str, report_path: Path) -> Sequence[str]:
		resolved_target = Path(target_path)
		return self._build_scan_command("filesystem", str(resolved_target), report_path)

	def run(
		self,
		target_path: Path | str,
		report_path: Optional[Path | str] = None,
		image_name: Optional[str] = None,
	) -> Path:
		self.validate_tool_installed()
		resolved_report_path = self._resolve_report_path(report_path)

		filesystem_report_path = resolved_report_path.with_name("trivy_filesystem_report.json")
		filesystem_data = self._execute_scan(
			command=self.build_command(target_path, filesystem_report_path),
			report_path=filesystem_report_path,
			scan_label="filesystem",
		)

		if image_name:
			image_report_path = resolved_report_path.with_name("trivy_image_report.json")
			image_data = self._execute_scan(
				command=self._build_scan_command("image", image_name, image_report_path),
				report_path=image_report_path,
				scan_label="image",
			)
		else:
			image_data = {
				"skipped": True,
				"reason": "No Docker image provided for Trivy image scan.",
			}

		combined_report = {
			"filesystem": filesystem_data,
			"image": image_data,
		}
		with resolved_report_path.open("w", encoding="utf-8") as file:
			json.dump(combined_report, file, indent=2, ensure_ascii=False)

		return resolved_report_path

	def _resolve_report_path(self, report_path: Optional[Path | str]) -> Path:
		if report_path is not None:
			resolved_path = Path(report_path)
		else:
			resolved_path = self.output_dir / "trivy_report.json"

		resolved_path.parent.mkdir(parents=True, exist_ok=True)
		return resolved_path

	def _build_scan_command(self, scan_type: str, target: str, report_path: Path) -> Sequence[str]:
		return [
			self.tool_executable,
			scan_type,
			"--config",
			str(self.config_path),
			"--format",
			"json",
			"--output",
			str(report_path),
			target,
		]

	def _execute_scan(self, command: Sequence[str], report_path: Path, scan_label: str) -> Dict[str, Any]:
		try:
			completed_process = subprocess.run(
				list(command),
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
			raise ScannerError(f"{self.tool_name} {scan_label} scan timed out after {self.timeout_seconds} seconds") from exc

		self._check_trivy_exit_code(completed_process, report_path, scan_label)

		if not report_path.exists() or report_path.stat().st_size == 0:
			return self._empty_scan_payload(scan_label, target=None)

		with report_path.open("r", encoding="utf-8") as file:
			return json.load(file)

	def _check_trivy_exit_code(
		self,
		completed_process: subprocess.CompletedProcess[str],
		report_path: Path,
		scan_label: str,
	) -> None:
		if completed_process.returncode == 0:
			return

		stderr = completed_process.stderr.strip()
		stdout = completed_process.stdout.strip()
		failure_output = f"{stderr} {stdout}".strip().lower()

		if scan_label == "image" and self._is_missing_image_error(failure_output):
			with report_path.open("w", encoding="utf-8") as file:
				json.dump(
					{
						"skipped": True,
						"reason": "Docker image not found or not accessible for Trivy scan.",
						"details": stderr or stdout,
					},
					file,
					indent=2,
					ensure_ascii=False,
				)
			return

		if "config" in failure_output or "yaml" in failure_output:
			raise ScannerError(
				f"trivy configuration is invalid | report path: {report_path} | details: {stderr or stdout}"
			)

		message_parts = [
			f"trivy {scan_label} scan exited with code {completed_process.returncode}",
			f"report path: {report_path}",
		]
		if stderr:
			message_parts.append(f"stderr: {stderr}")
		elif stdout:
			message_parts.append(f"stdout: {stdout}")

		raise ScannerError(" | ".join(message_parts))

	def _is_missing_image_error(self, failure_output: str) -> bool:
		return any(
			needle in failure_output
			for needle in (
				"unable to inspect the image",
				"unable to find the specified image",
				"no such image",
				"manifest unknown",
				"not found",
			)
		)

	def _empty_scan_payload(self, scan_label: str, target: Optional[str]) -> Dict[str, Any]:
		return {
			"SchemaVersion": 2,
			"ArtifactName": target or "",
			"ArtifactType": scan_label,
			"Results": [],
		}
