from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


class ReadOnlySecurityTools:
	"""Read-only helpers for loading scan artifacts used by agents."""

	_ALLOWED_RAW_REPORTS = {
		"gitleaks_report.json",
		"semgrep_report.json",
		"trivy_report.json",
	}

	def __init__(self, reports_base_dir: Optional[Path | str] = None) -> None:
		self.reports_base_dir = (
			Path(reports_base_dir) if reports_base_dir is not None else Path("security_system/reports")
		)

	@property
	def processed_dir(self) -> Path:
		return self.reports_base_dir

	@property
	def raw_dir(self) -> Path:
		return self.reports_base_dir

	def read_summary_json(self, path: Optional[Path | str] = None) -> Dict[str, Any]:
		"""Read summary JSON from processed artifacts."""

		target = Path(path) if path is not None else self.processed_dir / "summary.json"
		data = self._read_json_file(target)
		if not isinstance(data, dict):
			raise ValueError(f"Expected JSON object in {target}, got {type(data).__name__}")
		return data

	def read_git_context_json(self, path: Optional[Path | str] = None) -> Dict[str, Any]:
		"""Read git_context JSON from processed artifacts."""

		target = Path(path) if path is not None else self.processed_dir / "git_context.json"
		data = self._read_json_file(target)
		if not isinstance(data, dict):
			raise ValueError(f"Expected JSON object in {target}, got {type(data).__name__}")
		return data

	def read_git_diff_txt(self, path: Optional[Path | str] = None) -> str:
		"""Read git diff text from processed artifacts."""

		target = Path(path) if path is not None else self.processed_dir / "git_diff.txt"
		return self._read_text_file(target)

	def read_gitleaks_report_json(self, path: Optional[Path | str] = None) -> Any:
		"""Read raw gitleaks report JSON."""

		target = Path(path) if path is not None else self.raw_dir / "gitleaks_report.json"
		return self._read_allowed_raw_report(target)

	def read_semgrep_report_json(self, path: Optional[Path | str] = None) -> Any:
		"""Read raw semgrep report JSON."""

		target = Path(path) if path is not None else self.raw_dir / "semgrep_report.json"
		return self._read_allowed_raw_report(target)

	def read_trivy_report_json(self, path: Optional[Path | str] = None) -> Any:
		"""Read raw trivy report JSON."""

		target = Path(path) if path is not None else self.raw_dir / "trivy_report.json"
		return self._read_allowed_raw_report(target)

	def read_raw_report_json(self, report_filename: str) -> Any:
		"""Read one of the allowlisted raw scanner reports."""

		normalized_name = Path(report_filename).name
		if normalized_name not in self._ALLOWED_RAW_REPORTS:
			raise PermissionError(
				"Only read-only access to allowlisted raw reports is permitted: "
				"gitleaks_report.json, semgrep_report.json, trivy_report.json"
			)
		target = self.raw_dir / normalized_name
		return self._read_json_file(target)

	# Explicitly blocked capabilities to keep this toolkit read-only and non-destructive.
	def run_command(self, *_args: Any, **_kwargs: Any) -> None:
		raise PermissionError("Command execution is disabled for read-only security tools.")

	def refactor_code(self, *_args: Any, **_kwargs: Any) -> None:
		raise PermissionError("Code refactoring is disabled for read-only security tools.")

	def _read_allowed_raw_report(self, target: Path) -> Any:
		if target.name not in self._ALLOWED_RAW_REPORTS:
			raise PermissionError("Raw report access is restricted to allowlisted scanner report names.")
		return self._read_json_file(target)

	def _read_json_file(self, path: Path) -> Any:
		if not path.exists():
			raise FileNotFoundError(f"Artifact file not found: {path}")
		with path.open("r", encoding="utf-8") as file:
			return json.load(file)

	def _read_text_file(self, path: Path) -> str:
		if not path.exists():
			raise FileNotFoundError(f"Artifact file not found: {path}")
		return path.read_text(encoding="utf-8")


def create_read_only_tools(reports_base_dir: Optional[Path | str] = None) -> ReadOnlySecurityTools:
	"""Factory helper for injecting read-only tools into agent configurations."""

	return ReadOnlySecurityTools(reports_base_dir=reports_base_dir)
