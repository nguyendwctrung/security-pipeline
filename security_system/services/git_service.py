from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ..domain import GitContext
from ..repositories import ArtifactRepository


class GitServiceError(Exception):
	"""Raised when git metadata cannot be collected successfully."""


class GitService:
	"""Collect git metadata and persist it for reporting and dashboard use."""

	def __init__(
		self,
		repo_path: Optional[Path | str] = None,
		artifact_repository: Optional[ArtifactRepository] = None,
	) -> None:
		self.repo_path = Path(repo_path) if repo_path is not None else Path.cwd()
		self.artifact_repository = artifact_repository or ArtifactRepository()

	def get_commit_hash(self) -> str:
		return self._run_git_command(["git", "rev-parse", "HEAD"])

	def get_branch_name(self) -> str:
		return self._run_git_command(["git", "rev-parse", "--abbrev-ref", "HEAD"])

	def get_author(self) -> str:
		return self._run_git_command(["git", "log", "-1", "--pretty=%an"])

	def get_timestamp(self) -> str:
		return self._run_git_command(["git", "log", "-1", "--pretty=%cI"])

	def get_commit_message(self) -> str:
		return self._run_git_command(["git", "log", "-1", "--pretty=%B"])

	def get_changed_files(self) -> List[str]:
		output = self._run_git_command(["git", "show", "--pretty=", "--name-only", "HEAD"])
		return [line.strip() for line in output.splitlines() if line.strip()]

	def get_git_diff(self) -> str:
		return self._run_git_command(["git", "show", "--format=", "HEAD"])

	def create_git_context(self) -> GitContext:
		return GitContext.from_dict(
			{
				"commit_hash": self.get_commit_hash(),
				"branch": self.get_branch_name(),
				"author": self.get_author(),
				"timestamp": self.get_timestamp(),
				"commit_message": self.get_commit_message(),
				"changed_files": self.get_changed_files(),
				"diff": self.get_git_diff(),
			}
		)

	def write_git_artifacts(self, git_context: Optional[GitContext] = None, output_dir: Optional[Path | str] = None) -> Dict[str, Path]:
		context = git_context or self.create_git_context()
		return {
			"git_context": self.artifact_repository.write_git_context(context, output_dir=output_dir),
			"git_diff": self.artifact_repository.write_git_diff(context.diff, output_dir=output_dir),
		}

	def collect_and_persist(self, output_dir: Optional[Path | str] = None) -> GitContext:
		context = self.create_git_context()
		self.write_git_artifacts(context, output_dir=output_dir)
		return context

	def _run_git_command(self, command: List[str]) -> str:
		try:
			completed_process = subprocess.run(
				command,
				cwd=self.repo_path,
				capture_output=True,
				text=True,
				check=False,
			)
		except FileNotFoundError as exc:
			raise GitServiceError("git executable not found in PATH") from exc

		if completed_process.returncode != 0:
			stderr = completed_process.stderr.strip()
			stdout = completed_process.stdout.strip()
			details = stderr or stdout or "unknown git error"
			raise GitServiceError(f"Git command failed: {' '.join(command)} | details: {details}")

		return completed_process.stdout.strip()
