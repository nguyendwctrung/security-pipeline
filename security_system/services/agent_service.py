from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..agents.crew_manager import CrewRunResult, SecurityCrewManager
from ..domain import GitContext, ScanSummary
from ..repositories.artifact_repository import ArtifactRepository
from ..repositories.report_repository import ReportRepository


@dataclass(slots=True)
class AgentServiceResult:
	"""Result returned by AgentService after running the security crew."""

	crew_result: CrewRunResult
	summary: ScanSummary
	git_context: GitContext
	git_diff: str

	@property
	def agent_outputs_path(self) -> str:
		return self.crew_result.agent_outputs_path


class AgentService:
	"""Service layer that loads artifacts and executes the Crew manager."""

	def __init__(
		self,
		crew_manager: Optional[SecurityCrewManager] = None,
		report_repository: Optional[ReportRepository] = None,
		artifact_repository: Optional[ArtifactRepository] = None,
	) -> None:
		self.report_repository = report_repository or ReportRepository()
		self.artifact_repository = artifact_repository or ArtifactRepository(base_dir=self.report_repository.base_dir)
		self.crew_manager = crew_manager or SecurityCrewManager(
			report_repository=self.report_repository,
			artifact_repository=self.artifact_repository,
		)

	def run(
		self,
		summary_path: Optional[Path | str] = None,
		git_context_path: Optional[Path | str] = None,
		git_diff_path: Optional[Path | str] = None,
		output_dir: Optional[Path | str] = None,
	) -> AgentServiceResult:
		"""Load summary + git diff/context, run crew manager, and write agent_outputs.json."""

		summary = self.report_repository.read_summary(summary_path)
		git_context = self.artifact_repository.read_git_context(git_context_path)
		git_diff = self._read_git_diff(git_diff_path)

		# Prefer explicit git_diff artifact when available.
		if git_diff:
			git_context.diff = git_diff

		crew_result = self.crew_manager.run(
			summary=summary,
			git_context=git_context,
			output_dir=str(output_dir) if output_dir is not None else None,
		)

		return AgentServiceResult(
			crew_result=crew_result,
			summary=summary,
			git_context=git_context,
			git_diff=git_diff,
		)

	def _read_git_diff(self, git_diff_path: Optional[Path | str]) -> str:
		path = Path(git_diff_path) if git_diff_path is not None else self.artifact_repository.processed_dir / "git_diff.txt"
		if not path.exists():
			return ""
		return path.read_text(encoding="utf-8")
