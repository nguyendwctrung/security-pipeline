from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..domain import Decision, DecisionStatus, ScanSummary
from ..repositories import ArtifactRepository, ReportRepository
from ..services import AgentService, DecisionService, GitService, ReportService, ScanService
from ..services.agent_service import AgentServiceResult
from ..services.decision_service import DecisionResult
from ..services.scan_service import ScanServiceResult


@dataclass(slots=True)
class SecurityPipelineResult:
	"""Final output of SecurityPipeline.run containing stage artifacts and final status."""

	status: DecisionStatus
	decision: Decision
	decision_result: DecisionResult
	agent_result: AgentServiceResult
	scan_result: ScanServiceResult
	summary: ScanSummary
	summary_path: str
	git_context_path: str
	agent_outputs_path: str
	decision_report_path: str
	pr_comment_path: str


class SecurityPipeline:
	"""Coordinate scanner -> report -> git -> agents -> policy flow for CI security checks."""

	def __init__(
		self,
		scan_service: Optional[ScanService] = None,
		report_service: Optional[ReportService] = None,
		git_service: Optional[GitService] = None,
		agent_service: Optional[AgentService] = None,
		decision_service: Optional[DecisionService] = None,
		report_repository: Optional[ReportRepository] = None,
		artifact_repository: Optional[ArtifactRepository] = None,
		reports_root: Optional[Path | str] = None,
	) -> None:
		self.reports_root = Path(reports_root) if reports_root is not None else Path("security_system/reports")
		self.report_repository = report_repository or ReportRepository(base_dir=self.reports_root)
		self.artifact_repository = artifact_repository or ArtifactRepository(base_dir=self.reports_root)

		self.scan_service = scan_service or ScanService(reports_dir=self.report_repository.raw_dir)
		self.report_service = report_service or ReportService(report_repository=self.report_repository)
		self.git_service = git_service or GitService(artifact_repository=self.artifact_repository)
		self.agent_service = agent_service or AgentService(
			report_repository=self.report_repository,
			artifact_repository=self.artifact_repository,
		)
		self.decision_service = decision_service or DecisionService(
			report_repository=self.report_repository,
			artifact_repository=self.artifact_repository,
		)

	def run(
		self,
		target_path: Path | str,
		image_name: Optional[str] = None,
		output_dir: Optional[Path | str] = None,
	) -> SecurityPipelineResult:
		"""Execute the full security workflow and return final PASS/WARN/FAIL status."""

		processed_dir = self._prepare_reports_folder(output_dir)

		# 2) run security scanners
		scan_result = self.scan_service.run_all_with_result(target_path=target_path, image_name=image_name)

		# 3+4) parse raw reports and create summary.json
		summary = self.report_service.build_summary(scan_result.report_paths, output_dir=processed_dir)
		summary_path = str(processed_dir / "summary.json")

		# 5) collect git context and write git_context.json (+ git_diff.txt)
		git_context = self.git_service.collect_and_persist(output_dir=processed_dir)
		git_context_path = str(processed_dir / "git_context.json")

		# 6) run CrewAI agents and write agent_outputs.json
		agent_result = self.agent_service.run(
			summary_path=summary_path,
			git_context_path=git_context_path,
			git_diff_path=processed_dir / "git_diff.txt",
			output_dir=processed_dir,
		)
		agent_outputs_path = agent_result.agent_outputs_path

		# 7+8) run policy/decision engine and write decision_report.json
		decision_result = self.decision_service.run(
			summary_path=summary_path,
			agent_outputs_path=agent_outputs_path,
			git_context_path=git_context_path,
			output_dir=processed_dir,
		)

		# 9) create pr_comment.md
		pr_comment = self._build_pr_comment(decision_result.decision)
		pr_comment_path = str(self.artifact_repository.write_pr_comment(pr_comment, output_dir=processed_dir))

		# 10) return final status PASS/WARN/FAIL
		return SecurityPipelineResult(
			status=decision_result.decision.status,
			decision=decision_result.decision,
			decision_result=decision_result,
			agent_result=agent_result,
			scan_result=scan_result,
			summary=summary,
			summary_path=summary_path,
			git_context_path=git_context_path,
			agent_outputs_path=agent_outputs_path,
			decision_report_path=decision_result.decision_report_path,
			pr_comment_path=pr_comment_path,
		)

	def _prepare_reports_folder(self, output_dir: Optional[Path | str]) -> Path:
		"""Step 1: ensure reports directories exist before any workflow stage runs."""

		self.reports_root.mkdir(parents=True, exist_ok=True)
		self.report_repository.artifacts_dir.mkdir(parents=True, exist_ok=True)
		self.report_repository.raw_dir.mkdir(parents=True, exist_ok=True)

		processed_dir = Path(output_dir) if output_dir is not None else self.report_repository.processed_dir
		processed_dir.mkdir(parents=True, exist_ok=True)
		return processed_dir

	def _build_pr_comment(self, decision: Decision) -> str:
		lines = [
			"## Security Pipeline Result",
			"",
			f"- Status: **{decision.status.value}**",
			f"- Final score: {decision.final_score:.2f}",
		]

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
