from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..domain import AgentResult, Finding, GitContext, ScanSummary
from ..repositories.artifact_repository import ArtifactRepository
from ..repositories.report_repository import ReportRepository
from .code_security_agent import CodeSecurityAgent
from .dependency_agent import DependencyAgent
from .docker_image_agent import DockerImageAgent
from .malicious_intent_agent import MaliciousIntentAgent
from .risk_aggregator_agent import AggregatedAgentResult, RiskAggregatorAgent
from .secret_agent import SecretAgent


@dataclass(slots=True)
class CrewRunResult:
	"""Result bundle for manager execution."""

	aggregated_result: AggregatedAgentResult
	agent_outputs: List[AgentResult]
	agent_outputs_path: str


class SecurityCrewManager:
	"""Orchestrate security agents in fixed order and persist their outputs."""

	def __init__(
		self,
		report_repository: Optional[ReportRepository] = None,
		artifact_repository: Optional[ArtifactRepository] = None,
		llm_model: Optional[str] = None,
	) -> None:
		self.report_repository = report_repository or ReportRepository()
		self.artifact_repository = artifact_repository or ArtifactRepository(base_dir=self.report_repository.base_dir)
		self.llm_model = self._initialize_gemini_llm(llm_model)
		self.agents = self._initialize_agents()

	def _initialize_gemini_llm(self, llm_model: Optional[str] = None) -> str:
		"""Initialize Gemini model configuration for CrewAI agents."""

		try:
			from dotenv import load_dotenv

			dotenv_path = Path(__file__).resolve().parents[1] / ".env"
			load_dotenv(dotenv_path=dotenv_path, override=False)
		except Exception:
			# Keep manager usable even if python-dotenv is unavailable.
			pass

		model = llm_model or os.getenv("GEMINI_MODEL") or "gemini-2.5-flash-lite"

		# Prefer GOOGLE_API_KEY from .env, keep GEMINI_API_KEY as compatibility fallback.
		api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
		if api_key:
			os.environ.setdefault("GOOGLE_API_KEY", api_key)
			os.environ.setdefault("GEMINI_API_KEY", api_key)

		return model

	def _initialize_agents(self) -> Dict[str, Any]:
		"""Initialize all agents used in the security crew."""

		return {
			"secret_agent": SecretAgent(llm_model=self.llm_model),
			"code_security_agent": CodeSecurityAgent(llm_model=self.llm_model),
			"dependency_agent": DependencyAgent(llm_model=self.llm_model),
			"docker_image_agent": DockerImageAgent(llm_model=self.llm_model),
			"malicious_intent_agent": MaliciousIntentAgent(llm_model=self.llm_model),
			"risk_aggregator_agent": RiskAggregatorAgent(llm_model=self.llm_model),
		}

	def create_tasks(self, findings: Sequence[Finding], git_context: GitContext) -> List[Any]:
		"""Create CrewAI tasks for each agent in required processing order."""

		try:
			from crewai import Task
		except ImportError:
			# CrewAI not available in environment. We still run deterministic Python analysis.
			return []

		payload = {
			"findings": [finding.to_dict() for finding in findings],
			"git_context": git_context.to_dict(),
		}

		ordered_agents = [
			"secret_agent",
			"code_security_agent",
			"dependency_agent",
			"docker_image_agent",
			"malicious_intent_agent",
			"risk_aggregator_agent",
		]

		tasks: List[Any] = []
		for agent_name in ordered_agents:
			agent = self.agents[agent_name]
			task = Task(
				agent=agent.create_crewai_agent(),
				description=agent.build_task_description(payload),
				expected_output="JSON dictionary only",
			)
			tasks.append(task)

		return tasks

	def run(
		self,
		summary: Optional[ScanSummary] = None,
		git_context: Optional[GitContext] = None,
		output_dir: Optional[str] = None,
	) -> CrewRunResult:
		"""Run agents in order and return the final aggregated result."""

		resolved_summary = summary or self.report_repository.read_summary()
		resolved_git_context = git_context or self.artifact_repository.read_git_context()

		findings = list(resolved_summary.findings)

		# Create CrewAI tasks for observability and future LLM-powered execution.
		# The deterministic agent analyze() path below remains the source of truth for typed outputs.
		tasks = self.create_tasks(findings, resolved_git_context)
		if tasks:
			self._run_crewai(tasks)

		agent_outputs = self._run_agents_in_order(findings, resolved_git_context)
		aggregated_result = self.agents["risk_aggregator_agent"].analyze(agent_outputs)

		persist_outputs: List[AgentResult] = list(agent_outputs)
		persist_outputs.append(aggregated_result.to_agent_result())
		path = self.report_repository.write_agent_outputs(persist_outputs, output_dir=output_dir)

		return CrewRunResult(
			aggregated_result=aggregated_result,
			agent_outputs=agent_outputs,
			agent_outputs_path=str(path),
		)

	def _run_crewai(self, tasks: Sequence[Any]) -> None:
		"""Execute CrewAI pipeline sequentially when CrewAI is available."""

		try:
			from crewai import Crew, Process
		except ImportError:
			return

		crew_kwargs: Dict[str, Any] = {
			"agents": [task.agent for task in tasks],
			"tasks": list(tasks),
			"process": Process.sequential,
			"verbose": False,
		}
		crew = Crew(**crew_kwargs)
		crew.kickoff()

	def _run_agents_in_order(self, findings: Sequence[Finding], git_context: GitContext) -> List[AgentResult]:
		"""Run all non-aggregator agents in the required order and collect outputs."""

		ordered_names = [
			"secret_agent",
			"code_security_agent",
			"dependency_agent",
			"docker_image_agent",
			"malicious_intent_agent",
		]

		outputs: List[AgentResult] = []
		for name in ordered_names:
			agent = self.agents[name]
			outputs.append(agent.analyze(findings, git_context))
		return outputs

