from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..domain import AgentResult, Decision, ScanSummary
from ..policies.policy_engine import PolicyEngine, PolicyEvaluationContext
from ..repositories.policy_repository import PolicyRepository
from ..repositories.report_repository import ReportRepository


@dataclass(slots=True)
class DecisionResult:
	"""Result returned by DecisionService after policy evaluation."""

	decision: Decision
	summary: ScanSummary
	agent_outputs: list[AgentResult]
	decision_report_path: str


class DecisionService:
	"""Service that evaluates policy and persists the final decision report."""

	def __init__(
		self,
		policy_engine: Optional[PolicyEngine] = None,
		policy_repository: Optional[PolicyRepository] = None,
		report_repository: Optional[ReportRepository] = None,
	) -> None:
		self.policy_engine = policy_engine or PolicyEngine()
		self.policy_repository = policy_repository or PolicyRepository()
		self.report_repository = report_repository or ReportRepository()

	def run(
		self,
		summary_path: Optional[Path | str] = None,
		agent_outputs_path: Optional[Path | str] = None,
		output_dir: Optional[Path | str] = None,
	) -> DecisionResult:
		"""Load inputs, call policy engine, and return DecisionResult."""

		summary = self.report_repository.read_summary(summary_path)
		agent_outputs = self.report_repository.read_agent_outputs(agent_outputs_path)
		policy_bundle = self.policy_repository.read_all()

		context = PolicyEvaluationContext(
			summary=summary,
			agent_outputs=agent_outputs,
			security_policy=policy_bundle.get("security_policy", {}),
			allowlist=policy_bundle.get("allowlist", {}),
			baseline=policy_bundle.get("baseline", {}),
		)

		decision = self.policy_engine.evaluate(context)
		decision_report_path = self.report_repository.write_decision_report(
			decision,
			output_dir=str(output_dir) if output_dir is not None else None,
		)

		return DecisionResult(
			decision=decision,
			summary=summary,
			agent_outputs=agent_outputs,
			decision_report_path=str(decision_report_path),
		)
