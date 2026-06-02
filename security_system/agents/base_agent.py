from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional, Sequence

from ..domain import AgentResult, Finding, RiskLevel


@dataclass(slots=True)
class AgentConfig:
	"""Shared configuration for all security-focused CrewAI agents."""

	agent_name: str
	role: str
	goal: str
	backstory: str
	llm_model: str
	prompt: str = ""
	tools: List[Any] = field(default_factory=list)
	verbose: bool = False
	allow_delegation: bool = False


class BaseSecurityAgent(ABC):
	"""Base class for security agents that wraps CrewAI configuration and output handling."""

	def __init__(self, config: AgentConfig) -> None:
		self.config = config

	@property
	def agent_name(self) -> str:
		return self.config.agent_name

	@property
	def role(self) -> str:
		return self.config.role

	@property
	def goal(self) -> str:
		return self.config.goal

	@property
	def backstory(self) -> str:
		return self.config.backstory

	@property
	def llm_model(self) -> str:
		return self.config.llm_model

	@property
	def tools(self) -> List[Any]:
		return self.config.tools

	@property
	def prompt(self) -> str:
		return self.config.prompt

	def create_crewai_agent(self) -> Any:
		"""Create a CrewAI Agent using the shared configuration for this security role."""

		try:
			from crewai import Agent
		except ImportError as exc:
			raise RuntimeError(
				"CrewAI is not installed. Add the 'crewai' package before creating agents."
			) from exc

		return Agent(
			role=self.role,
			goal=self.goal,
			backstory=self.backstory,
			tools=self._resolve_crewai_tools(),
			llm=self.llm_model,
			verbose=self.config.verbose,
			allow_delegation=self.config.allow_delegation,
		)

	def _resolve_crewai_tools(self) -> List[Any]:
		"""Filter configured tools down to CrewAI-compatible tool objects."""

		resolved: List[Any] = []
		for tool in self.tools:
			if tool is None:
				continue
			if isinstance(tool, dict):
				resolved.append(tool)
				continue

			has_tool_shape = (
				hasattr(tool, "name")
				and hasattr(tool, "description")
				and (hasattr(tool, "run") or hasattr(tool, "_run"))
			)
			if has_tool_shape:
				resolved.append(tool)

		return resolved

	def build_task_description(self, input_payload: Optional[Dict[str, Any]] = None) -> str:
		"""Build a CrewAI task description from shared prompt and optional JSON payload."""

		base_prompt = self.prompt.strip() or self.goal
		if input_payload is None:
			return base_prompt

		payload_json = json.dumps(input_payload, ensure_ascii=False, default=str)
		return f"{base_prompt}\n\nInput JSON payload for analysis:\n{payload_json}"

	def normalize_output(
		self,
		output: Any,
		findings: Optional[Sequence[Finding]] = None,
		default_risk_score: float = 0.0,
		default_confidence: float = 0.0,
	) -> AgentResult:
		"""Normalize free-form agent output into the shared AgentResult model."""

		payload = self._coerce_output_payload(output)
		normalized_findings = self._coerce_findings(payload.get("findings"), findings)
		recommendations = self._coerce_string_list(payload.get("recommendations"))
		evidence = self._coerce_string_list(payload.get("evidence"))

		return AgentResult(
			agent_name=str(payload.get("agent_name") or self.agent_name),
			risk_score=self._coerce_float(payload.get("risk_score"), default_risk_score),
			risk_level=self._coerce_risk_level(payload.get("risk_level")),
			findings=normalized_findings,
			recommendations=recommendations,
			summary=str(payload.get("summary") or ""),
			confidence=self._coerce_float(payload.get("confidence"), default_confidence),
			evidence=evidence,
		)

	def _coerce_output_payload(self, output: Any) -> Dict[str, Any]:
		if isinstance(output, AgentResult):
			return output.to_dict()
		if isinstance(output, dict):
			return output
		if output is None:
			return {}
		return {"summary": str(output)}

	def _coerce_findings(self, raw_findings: Any, fallback_findings: Optional[Sequence[Finding]]) -> List[Finding]:
		if isinstance(raw_findings, list):
			findings: List[Finding] = []
			for item in raw_findings:
				if isinstance(item, Finding):
					findings.append(item)
				elif isinstance(item, dict):
					findings.append(Finding.from_dict(item))
			return findings

		if fallback_findings is None:
			return []

		return list(fallback_findings)

	def _coerce_string_list(self, value: Any) -> List[str]:
		if isinstance(value, list):
			return [str(item) for item in value if item is not None]
		if value is None:
			return []
		return [str(value)]

	def _coerce_float(self, value: Any, default: float) -> float:
		try:
			return float(value)
		except (TypeError, ValueError):
			return default

	def _coerce_risk_level(self, value: Any) -> RiskLevel:
		if isinstance(value, RiskLevel):
			return value
		if value is None:
			return RiskLevel.NONE
		try:
			return RiskLevel(str(value).upper())
		except ValueError:
			return RiskLevel.NONE
