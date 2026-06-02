from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ...domain import AgentResult, DecisionStatus, Finding, GitContext, ScanSummary, Severity


@dataclass(slots=True)
class RuleResult:
	"""Standardized output for a single policy rule evaluation."""

	status: DecisionStatus
	reason: str
	severity: Severity
	blocking: bool
	metadata: Dict[str, object] = field(default_factory=dict)

	def to_dict(self) -> Dict[str, object]:
		return {
			"status": self.status.value,
			"reason": self.reason,
			"severity": self.severity.value,
			"blocking": self.blocking,
			"metadata": self.metadata,
		}


@dataclass(slots=True)
class RuleContext:
	"""Typed evaluation context passed to policy rules."""

	summary: ScanSummary
	findings: List[Finding]
	agent_outputs: List[AgentResult]
	git_context: GitContext


class BaseRule(ABC):
	"""Common interface for all policy rules."""

	@abstractmethod
	def evaluate(
		self,
		summary: ScanSummary,
		findings: Sequence[Finding],
		agent_outputs: Sequence[AgentResult],
		git_context: GitContext,
	) -> RuleResult:
		"""Evaluate rule against pipeline context and return a standardized RuleResult."""

		raise NotImplementedError

	def pass_result(
		self,
		reason: str,
		severity: Severity = Severity.INFO,
		metadata: Dict[str, object] | None = None,
	) -> RuleResult:
		return RuleResult(
			status=DecisionStatus.PASS,
			reason=reason,
			severity=severity,
			blocking=False,
			metadata=metadata or {},
		)

	def warn_result(
		self,
		reason: str,
		severity: Severity = Severity.MEDIUM,
		metadata: Dict[str, object] | None = None,
	) -> RuleResult:
		return RuleResult(
			status=DecisionStatus.WARN,
			reason=reason,
			severity=severity,
			blocking=False,
			metadata=metadata or {},
		)

	def fail_result(
		self,
		reason: str,
		severity: Severity = Severity.HIGH,
		metadata: Dict[str, object] | None = None,
	) -> RuleResult:
		return RuleResult(
			status=DecisionStatus.FAIL,
			reason=reason,
			severity=severity,
			blocking=True,
			metadata=metadata or {},
		)
