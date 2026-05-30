from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..domain import AgentResult, Decision, ScanReport, ScanSummary


class ReportRepository:
    """Repository for reading scan inputs and writing normalized report artifacts."""

    def __init__(self, base_dir: Optional[Path | str] = None) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else Path("security_system/reports")

    @property
    def artifacts_dir(self) -> Path:
        return self.base_dir / "artifacts"

    @property
    def raw_dir(self) -> Path:
        return self.artifacts_dir / "raw"

    @property
    def processed_dir(self) -> Path:
        return self.artifacts_dir / "processed"

    def read_raw_report_json(self, report_path: Path | str) -> Any:
        path = Path(report_path)
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def read_summary(self, report_path: Optional[Path | str] = None) -> ScanSummary:
        path = Path(report_path) if report_path is not None else self.processed_dir / "summary.json"
        data = self._read_json(path)
        if isinstance(data, dict):
            if "reports" in data or "findings" in data:
                return ScanSummary.from_dict(data)
            return ScanSummary(reports=[ScanReport.from_dict(data)])
        if isinstance(data, list):
            return ScanSummary(reports=[ScanReport.from_dict(item) for item in data if isinstance(item, dict)])
        return ScanSummary()

    def read_agent_outputs(self, report_path: Optional[Path | str] = None) -> List[AgentResult]:
        path = Path(report_path) if report_path is not None else self.processed_dir / "agent_outputs.json"
        data = self._read_json(path)
        if isinstance(data, list):
            return [AgentResult.from_dict(item) for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            return [AgentResult.from_dict(data)]
        return []

    def read_decision_report(self, report_path: Optional[Path | str] = None) -> Decision:
        path = Path(report_path) if report_path is not None else self.processed_dir / "decision_report.json"
        data = self._read_json(path)
        if not isinstance(data, dict):
            raise ValueError(f"Decision report must be a JSON object: {path}")
        return Decision.from_dict(data)

    def write_summary(
        self,
        summary: ScanSummary | ScanReport | Iterable[ScanReport],
        output_dir: Optional[Path | str] = None,
    ) -> Path:
        return self._write_json(self._serialize_report_collection(summary), self._resolve_output_dir(output_dir) / "summary.json")

    def write_agent_outputs(
        self,
        agent_outputs: AgentResult | Iterable[AgentResult],
        output_dir: Optional[Path | str] = None,
    ) -> Path:
        return self._write_json(
            self._serialize_agent_results(agent_outputs),
            self._resolve_output_dir(output_dir) / "agent_outputs.json",
        )

    def write_decision_report(self, decision_report: Decision, output_dir: Optional[Path | str] = None) -> Path:
        return self._write_json(decision_report.to_dict(), self._resolve_output_dir(output_dir) / "decision_report.json")

    def write_all(
        self,
        summary: ScanSummary | ScanReport | Iterable[ScanReport],
        agent_outputs: AgentResult | Iterable[AgentResult],
        decision_report: Decision,
        output_dir: Optional[Path | str] = None,
    ) -> Dict[str, Path]:
        target_dir = self._resolve_output_dir(output_dir)
        return {
            "summary": self._write_json(self._serialize_report_collection(summary), target_dir / "summary.json"),
            "agent_outputs": self._write_json(self._serialize_agent_results(agent_outputs), target_dir / "agent_outputs.json"),
            "decision_report": self._write_json(decision_report.to_dict(), target_dir / "decision_report.json"),
        }

    def _resolve_output_dir(self, output_dir: Optional[Path | str]) -> Path:
        target_dir = Path(output_dir) if output_dir is not None else self.processed_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _write_json(self, payload: Dict[str, Any] | List[Dict[str, Any]], target_path: Path) -> Path:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with target_path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)
        return target_path

    def _read_json(self, path: Path) -> Any:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def _serialize_report_collection(
        self,
        summary: ScanSummary | ScanReport | Iterable[ScanReport],
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        if isinstance(summary, ScanSummary):
            return summary.to_dict()
        if isinstance(summary, ScanReport):
            return summary.to_dict()
        return [report.to_dict() for report in summary]

    def _serialize_agent_results(
        self,
        agent_outputs: AgentResult | Iterable[AgentResult],
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        if isinstance(agent_outputs, AgentResult):
            return agent_outputs.to_dict()
        return [result.to_dict() for result in agent_outputs]