from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


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

    def write_summary(self, summary: Dict[str, Any], output_dir: Optional[Path | str] = None) -> Path:
        return self._write_json(summary, self._resolve_output_dir(output_dir) / "summary.json")

    def write_agent_outputs(self, agent_outputs: Dict[str, Any], output_dir: Optional[Path | str] = None) -> Path:
        return self._write_json(agent_outputs, self._resolve_output_dir(output_dir) / "agent_outputs.json")

    def write_decision_report(self, decision_report: Dict[str, Any], output_dir: Optional[Path | str] = None) -> Path:
        return self._write_json(decision_report, self._resolve_output_dir(output_dir) / "decision_report.json")

    def write_all(
        self,
        summary: Dict[str, Any],
        agent_outputs: Dict[str, Any],
        decision_report: Dict[str, Any],
        output_dir: Optional[Path | str] = None,
    ) -> Dict[str, Path]:
        target_dir = self._resolve_output_dir(output_dir)
        return {
            "summary": self._write_json(summary, target_dir / "summary.json"),
            "agent_outputs": self._write_json(agent_outputs, target_dir / "agent_outputs.json"),
            "decision_report": self._write_json(decision_report, target_dir / "decision_report.json"),
        }

    def _resolve_output_dir(self, output_dir: Optional[Path | str]) -> Path:
        target_dir = Path(output_dir) if output_dir is not None else self.processed_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _write_json(self, payload: Dict[str, Any], target_path: Path) -> Path:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with target_path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)
        return target_path