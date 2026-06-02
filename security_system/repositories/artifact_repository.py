from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from ..domain import GitContext


class ArtifactRepository:
	"""Repository for writing non-summary artifacts used by PR reporting and AI context."""

	def __init__(self, base_dir: Optional[Path | str] = None) -> None:
		self.base_dir = Path(base_dir) if base_dir is not None else Path("security_system/reports")

	@property
	def artifacts_dir(self) -> Path:
		return self.base_dir

	@property
	def processed_dir(self) -> Path:
		return self.base_dir

	def write_pr_comment(self, pr_comment: str, output_dir: Optional[Path | str] = None) -> Path:
		return self._write_text(pr_comment, self._resolve_output_dir(output_dir) / "pr_comment.md")

	def write_git_diff(self, git_diff: str, output_dir: Optional[Path | str] = None) -> Path:
		return self._write_text(git_diff, self._resolve_output_dir(output_dir) / "git_diff.txt")

	def read_git_context(self, artifact_path: Optional[Path | str] = None) -> GitContext:
		path = Path(artifact_path) if artifact_path is not None else self.processed_dir / "git_context.json"
		data = self._read_json(path)
		if not isinstance(data, dict):
			raise ValueError(f"Git context must be a JSON object: {path}")
		return GitContext.from_dict(data)

	def write_git_context(self, git_context: GitContext, output_dir: Optional[Path | str] = None) -> Path:
		return self._write_json(git_context.to_dict(), self._resolve_output_dir(output_dir) / "git_context.json")

	def write_all(
		self,
		pr_comment: str,
		git_diff: str,
		git_context: GitContext,
		output_dir: Optional[Path | str] = None,
	) -> Dict[str, Path]:
		target_dir = self._resolve_output_dir(output_dir)
		return {
			"pr_comment": self._write_text(pr_comment, target_dir / "pr_comment.md"),
			"git_diff": self._write_text(git_diff, target_dir / "git_diff.txt"),
			"git_context": self._write_json(git_context.to_dict(), target_dir / "git_context.json"),
		}

	def _resolve_output_dir(self, output_dir: Optional[Path | str]) -> Path:
		target_dir = Path(output_dir) if output_dir is not None else self.processed_dir
		target_dir.mkdir(parents=True, exist_ok=True)
		return target_dir

	def _write_text(self, content: str, target_path: Path) -> Path:
		target_path.parent.mkdir(parents=True, exist_ok=True)
		with target_path.open("w", encoding="utf-8") as file:
			file.write(content)
		return target_path

	def _write_json(self, payload: Dict[str, Any], target_path: Path) -> Path:
		target_path.parent.mkdir(parents=True, exist_ok=True)
		with target_path.open("w", encoding="utf-8") as file:
			json.dump(payload, file, indent=2, ensure_ascii=False)
		return target_path

	def _read_json(self, path: Path) -> Any:
		with path.open("r", encoding="utf-8") as file:
			return json.load(file)
