from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass(slots=True)
class GitContext:
	"""Shared git metadata model for services, agents, and dashboard views."""

	commit_hash: str
	branch: str
	author: str
	timestamp: datetime
	commit_message: str
	changed_files: List[str] = field(default_factory=list)
	diff: str = ""

	def to_dict(self) -> Dict[str, object]:
		return {
			"commit_hash": self.commit_hash,
			"branch": self.branch,
			"author": self.author,
			"timestamp": self.timestamp.isoformat(),
			"commit_message": self.commit_message,
			"changed_files": self.changed_files,
			"diff": self.diff,
		}

	@classmethod
	def from_dict(cls, data: Dict[str, object]) -> "GitContext":
		timestamp_raw = data.get("timestamp")
		timestamp = datetime.fromisoformat(str(timestamp_raw)) if timestamp_raw else datetime.utcnow()
		changed_files_raw = data.get("changed_files")
		changed_files = changed_files_raw if isinstance(changed_files_raw, list) else []
		return cls(
			commit_hash=str(data.get("commit_hash") or ""),
			branch=str(data.get("branch") or ""),
			author=str(data.get("author") or ""),
			timestamp=timestamp,
			commit_message=str(data.get("commit_message") or ""),
			changed_files=[str(item) for item in changed_files],
			diff=str(data.get("diff") or ""),
		)
