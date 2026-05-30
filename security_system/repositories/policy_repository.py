from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class PolicyRepository:
	"""Repository for loading policy configuration files from disk."""

	def __init__(self, base_dir: Optional[Path | str] = None) -> None:
		self.base_dir = Path(base_dir) if base_dir is not None else Path("security_system/policies")

	@property
	def security_policy_path(self) -> Path:
		return self.base_dir / "security_policy.yml"

	@property
	def allowlist_path(self) -> Path:
		return self.base_dir / "allowlist.yml"

	@property
	def baseline_path(self) -> Path:
		return self.base_dir / "baseline.yml"

	def read_security_policy(self) -> Dict[str, Any]:
		data = self._read_yaml(self.security_policy_path)
		return data if isinstance(data, dict) else {"raw": data}

	def read_allowlist(self) -> Dict[str, Any]:
		data = self._read_yaml(self.allowlist_path)
		return data if isinstance(data, dict) else {"raw": data}

	def read_baseline(self) -> Dict[str, Any]:
		data = self._read_yaml(self.baseline_path)
		return data if isinstance(data, dict) else {"raw": data}

	def read_all(self) -> Dict[str, Dict[str, Any]]:
		return {
			"security_policy": self.read_security_policy(),
			"allowlist": self.read_allowlist(),
			"baseline": self.read_baseline(),
		}

	def _read_yaml(self, path: Path) -> Any:
		if not path.exists():
			raise FileNotFoundError(f"Policy file not found: {path}")

		with path.open("r", encoding="utf-8") as file:
			data = yaml.safe_load(file)

		return {} if data is None else data
