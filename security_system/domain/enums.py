from __future__ import annotations

from enum import Enum


class ScannerType(str, Enum):
	GITLEAKS = "gitleaks"
	SEMGREP = "semgrep"
	TRIVY = "trivy"


class Severity(str, Enum):
	CRITICAL = "CRITICAL"
	HIGH = "HIGH"
	MEDIUM = "MEDIUM"
	LOW = "LOW"
	INFO = "INFO"
	UNKNOWN = "UNKNOWN"


class Status(str, Enum):
	PENDING = "PENDING"
	RUNNING = "RUNNING"
	SUCCESS = "SUCCESS"
	FAILED = "FAILED"
	SKIPPED = "SKIPPED"


class DecisionStatus(str, Enum):
	PASS = "PASS"
	WARN = "WARN"
	FAIL = "FAIL"


class RiskLevel(str, Enum):
	NONE = "NONE"
	LOW = "LOW"
	MEDIUM = "MEDIUM"
	HIGH = "HIGH"
	CRITICAL = "CRITICAL"