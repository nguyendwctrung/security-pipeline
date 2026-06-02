from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .domain import DecisionStatus
from .orchestrator import SecurityPipeline


def build_parser() -> argparse.ArgumentParser:
	"""Create CLI parser for running the security pipeline in local and CI contexts."""

	parser = argparse.ArgumentParser(description="Run the security_system pipeline.")
	parser.add_argument(
		"--target-path",
		type=str,
		default=".",
		help="Path to repository/project to scan (default: current directory).",
	)
	parser.add_argument(
		"--image-name",
		type=str,
		default=None,
		help="Optional container image name for Trivy image scanning.",
	)
	parser.add_argument(
		"--output-dir",
		type=str,
		default=None,
		help="Optional directory for processed artifacts (summary, agent outputs, decision report).",
	)
	return parser


def main() -> int:
	"""Main entrypoint for security_system and GitHub Actions integration."""

	parser = build_parser()
	args = parser.parse_args()

	pipeline = SecurityPipeline()

	try:
		result = pipeline.run(
			target_path=Path(args.target_path),
			image_name=args.image_name,
			output_dir=Path(args.output_dir) if args.output_dir else None,
		)
	except Exception as exc:
		print(f"[ERROR] security pipeline execution failed: {exc}", file=sys.stderr)
		return 1

	decision = result.decision
	print(f"Final decision: {decision.status.value}")
	print(f"Final score: {decision.final_score:.2f}")
	print(f"Decision report: {result.decision_report_path}")

	if decision.blocking_reasons:
		print("Blocking reasons:")
		for reason in decision.blocking_reasons:
			print(f"- {reason}")

	if decision.warnings:
		print("Warnings:")
		for warning in decision.warnings:
			print(f"- {warning}")

	# GitHub Actions exit code mapping requested by user:
	# PASS -> 0, WARN -> 0, FAIL -> 1, ERROR -> 1.
	if decision.status in (DecisionStatus.PASS, DecisionStatus.WARN):
		return 0
	return 1


if __name__ == "__main__":
	raise SystemExit(main())
