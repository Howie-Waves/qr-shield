"""Local CLI for authorised review decisions and model-release audit records."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services import review_store


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    decide = commands.add_parser("decide")
    decide.add_argument("case_id")
    decide.add_argument("reviewer_id")
    decide.add_argument("decision", choices=["approved", "rejected", "closed"])
    release = commands.add_parser("release")
    release.add_argument("model_version")
    release.add_argument("metrics_path", type=Path)
    release.add_argument("reviewer_id")
    release.add_argument("decision", choices=["approved", "rejected", "rolled_back"])
    release.add_argument("--rollback-target")
    release.add_argument("--notes")
    commands.add_parser("cleanup")
    args = parser.parse_args(argv)
    if args.command == "list":
        print(json.dumps(review_store.list_review_cases(), indent=2))
    elif args.command == "decide":
        review_store.decide_case(args.case_id, args.reviewer_id, args.decision)
    elif args.command == "release":
        print(
            review_store.record_model_release(
                args.model_version, args.metrics_path, args.reviewer_id,
                args.decision, args.rollback_target, args.notes,
            )
        )
    else:
        print(review_store.cleanup_expired())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
