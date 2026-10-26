#!/usr/bin/env python3
"""Run a synthetic audit. Default is offline; live mode is explicit."""
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.demo import run_demo

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("replay", "deterministic", "live"), default="replay")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "runs/demo")
    args = parser.parse_args()
    result = run_demo(ROOT, args.output_dir, args.mode)
    print(json.dumps({k: result[k] for k in ("case_id", "status", "resolved_subject", "request_used_historical_email", "mode", "real_model_calls", "tool_calls", "guard_verdicts", "agent_prediction_promotion")}, indent=2))
    print(f"Result: {args.output_dir / 'result.json'}")
if __name__ == "__main__":
    main()
