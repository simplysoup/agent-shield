import argparse
import json
from .core import benchmark, run_case, scenarios

def main():
    parser = argparse.ArgumentParser(description="AgentShield deterministic security testbed")
    parser.add_argument("command", choices=["benchmark", "demo", "scenarios"])
    parser.add_argument("--mode", choices=["baseline", "prompt", "policy", "layered"], default="layered")
    args = parser.parse_args()
    if args.command == "benchmark":
        output = benchmark()
    elif args.command == "scenarios":
        output = [{"id": s.id, "category": s.category} for s in scenarios()]
    else:
        s = scenarios()[0]
        output = {"scenario": s.id, "baseline": run_case(s, "baseline").__dict__, "defended": run_case(s, args.mode).__dict__}
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
