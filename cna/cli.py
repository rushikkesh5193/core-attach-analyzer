import argparse, json, sys
from .analyze import load_trace, analyze, render_markdown
from .synth import generate


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cna", description="LTE attach call-flow analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write a synthetic trace (JSON lines)")
    g.add_argument("out"); g.add_argument("--seed", type=int, default=7)
    a = sub.add_parser("analyze", help="analyze a trace")
    a.add_argument("trace"); a.add_argument("--json", action="store_true")
    a.add_argument("--attach-min", type=float); a.add_argument("--hss-p95-max-ms", type=float)
    a.add_argument("--fail-on-alarm", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "generate":
        events, truth = generate(args.seed)
        with open(args.out, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        print(f"wrote {len(events)} events for {truth['attempts']} sessions to {args.out}")
        return 0
    th = {}
    if args.attach_min is not None: th["attach_success_min"] = args.attach_min
    if args.hss_p95_max_ms is not None: th["hss_p95_max_ms"] = args.hss_p95_max_ms
    r = analyze(load_trace(args.trace), th)
    if args.json:
        print(json.dumps({k: v for k, v in r.items() if k != "sessions"}, indent=2))
    else:
        print(render_markdown(r), end="")
    return 2 if (args.fail_on_alarm and r["alarms"]) else 0


if __name__ == "__main__":
    sys.exit(main())
