import argparse
import json
import sys
from .analyzer import LogAnalyzer


def build_report(analyzer: LogAnalyzer) -> dict: # it makes a dict for us (for the json)
    return {
        "total_lines": analyzer.total_lines,
        "parsed_lines": analyzer.parsed_count,
        "malformed_lines": analyzer.malformed_count,
        "unique_ips": len(analyzer.unique_ips),
        "error_rate_percent": round(analyzer.error_rate_percent, 2),
        "top_endpoints": analyzer.top_endpoints(),
        "hourly_distribution": analyzer.hourly_distribution(),
        "error_spikes": [
            {"hour": h, "rate_percent": round(r * 100, 1), "5xx_count": f, "total": t}
            for h, r, f, t in analyzer.error_spikes()
        ],
    }


def print_report(report: dict) -> None:
    line = "=" * 56
    print(line)
    print("log analysis report:")
    print(line)
    print(f"total lines:                {report['total_lines']}")
    print(f"legal parsed lines:    {report['parsed_lines']}")
    print(f"malformed lines:             {report['malformed_lines']}")
    print(f"unique ips:             {report['unique_ips']}")
    print(f"error rate percent(4xx + 5xx):          {report['error_rate_percent']}%")
    print()

    print(f"-- tops(top {len(report['top_endpoints'])}) --")
    for path, count in report["top_endpoints"]:
        print(f"  {count:>8}   {path}")
    print()

    print("--hourly distribution: --")
    max_count = max((c for _, c in report["hourly_distribution"]), default=0)
    for hour, count in report["hourly_distribution"]:
        bar_len = int((count / max_count) * 40) if max_count else 0
        print(f"  {hour}   {count:>7}   {'#' * bar_len}")

    

    if report["error_spikes"]:
        print()
        print("-- 5x rate percent--")
        for spike in report["error_spikes"]:
            print(
                f"  {spike['hour']}   rate: {spike['rate_percent']}%   "
                f"({spike['5xx_count']} از {spike['total']} "
            )


def build_arg_parser() -> argparse.ArgumentParser: 
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Command-line tool for analyzing access logs (Combined Log Format).",
    )
    parser.add_argument("logfile", help="log file path please")
    parser.add_argument(
        "--top", type=int, default=10, metavar="N",
        help="tumber of top endpoints to display (default: 10)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output in JSON format",
    )
   
    parser.add_argument(
        "--error-spike-threshold", type=float, default=0.5, metavar="RATE",
        help="5xx rate threshold to flag as spike (default: 0.5)",
    )
    return parser


def main(argv=None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    analyzer = LogAnalyzer(
        top_n=args.top,
        error_spike_threshold=args.error_spike_threshold,
    )

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                analyzer.process_line(raw_line)
    except FileNotFoundError:
        print(f"error:couldnt find '{args.logfile}'.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"error while reading the file{exc}", file=sys.stderr)
        sys.exit(1)

    report = build_report(analyzer)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()