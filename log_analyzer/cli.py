import argparse 
import json
import sys
import gzip
import time
from .analyzer import LogAnalyzer
from datetime import datetime, timezone 
from typing import IO #seems like it make a file-like object (we need it to convert gzip)

CLI_TIME_FORMAT = "%Y-%m-%dT%H:%M"

def open_log_file(path: str) -> IO[str]: #open a log file with automatic support for compressed (gzip) files
    if path.endswith(".gz"):             #(asked as an extra task)
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="r", encoding="utf-8", errors="replace")

def parse_cli_time(value: str) -> datetime: #Parse a time string from command-line arguments into a UTC datetime
    dt = datetime.strptime(value, CLI_TIME_FORMAT)
    return dt.replace(tzinfo=timezone.utc)

def build_report(analyzer: LogAnalyzer) -> dict: #Build a structured dict report from the analyzer
    return {
        "total_lines": analyzer.total_lines,
        "parsed_lines": analyzer.parsed_count,
        "malformed_lines": analyzer.malformed_count,
        "filtered_out_lines": analyzer.filtered_out_count,
        "unique_ips": len(analyzer.unique_ips),
        "error_rate_percent": round(analyzer.error_rate_percent, 2),
        "top_endpoints": analyzer.top_endpoints(),
        "hourly_distribution": analyzer.hourly_distribution(),
        "suspicious_ips": analyzer.suspicious_ips(),
        "error_spikes": [
            {"hour": h, "rate_percent": round(r * 100, 1), "5xx_count": f, "total": t}
            for h, r, f, t in analyzer.error_spikes()
        ],
    }


def print_report(report: dict,elapsed_seconds: float) -> None: 
    line = "=" * 56
    print(line)
    print("log analysis report:")
    print(line)
    print(f"total lines:                {report['total_lines']}")
    print(f"legal parsed lines:    {report['parsed_lines']}")
    print(f"malformed lines:             {report['malformed_lines']}")
    if report["filtered_out_lines"]: 
        print(f"filtered out lines:    {report['filtered_out_lines']}")  
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
    if report["suspicious_ips"]:
        print()
        print("--suspicious ips on/login --")
        for ip, count in report["suspicious_ips"]:
            print(f"  {ip:<20} {count} unsuccesfull try")

    if report["error_spikes"]:
        print()
        print("-- 5x rate percent--")
        for spike in report["error_spikes"]:
            print(
                f"  {spike['hour']}   rate: {spike['rate_percent']}%   "
                f"({spike['5xx_count']}from{spike['total']} reqs)"
            )
        print()    
        print(f"(proccessing time {elapsed_seconds:.2f} s)")


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
    parser.add_argument( #add later
        "--suspicious-threshold", type=int, default=10, metavar="N",
        help="minimum number of 401 errors on /login to flag an IP as suspicious (default: 10)",
    )
   
    parser.add_argument(
        "--error-spike-threshold", type=float, default=0.5, metavar="RATE",
        help="5xx rate threshold to flag as spike (default: 0.5)",
    )

    parser.add_argument(
        "--since", type=str, default=None, metavar="YYYY-MM-DDTHH:MM",
        help="nclude only log entries with a timestamp after this time (UTC format)",
    )

    parser.add_argument(
        "--until", type=str, default=None, metavar="YYYY-MM-DDTHH:MM",
        help="Include only log entries with a timestamp before this time (UTC format)",
    )
    return parser


def main(argv=None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    time_start = parse_cli_time(args.since) if args.since else None
    time_end = parse_cli_time(args.until) if args.until else None


    analyzer = LogAnalyzer(
        top_n=args.top,
        suspicious_401_threshold=args.suspicious_threshold,
        error_spike_threshold=args.error_spike_threshold,
        time_start=time_start,
        time_end=time_end,
    )
    start_time = time.perf_counter()
    try:
        with open_log_file(args.logfile) as f:
            for raw_line in f:
                analyzer.process_line(raw_line)
    except FileNotFoundError:
        print(f"error:couldnt find '{args.logfile}'.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"error while reading the file{exc}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.perf_counter() - start_time    

    report = build_report(analyzer)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report,elapsed)


if __name__ == "__main__":
    main()