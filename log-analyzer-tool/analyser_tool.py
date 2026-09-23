import argparse
import subprocess
import re
import csv
import os
from datetime import datetime

# ─────────────────────────────────────────────
#  PATTERNS
# ─────────────────────────────────────────────

STANDARD_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)'
)

FALLBACK_PATTERN = re.compile(
    r'\b(ERROR|WARNING|WARN|INFO|DEBUG|CRITICAL)\b', re.IGNORECASE
)

# ─────────────────────────────────────────────
#  PARSING FUNCTIONS
# ─────────────────────────────────────────────

def parse_line(line):
    line = line.strip()
    if not line:
        return None

    match = STANDARD_PATTERN.match(line)
    if match:
        return {
            "timestamp": match.group(1),
            "level": match.group(2).upper(),
            "message": match.group(3).strip(),
            "raw": line
        }

    fallback = FALLBACK_PATTERN.search(line)
    level = fallback.group(1).upper() if fallback else "UNKNOWN"
    if level == "WARN":
        level = "WARNING"
    return {
        "timestamp": None,
        "level": level,
        "message": line,
        "raw": line
    }


def read_logs(filepath):
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: '{filepath}'")
        exit(1)

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    parsed = [parse_line(line) for line in lines]
    return [p for p in parsed if p is not None]


def filter_by_level(logs, level):
    return [log for log in logs if log["level"] == level.upper()]


def filter_by_keyword(logs, keyword):
    return [log for log in logs if keyword.lower() in log["raw"].lower()]


def filter_by_date(logs, from_date, to_date):
    result = []
    for log in logs:
        if log["timestamp"] is None:
            continue
        try:
            log_date = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            if from_date and log_date < from_date:
                continue
            if to_date and log_date > to_date:
                continue
            result.append(log)
        except ValueError:
            continue
    return result

# ─────────────────────────────────────────────
#  DISPLAY FUNCTIONS
# ─────────────────────────────────────────────

COLORS = {
    "ERROR":    "\033[91m",
    "CRITICAL": "\033[91m",
    "WARNING":  "\033[93m",
    "INFO":     "\033[92m",
    "DEBUG":    "\033[94m",
    "UNKNOWN":  "\033[97m",
    "RESET":    "\033[0m"
}


def colorize(level, text):
    color = COLORS.get(level, COLORS["RESET"])
    return f"{color}{text}{COLORS['RESET']}"


def print_logs(logs, limit=None):
    if not logs:
        print("  No matching logs found.")
        return
    display = logs[:limit] if limit else logs
    for log in display:
        level_str = f"[{log['level']:<8}]"
        ts = log["timestamp"] or "no-timestamp    "
        print(f"  {colorize(log['level'], level_str)}  {ts}  {log['message']}")
    if limit and len(logs) > limit:
        print(f"\n  ... and {len(logs) - limit} more. Use --export to see all.")


def print_summary(logs):
    total = len(logs)
    levels = {}
    for log in logs:
        levels[log["level"]] = levels.get(log["level"], 0) + 1

    print("\n" + "─" * 45)
    print("  LOG SUMMARY")
    print("─" * 45)
    print(f"  {'Total lines':<20}: {total}")
    for level, count in sorted(levels.items()):
        bar = "█" * min(count, 30)
        print(f"  {level:<20}: {count:<6} {colorize(level, bar)}")
    print("─" * 45 + "\n")

# ─────────────────────────────────────────────
#  EXPORT FUNCTION
# ─────────────────────────────────────────────

def export_to_csv(logs, output_path):
    if not logs:
        print("  Nothing to export.")
        return
    with open(output_path, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "level", "message", "raw"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)
    print(f"  Exported {len(logs)} log(s) to '{output_path}'")

# ─────────────────────────────────────────────
#  MAIN — only runs when called directly
# ─────────────────────────────────────────────

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Log Analyser Tool — Parse, filter, and export log files.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 analyser_tool.py --file app.log --summary
  python3 analyser_tool.py --file app.log --errors
  python3 analyser_tool.py --file app.log --warnings
  python3 analyser_tool.py --file app.log --search "database"
  python3 analyser_tool.py --file app.log --level CRITICAL
  python3 analyser_tool.py --file app.log --from 2024-01-01 --to 2024-01-31
  python3 analyser_tool.py --file app.log --errors --export results.csv
  python3 analyser_tool.py --list
  python3 analyser_tool.py --run "ls"
        """
    )

    parser.add_argument("--file", metavar="PATH", help="Path to the log file")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--errors",   action="store_true", help="Show ERROR logs")
    group.add_argument("--warnings", action="store_true", help="Show WARNING logs")
    group.add_argument("--summary",  action="store_true", help="Show summary of all log levels")
    group.add_argument("--search",   metavar="KEYWORD",   help="Search logs by keyword")
    group.add_argument("--level",    metavar="LEVEL",     help="Filter by any level (e.g. DEBUG, INFO, CRITICAL)")
    group.add_argument("--list",     action="store_true", help="List files in current directory")
    group.add_argument("--run",      metavar="COMMAND",   help="Run a shell command and show output")

    parser.add_argument("--from",   dest="from_date", metavar="YYYY-MM-DD", help="Show logs from this date")
    parser.add_argument("--to",     dest="to_date",   metavar="YYYY-MM-DD", help="Show logs up to this date")
    parser.add_argument("--limit",  metavar="N", type=int,                  help="Limit number of results shown")
    parser.add_argument("--export", metavar="OUTPUT.csv",                   help="Export results to a CSV file")

    args = parser.parse_args()

    try:

        if args.list:
            pwd = subprocess.run(["pwd"], capture_output=True, text=True)
            ls  = subprocess.run(["ls", "-lh"], capture_output=True, text=True)
            print(f"\n  Current directory: {pwd.stdout.strip()}\n")
            if ls.returncode == 0:
                for line in ls.stdout.strip().split("\n"):
                    print(f"  {line}")
            else:
                print(f"  [ERROR] {ls.stderr.strip()}")
            print()

        elif args.run:
            command = args.run.split()
            print(f"\n  Running: {' '.join(command)}\n")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print("  Output:")
                for line in result.stdout.strip().split("\n"):
                    print(f"    {line}")
                print("\n  Status: Success\n")
            else:
                print("  Error:")
                for line in result.stderr.strip().split("\n"):
                    print(f"    {line}")
                print("\n  Status: Failed\n")

        else:
            if not args.file:
                parser.print_help()
                print("\n[ERROR] Please provide --file <path>")
                exit(1)

            logs = read_logs(args.file)
            results = logs

            from_date = datetime.strptime(args.from_date, "%Y-%m-%d") if args.from_date else None
            to_date   = datetime.strptime(args.to_date,   "%Y-%m-%d") if args.to_date   else None
            if from_date or to_date:
                results = filter_by_date(results, from_date, to_date)

            if args.summary:
                print_summary(results)

            elif args.errors:
                results = filter_by_level(results, "ERROR")
                print(f"\n  Found {len(results)} ERROR log(s):\n")
                print_logs(results, limit=args.limit)
                print()

            elif args.warnings:
                results = filter_by_level(results, "WARNING")
                print(f"\n  Found {len(results)} WARNING log(s):\n")
                print_logs(results, limit=args.limit)
                print()

            elif args.search:
                results = filter_by_keyword(results, args.search)
                print(f"\n  Found {len(results)} log(s) matching '{args.search}':\n")
                print_logs(results, limit=args.limit)
                print()

            elif args.level:
                results = filter_by_level(results, args.level)
                print(f"\n  Found {len(results)} {args.level.upper()} log(s):\n")
                print_logs(results, limit=args.limit)
                print()

            else:
                print_summary(results)

            if args.export:
                export_to_csv(results, args.export)

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user. Exiting.\n")
    except Exception as e:
        print(f"\n  [ERROR] Unexpected error: {e}\n")