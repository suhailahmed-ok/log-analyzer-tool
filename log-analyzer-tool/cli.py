#!/usr/bin/env python3
"""Terminal mode: pipe journalctl into it and it explains what happened in plain English.

  journalctl --since "1 day ago" | python3 cli.py       summary of the last day
  journalctl -f | python3 cli.py                         live, in plain English
"""
import argparse
import sys
import textwrap

from rules import Analyzer

RESET = "\033[0m"
STYLE = {"info": ("\033[36m", "i"), "normal": ("\033[90m", "~"),
         "check": ("\033[33m", "!"), "problem": ("\033[1;31m", "X"),
         "hidden": ("\033[90m", ".")}
WIDTH = 78

NORMAL_WHY = ("These programs exited with an error while the desktop was closing a session "
              "(logging in, logging out or shutting down). That happens a lot and is harmless.")


def wrap(text, indent, first=None, hang=None):
    """Wrap text; `first` is the first-line prefix, `hang` the prefix for later lines."""
    return textwrap.fill(text, width=WIDTH, initial_indent=first if first is not None else indent,
                         subsequent_indent=hang if hang is not None else indent)


def show_event(e):
    color, icon = STYLE[e["level"]]
    print(f"{color}[{icon}]{RESET} {e['time']:<15} {e['text']}", flush=True)


def print_report(r, tips=True):
    bar = "=" * 62
    print(f"\n{bar}\n LOGSCOPE: WHAT HAPPENED, IN PLAIN ENGLISH\n{bar}")
    v = r["verdict"]
    color = {"ok": "\033[32m", "check": "\033[33m", "problem": "\033[1;31m"}[v["level"]]
    s = r["span"]
    if s["from"]:
        print(f" Covers {s['from']} to {s['to']} ({s['lines']} log lines)")
    print(f"\n {color}{v['text']}{RESET}")

    print("\n WHAT HAPPENED")
    for line in r["happened"]:
        print(wrap(line, "", first="  - ", hang="    "))

    if r["normal"]:
        print("\n LOOKED SCARY, BUT NORMAL")
        for n in r["normal"]:
            print(wrap(n["title"], "", first="  - ", hang="    "))
            if n["why"]:
                print(wrap(n["why"], "      "))
        print(wrap(NORMAL_WHY, "   "))
        print("   Nothing to do.")

    if r["attention"]:
        print("\n WORTH A LOOK")
        for a in r["attention"]:
            color, icon = STYLE[a["level"]]
            print(f"\n  {color}[{icon}] {a['title']}{RESET}")
            print(wrap(a["explain"], "      "))
            if tips and a["commands"]:
                print("      You can run these to find out more (nothing runs automatically):")
                for cmd in a["commands"]:
                    print(f"        $ {cmd['cmd']}")
                    print(wrap(cmd["why"], "", first="            -> ", hang="               "))
    print()


def main():
    ap = argparse.ArgumentParser(prog="logscope")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="no live lines, only the final summary")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also show every service start/stop")
    ap.add_argument("-b", "--brute", type=int, default=5,
                    help="failed logins from one address to count as an attack")
    ap.add_argument("--no-tips", action="store_true", help="hide the 'you can run' commands")
    args = ap.parse_args()

    a = Analyzer(brute=args.brute)
    try:
        for line in sys.stdin:
            e = a.feed(line)
            if e and not args.quiet and (e["level"] != "hidden" or args.verbose):
                show_event(e)
    except KeyboardInterrupt:
        pass
    print_report(a.report(), tips=not args.no_tips)


if __name__ == "__main__":
    main()