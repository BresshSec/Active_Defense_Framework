#!/usr/bin/env python3
"""Athena Defense module manager."""

import argparse
import os
import sys

from athena.modules import file_defense, pdf_defense

BLUE = "\033[34m"
RESET = "\033[0m"
BANNER = r"""
    _   _   _                            ____        __
   / \ | |_| |__   ___ _ __   __ _       |  _ \  ___ / _| ___ _ __  ___  ___
  / _ \| __| '_ \ / _ \ '_ \ / _` |      | | | |/ _ \ |_ / _ \ '_ \/ __|/ _ \
 / ___ \ |_| | | |  __/ | | | (_| |      | |_| |  __/  _|  __/ | | \__ \  __/
/_/   \_\__|_| |_|\___|_| |_|\__,_|      |____/ \___|_|  \___|_| |_|___/\___|
"""
CAPTION = "Inspect locally. Hunt deliberately. Defend with evidence."


def show_banner():
    color = BLUE if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else ""
    print(color + BANNER + RESET)
    print("  " + CAPTION + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Athena Defense module manager")
    parser.add_argument("module", nargs="?", choices=("pdf", "file"))
    parser.add_argument("module_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    show_banner()
    if args.module == "pdf":
        return pdf_defense.main(args.module_args)
    if args.module == "file":
        return file_defense.main(args.module_args)
    while True:
        print("Modules\n  1. PDF Defense  — structure, actions, objects, text\n  2. File Defense — type, signatures, strings, archives\n  Q. Quit")
        try:
            choice = input("Athenadef> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled")
            return 130
        if choice == "1":
            return pdf_defense.main([])
        if choice == "2":
            return file_defense.main([])
        if choice == "q":
            return 0
        print("Choose 1, 2 or Q.\n")


if __name__ == "__main__":
    raise SystemExit(main())

