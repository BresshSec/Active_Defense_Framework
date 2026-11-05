#!/usr/bin/env python3
"""Athena Defense module manager."""

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from athena.modules import archive_defense, batch_defense, email_defense, file_defense, office_defense, pdf_defense

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
    parser.add_argument("--inline", action="store_true", help="Stay in the current terminal")
    parser.add_argument("module", nargs="?", choices=("pdf", "file", "email", "archive", "office", "batch"))
    parser.add_argument("module_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.inline and not os.environ.get("ATHENA_CHILD") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        terminal = shutil.which("xfce4-terminal")
        if terminal:
            child_args = [sys.executable, str(Path(__file__).resolve()), "--inline"]
            if args.module:
                child_args += [args.module, *args.module_args]
            try:
                subprocess.Popen([terminal, "--maximize", "--hold", "--title=Athena Defense",
                                  "--command=" + shlex.join(child_args)],
                                 env={**os.environ, "ATHENA_CHILD": "1"}, cwd=os.getcwd(),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                print("Athena Defense opened in a new maximized terminal window.")
                return 0
            except OSError as exc:
                print(f"Could not open a new window ({exc}); continuing here.", file=sys.stderr)
    show_banner()
    modules = {"pdf": pdf_defense, "file": file_defense,
               "email": email_defense, "archive": archive_defense,
               "office": office_defense, "batch": batch_defense}
    if args.module:
        return modules[args.module].main(args.module_args)
    while True:
        print("Modules\n  1. PDF Defense     — structure, actions, objects, text\n  2. File Defense    — type, signatures, strings, archives\n  3. Email Defense   — headers, attachments, links\n  4. Archive Defense — paths, encryption, compression\n  5. Office Defense  — macros, DDE, external links\n  6. Batch Defense   — bounded directory triage\n  Q. Quit")
        try:
            choice = input("Athenadef> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled")
            return 130
        if choice in ("1", "2", "3", "4", "5", "6"):
            module = (pdf_defense, file_defense, email_defense, archive_defense, office_defense, batch_defense)[int(choice) - 1]
            module.main([])
            print()
            continue
        if choice == "q":
            return 0
        print("Choose 1-6 or Q.\n")


if __name__ == "__main__":
    raise SystemExit(main())

