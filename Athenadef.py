#!/usr/bin/env python3
"""Athena Defense module manager."""

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from athena import cases, doctor
from athena.modules import archive_defense, batch_defense, email_defense, file_defense, office_defense, pdf_defense, yara_defense

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


MODULES = {"pdf": pdf_defense, "file": file_defense, "email": email_defense,
           "archive": archive_defense, "office": office_defense,
           "batch": batch_defense, "yara": yara_defense}


def run_module(name, argv):
    case_id, case_dir = cases.create_case(name)
    started = datetime.now(timezone.utc).isoformat()
    custom_output = any(arg in ("-o", "--output-dir") or arg.startswith("--output-dir=")
                        for arg in argv)
    output_dir = case_dir if not custom_output else None
    if not custom_output:
        argv = [*argv, "-o", str(case_dir)]
    old_case = os.environ.get("ATHENA_CASE_ID")
    os.environ["ATHENA_CASE_ID"] = case_id
    try:
        try:
            code = MODULES[name].main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
        except Exception as exc:
            print(f"Module failed: {exc}", file=sys.stderr)
            code = 1
    finally:
        if old_case is None:
            os.environ.pop("ATHENA_CASE_ID", None)
        else:
            os.environ["ATHENA_CASE_ID"] = old_case
    if output_dir is None:
        for index, arg in enumerate(argv):
            if arg in ("-o", "--output-dir") and index + 1 < len(argv):
                output_dir = Path(argv[index + 1]).expanduser().resolve()
            elif arg.startswith("--output-dir="):
                output_dir = Path(arg.split("=", 1)[1]).expanduser().resolve()
        output_dir = output_dir or case_dir
    if not any(output_dir.glob("*.json")) and code == 0 and output_dir == case_dir:
        case_dir.rmdir()
        return code
    cases.save_manifest(case_id, case_dir, name, started, output_dir, code)
    print(f"Case: {case_id}  |  {case_dir}")
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description="Athena Defense module manager")
    parser.add_argument("--inline", action="store_true", help="Stay in the current terminal")
    parser.add_argument("module", nargs="?", choices=(*MODULES, "doctor", "cases"))
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
    if args.module == "doctor":
        return doctor.main(args.module_args)
    if args.module == "cases":
        return cases.list_cases()
    if args.module:
        return run_module(args.module, args.module_args)
    while True:
        print("Modules\n  1. PDF Defense     — structure, actions, objects, text\n  2. File Defense    — type, signatures, strings, archives\n  3. Email Defense   — headers, attachments, links\n  4. Archive Defense — paths, encryption, compression\n  5. Office Defense  — macros, DDE, external links\n  6. Batch Defense   — bounded directory triage\n  7. YARA Defense    — rule-based offline hunting\n  D. Doctor          — tool and signature health\n  C. Cases           — previous investigations\n  Q. Quit")
        try:
            choice = input("Athenadef> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled")
            return 130
        if choice in ("1", "2", "3", "4", "5", "6", "7"):
            name = ("pdf", "file", "email", "archive", "office", "batch", "yara")[int(choice) - 1]
            run_module(name, [])
            print()
            continue
        if choice == "d":
            doctor.main()
            continue
        if choice == "c":
            cases.list_cases()
            continue
        if choice == "q":
            return 0
        print("Choose 1-7, D, C or Q.\n")


if __name__ == "__main__":
    raise SystemExit(main())

