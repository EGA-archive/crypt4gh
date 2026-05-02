#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''This module install shell completion scripts'''

import argparse
import sys
from pathlib import Path

_HERE = Path(__file__).parent

SHELLS = {
    #
    # Shell => (default location, keep_extension)
    #
    "bash": (Path.home() / ".local/share/bash-completion/completions", False),
    "zsh":  (Path.home() / ".zsh/completions",                         False),
    "fish": (Path.home() / ".config/fish/completions",                 True),
    "ksh":  (Path.home() / ".ksh/completions",                         True),
    "tcsh": (Path.home() / ".tcsh/completions",                        True),
    "csh":  (Path.home() / ".csh/completions",                         True),
    "sh":   (Path.home() / ".sh/completions",                          True),
}
def main():
    parser = argparse.ArgumentParser(
        prog="crypt4gh-install-completions",
        description="Install crypt4gh shell completion scripts.",
    )
    parser.add_argument(
        "shell",
        choices=SHELLS.keys(),
        metavar="shell",
        help=f"Shell type. Supported: {', '.join(SHELLS)}",
    )
    parser.add_argument(
        "target_dir",
        nargs="?",
        default=None,
        help="Directory to install completions into (defaults to the standard user-local location for the chosen shell)",
    )

    args = parser.parse_args()

    default_dir, keep_extension = SHELLS[args.shell] # No KeyError, thanks to parser choice
    dest = Path(args.target_dir).expanduser().resolve() if args.target_dir else default_dir
    scripts = list(_HERE.glob('*.' + args.shell)) # gen => list, so we can "if not list"

    if not scripts:
        print(f"""\
  ✗  No {args.shell} completion scripts are currently shipped with this package.

  contributed to the project.
  If you know how to write completion scripts for {args.shell},
  please contribute with a pull request at:
  https://github.com/EGA-archive/crypt4gh/pulls""", file=sys.stderr)
        sys.exit(1)

    dest.mkdir(parents=True, exist_ok=True)

    print(f'\n  Installing crypt4gh {args.shell} completions → {dest}\n')
    for script in scripts:
        target = dest / (script.name if keep_extension else script.stem)
        target.write_text(script.read_text()) # copy content
        print(f"    ✔  {script}")

    print(f"\n  Done! You may need to restart your shell or source your rc file for completions to take effect.\n")

if __name__ == "__main__":
    main()
