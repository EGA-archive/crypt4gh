#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''This module installs shell completion scripts'''

import sys
from pathlib import Path

from docopt import docopt

from .. import __title__, __version__, PROG

_HERE = Path(__file__).parent
_HOME = Path.home()

SHELLS = {
    #
    # Shell => (default location, keep_extension)
    #
    'bash': (_HOME / '.local/share/bash-completion/completions', False),
    'zsh':  (_HOME / '.zsh/completions',                         False),
    'fish': (_HOME / '.config/fish/completions',                 True),
    'ksh':  (_HOME / '.ksh/completions',                         True),
    'tcsh': (_HOME / '.tcsh/completions',                        True),
    'csh':  (_HOME / '.csh/completions',                         True),
    'sh':   (_HOME / '.sh/completions',                          True),
}

__doc__ = f'''
Utility to install Crypt4GH shell completion scripts.

Usage:
   {PROG}-install-completions [-hv] <shell> [--target <dir>]
   {PROG}-install-completions [-hv] --show [<shell>]

Arguments:
  <shell>       Shell type.

Options:
   -h, --help        Prints this help and exit
   -v, --version     Prints the version and exits
   --show            Show what would be installed, or list default locations if no shell is given.
   --target <dir>    Directory to install completions into.
                     Defaults to the standard user-local location for the chosen shell (see below).
'''

def show_defaults():
    headers = ('Shell', 'Default location', 'Scripts')
    rows = []
    for k, (d, _) in SHELLS.items():
        scripts = list(_HERE.glob(f'*.{k}'))
        status = ', '.join(s.name for s in scripts) if scripts else '(none shipped)'
        rows.append((k, str(d), status))

    col_widths = [
        max(len(h), max(len(r[i]) for r in rows))
        for i, h in enumerate(headers)
    ]

    def fmt(row):
        return '  | ' + ' | '.join(f'{cell:<{col_widths[i]}}' for i, cell in enumerate(row)) + ' |'

    sep = '  |-' + '-|-'.join('-' * w for w in col_widths) + '-|'

    print()
    print(fmt(headers))
    print(sep)
    for row in rows:
        print(fmt(row))

def show(shell):
    default_dir, _ = SHELLS.get(shell, (None, True))
    scripts = list(_HERE.glob(f'*.{shell}'))
    print(f"\n  Shell:    {shell}")
    print(f"  Default:  {default_dir or '(unknown shell, use --target)'}")
    if scripts:
        print(f"  Scripts to install:")
        for s in scripts:
            print(f"    ✔  {s.name}")
    else:
        print(f"  ✗  No scripts shipped for {shell!r}")

def main():
    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, sys.argv[1:], version=version)

    shell = args['<shell>']

    if args['--show']:
        show(shell) if shell else show_defaults()
        print()
        return

    default_dir, keep_extension = SHELLS.get(shell, (None, True))
    target_dir = args['--target']
    dest = Path(target_dir).expanduser().resolve() if target_dir else default_dir

    if dest is None:
        print(f"  ✗  Unknown shell {shell!r} and no --target provided.\n"
              f"     Please specify a target directory with --target <dir>",
              file=sys.stderr)
        sys.exit(1)

    scripts = list(_HERE.glob('*.' + shell))
    if not scripts:
        print(f"""\
  ✗  No {shell!r} completion scripts are currently shipped with this package.
  If you know how to write completion scripts for {shell},
  please contribute with a pull request at:
  https://github.com/EGA-archive/crypt4gh/pulls""", file=sys.stderr)
        sys.exit(1)

    dest.mkdir(parents=True, exist_ok=True)
    print(f"\n  Installing crypt4gh {shell} completions → {dest}\n")
    for script in scripts:
        target = dest / (script.name if keep_extension else script.stem)
        target.write_text(script.read_text())
        print(f"    ✔  {script.name} → {target.name}")
    print("\n  Done! You may need to restart your shell or source your rc file for completions to take effect.\n")

if __name__ == "__main__":
    main()
