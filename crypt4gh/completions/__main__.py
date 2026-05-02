#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''This module installs shell completion scripts'''

import sys
from pathlib import Path
import argparse

from .. import __version__, PROG

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

def make_parser():

    description = f'Utility to install Crypt4GH shell completion scripts (version {__version__}).'
    parser = argparse.ArgumentParser(
        prog=f'{PROG}-completions',
        description=description,
    )
    parser.add_argument('-v', '--version',
                        action='version',
                        version=description)

    subparsers = parser.add_subparsers(dest='command')

    # install subcommand
    install = subparsers.add_parser('install',
                                     help='Install completion scripts for a shell.')
    install.add_argument('shell',
                         metavar='<shell>',
                         help='Shell type.')
    install.add_argument('--target',
                         metavar='<dir>',
                         help='Directory to install completions into. '
                              'Defaults to the standard user-local location for the chosen shell.')

    # show subcommand
    show_p = subparsers.add_parser('show',
                                    help='Show what would be installed, or list default locations.')
    show_p.add_argument('shell',
                        nargs='?',
                        metavar='<shell>',
                        help='Shell type. If omitted, lists all known default locations.')

    return parser

def main():

    parser = make_parser()
    args = parser.parse_args(sys.argv[1:])

    if args.command == 'show':
        show(args.shell) if args.shell else show_defaults()
        print()
        return

    if args.command != 'install':
        parser.print_usage(sys.stderr)
        sys.exit(2)

    default_dir, keep_extension = SHELLS.get(args.shell, (None, True))
    dest = Path(args.target).expanduser().resolve() if args.target else default_dir

    if dest is None:
        print(f"  ✗  Unknown shell {args.shell!r} and no --target provided.\n"
              f"     Please specify a target directory with --target <dir>",
              file=sys.stderr)
        sys.exit(1)

    scripts = list(_HERE.glob('*.' + args.shell))
    if not scripts:
        print(f"""\
  ✗  No {args.shell!r} completion scripts are currently shipped with this package.
  If you know how to write completion scripts for {args.shell},
  please contribute with a pull request at:
  https://github.com/EGA-archive/crypt4gh/pulls""", file=sys.stderr)
        sys.exit(1)

    dest.mkdir(parents=True, exist_ok=True)
    print(f"\n  Installing crypt4gh {args.shell} completions → {dest}\n")
    for script in scripts:
        target = dest / (script.name if keep_extension else script.stem)
        target.write_text(script.read_text())
        print(f"    ✔  {script.name} → {target.name}")
    print("\n  Done! You may need to restart your shell or source your rc file for completions to take effect.\n")

if __name__ == "__main__":
    main()
