#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''This module install shell completion scripts'''

import argparse
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


supported_shells = 'Supported shells and default target locations:'
for k, (d,_) in SHELLS.items():
    supported_shells += f'\n\t{k:>5}: {d}'
# inefficient but working

__doc__ = f'''
 
Utility to install Crypt4GH shell completion scripts.

Usage:
   {PROG}-install-completions [-hv] <shell> [--target <dir>]

Arguments:
  <shell>       Shell type. Supported: bash, zsh, fish, ksh, tcsh, csh, sh

Options:
   -h, --help        Prints this help and exit
   -v, --version     Prints the version and exits
   --target <dir>    Directory to install completions into.
                     Defaults to the standard user-local location for the chosen shell (see below).

{supported_shells}

'''

def main():
    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, sys.argv[1:], version=version)

    shell = args['<shell>']
    if shell not in SHELLS: # keys
        print(f"  ✗  Unsupported shell {shell!r}. Choose from: {', '.join(SHELLS)}",
              file=sys.stderr)
        sys.exit(1)

    default_dir, keep_extension = SHELLS[shell]

    target_dir = args['--target']
    dest = Path(target_dir).expanduser().resolve() if target_dir else default_dir

    scripts = list(_HERE.glob('*.' + shell)) # gen => list, so we can "if not list"

    if not scripts:
        print(f"""\
  ✗  No {shell} completion scripts are currently shipped with this package.

  contributed to the project.
  If you know how to write completion scripts for {shell},
  please contribute with a pull request at:
  https://github.com/EGA-archive/crypt4gh/pulls""", file=sys.stderr)
        sys.exit(1)

    dest.mkdir(parents=True, exist_ok=True)

    print(f"\n  Installing crypt4gh {shell} completions → {dest}\n")
    for script in scripts:
        target = dest / (script.name if keep_extension else script.stem)
        target.write_text(script.read_text()) # copy content
        print(f"    ✔  {script}")

    print(f"\n  Done! You may need to restart your shell or source your rc file for completions to take effect.\n")

if __name__ == "__main__":
    main()
