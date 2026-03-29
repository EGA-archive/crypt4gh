import sys
assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"
import subprocess
from pathlib import Path

from setuptools import setup, find_packages, Extension

_readme = (Path(__file__).parent / "README.md").read_text()

def pkg_config(*args):
    try:
        cmd = 'pkg-config ' + ' '.join(args)
        output = subprocess.check_output(cmd,
                                         shell=True,
                                         stderr=subprocess.STDOUT)
        return output.decode().strip().split()
    except subprocess.CalledProcessError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

setup(name='crypt4gh',
      version='1.8',
      url='https://www.github.com/EGA-archive/crypt4gh',
      license='Apache License 2.0',
      author='Frédéric Haziza',
      author_email='frederic.haziza@crg.eu',
      description='GA4GH cryptographic utilities',
      long_description=_readme,
      long_description_content_type="text/markdown",
      packages=find_packages(),
      include_package_data=True,
      package_data={ 'crypt4gh': ['completions'] },
      zip_safe=False,
      entry_points={
          'console_scripts': [
              f'crypt4gh=crypt4gh.__main__:main',
              f'crypt4gh-keygen=crypt4gh.keys.__init__:main',
          ]
      },
      platforms='any',
      classifiers=[  # Optional
          'Development Status :: 5 - Production/Stable',

          'Natural Language :: English',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX',
          'Operating System :: POSIX :: BSD',
          'Operating System :: POSIX :: Linux',
          # 'Operating System :: Microsoft :: Windows,

          'Intended Audience :: Developers',
          'Intended Audience :: Healthcare Industry',
          'Intended Audience :: Information Technology',
          'Topic :: Security :: Cryptography',
          'Topic :: Scientific/Engineering :: Bio-Informatics',

          'Programming Language :: Python :: Implementation :: CPython',
      ],
      python_requires='>=3.6',
      # See https://packaging.python.org/discussions/install-requires-vs-requirements/
      install_requires=[
          'pyYaml>=5.1.2',
          'docopt-ng', # include version when needed
          'cryptography>=2.8',
          'bcrypt', # include version when needed
      ],
      ext_modules=[
          Extension('crypt4gh.sodium',
                    sources=['crypt4gh/sodium.c'],
                    description='Python C extension for libsodium used by Crypt4GH',
                    extra_compile_args=pkg_config("--cflags", "libsodium"),
                    extra_link_args=pkg_config("--libs", "libsodium"),
                    )
      ],
)
