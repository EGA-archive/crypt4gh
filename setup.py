import sys
import os
assert sys.version_info >= (3, 9), "crypt4gh requires python 3.9 or higher"
import subprocess
from pathlib import Path
import shutil

from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext
from distutils.command.clean import clean

_here = Path(__file__).parent

# Check for SODIUM_INSTALL environment variable
use_system_sodium = os.environ.get('SODIUM_INSTALL') == 'system'

include_dirs=[]
library_dirs=[]
libraries=[]
extra_compile_args = []
extra_link_args = []

if not use_system_sodium:
    # Path to libsodium
    LIBSODIUM = _here / 'libsodium-stable'
    # Path to the built libsodium library
    LIBSODIUM_BUILD = _here / 'libsodium-build'

    include_dirs=[str(LIBSODIUM_BUILD / 'include')]
    library_dirs=[str(LIBSODIUM_BUILD / 'lib')]
    libraries=['sodium']
    if sys.platform == "darwin":
        extra_compile_args = ['-fPIC','-dead_strip']
        extra_link_args = ['-fPIC','-dead_strip', '-Xlinker', '-dead_strip_dylibs']
    else:
        extra_compile_args = ['-fPIC', '-ffunction-sections', '-fdata-sections']
        extra_link_args = ['-fPIC', '-Wl,--as-needed', '-Wl,--gc-sections']
        # on linux, gc-sections is too conservative and keeps more than needed 
        # the final C-extension will likely be bigger than needed: ¯\_(ツ)_/¯
        # On macos, the linker is more aggressive and makes a smaller shared object

class BuildLibsodium(build_ext):
    def run(self):

        if use_system_sodium:
            print('''\
Skipping build, using system-installed libsodium.
CFLAGS and LDFLAGS may be needed.
''')
            return super().run()

        print("Bundling libsodium from libsodium-stable.")
        # Configure and build libsodium
        cmd = ['./configure',
               '--prefix', str(LIBSODIUM_BUILD),
               '--enable-minimal',
               '--enable-opt', # since we install it on the machine
               '--disable-shared',
               '--enable-static',
               '--enable-pic',
               ]
        if not (LIBSODIUM / 'config.status').exists():
            subprocess.check_call(cmd, cwd=LIBSODIUM)
        subprocess.check_call(['make'], cwd=LIBSODIUM)
        #subprocess.check_call(['make', 'check'], cwd=str(LIBSODIUM))

        # copy to LIBSODIUM_BUILD/{include,lib}
        # so it's easier in the Extension block
        subprocess.check_call(['make', 'install'], cwd=LIBSODIUM)

        super().run()

class CleanLibsodium(clean):
    description = 'remove libsodium-build and crypt4gh/libs directories'
    def run(self):
        super().run()

        if use_system_sodium:
            return

        print('Removing', LIBSODIUM_BUILD)
        shutil.rmtree(LIBSODIUM_BUILD, ignore_errors=True)

        if (LIBSODIUM / 'Makefile').exists():
            print('Cleaning up', LIBSODIUM)
            subprocess.check_call(['make', 'distclean'], cwd=str(LIBSODIUM))



setup(name='crypt4gh',
      version='1.8',
      url='https://www.github.com/EGA-archive/crypt4gh',
      license='Apache License 2.0',
      author='Frédéric Haziza',
      author_email='frederic.haziza@crg.eu',
      description='GA4GH cryptographic utilities',
      long_description=(_here / 'README.md').read_text(),
      long_description_content_type='text/markdown',
      packages=find_packages(),
      include_package_data=True,
      package_data={
          'crypt4gh': ['completions'],
      },
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
      python_requires='>=3.9',
      # See https://packaging.python.org/discussions/install-requires-vs-requirements/
      install_requires=[
          'docopt-ng', # include version when needed
          'cryptography>=2.8',
          'bcrypt', # include version when needed
          'setuptools', # include version when needed
      ],
      cmdclass={
          'build_ext': BuildLibsodium,
          'clean': CleanLibsodium,
      },
      ext_modules=[
          Extension(
              'crypt4gh.sodium',
              sources = ['crypt4gh/sodium.c'],
              include_dirs = include_dirs,
              library_dirs = library_dirs,
              libraries = libraries,
              extra_compile_args=extra_compile_args,
              extra_link_args = extra_link_args
          )
      ],
)
