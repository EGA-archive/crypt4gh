import sys
assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"

from pathlib import Path
from setuptools import setup, find_packages

_readme = (Path(__file__).parent / "README.md").read_text()

setup(name='crypt4gh',
      version='1.1',
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
          'License :: OSI Approved :: Apache Software License',

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

          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',

          'Programming Language :: Python :: Implementation :: CPython',
      ],
      python_requires='>=3.6',
      # See https://packaging.python.org/discussions/install-requires-vs-requirements/
      install_requires=[
          'pyYaml>=5.1.2',
          'docopt', # include version when needed
          'cryptography>=2.8',
          'pynacl>=1.3.0',
          'bcrypt', # include version when needed
      ],
)
