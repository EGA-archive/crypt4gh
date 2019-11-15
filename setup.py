import sys
assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"

from setuptools import setup

from crypt4gh import (__title__,
                      __version__,
                      __author__,
                      __author_email__,
                      __license__,
                      __doc__ as crypt4gh_doc,
                      PROG)

setup(name='crypt4gh',
      version=__version__,
      url='https://www.github.com/EGA-archive/crypt4gh',
      license=__license__,
      author=__author__,
      author_email=__author_email__,
      description=__title__,
      long_description=crypt4gh_doc,
      packages=['crypt4gh', 'crypt4gh.keys'],
      include_package_data=False,
      package_data={ 'crypt4gh': ['completions'] },
      zip_safe=False,
      entry_points={
          'console_scripts': [
              f'{PROG}=crypt4gh.__main__:main',
              f'{PROG}-keygen=crypt4gh.keys.__init__:main',
          ]
      },
      platforms = 'any',
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
