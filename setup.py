import os
import sys
from setuptools import setup

assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"

from crypt4gh import __version__, __author__, __title__, __doc__ as crypt4gh_doc, __license__, PROG

here = os.path.dirname(__file__)
with open(os.path.join(here, 'requirements.txt')) as f:
    packages = f.readlines()

setup(name='crypt4gh',
      version=__version__,
      url='https://www.github.com/EGA-archive/crypt4gh',
      license=__license__,
      author=__author__,
      #author_email='frederic.haziza@crg.eu',
      description=__title__,
      long_description=crypt4gh_doc,
      packages=['crypt4gh'],
      include_package_data=False,
      package_data={ 'crypt4gh': ['completions'] },
      zip_safe=False,
      entry_points={
          'console_scripts': [
              f'{PROG}=crypt4gh.__main__:main',
              f'{PROG}-keygen=crypt4gh.keys:main',
              f'{PROG}-debug=crypt4gh.debug:main',
          ]
      },
      platforms = 'any',
      python_requires='>=3.6',
      install_requires=packages,
)
