import sys
assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"

from setuptools import setup

setup(name='crypt4gh',
      version=1,
      url='https://www.github.com/EGA-archive/crypt4gh',
      license='Apache License 2.0',
      author='Frédéric Haziza <frederic.haziza@crg.eu>',
      description='GA4GH cryptographic utilities',
      long_description="""The crypt4gh package is an implementation to handle the GA4GH cryptographic file format.""",
      packages=['crypt4gh'],
      include_package_data=False,
      package_data={ 'crypt4gh': ['completions'] },
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'crypt4gh=crypt4gh.__main__:main',
              'crypt4gh-keygen=crypt4gh.keys:main',
              'crypt4gh-debug=crypt4gh.debug:main',
          ]
      },
      platforms = 'any',
      python_requires='>=3.6',
      # See https://packaging.python.org/discussions/install-requires-vs-requirements/
      install_requires=[ # Should add >=x.y.z for all
          'pyYaml',
          'docopt',
          'cryptography',
          'pynacl',
          'bcrypt',
      ],
)
