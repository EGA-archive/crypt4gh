from setuptools import setup
from legacryptor import __version__, __author__, __title__, __doc__ as lega_doc, __license__

setup(name='legacryptor',
      version=__version__,
      url='https://www.github.com/ega-archive/LocalEGA-cryptor',
      license=__license__,
      author=__author__,
      #author_email='frederic.haziza@crg.eu',
      description=__title__,
      long_description=lega_doc,
      packages=['legacryptor'],
      include_package_data=False,
      package_data={ 'legacryptor': ['completion.bash'] },
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'lega-cryptor = legacryptor.__main__:main',
          ]
      },
      platforms = 'any',
      install_requires=[
          'cryptography',
          'pyYaml',
          'ed25519',
          'pynacl',
          'docopt',
      ],
)          
