from setuptools import setup
import sys


__version__ = '0.5.1'


requires = [
    'six',
    'nose',
]


if sys.version_info[:2] < (3, 4):
    requires.append('enum34')


setup(
    name='pwnypack',
    packages=['pwny', 'pwnypack'],
    version=__version__,
    description='Official Certified Edible Dinosaurs CTF toolkit.',
    author='Ingmar Steen',
    author_email='iksteen@gmail.com',
    url='https://github.com/iksteen/pwnypack/',
    download_url='https://github.com/iksteen/pwnypack/tarball/v%s' % __version__,
    install_requires=requires,
    tests_require=['mock', 'coverage'],
    keywords=['wargame', 'ctf'],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],
)
