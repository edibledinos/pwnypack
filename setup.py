from setuptools import setup
import sys
import os


__version__ = '0.5.2'


requires = [
    'six',
    'nose',
    'IPython',
]


if sys.version_info[:2] < (3, 4):
    requires.append('enum34')


def read_file(filename):
    try:
        with open(os.path.join(os.path.dirname(__file__), filename)) as f:
            return f.read()
    except IOError:
        return ''


setup(
    name='pwnypack',
    packages=['pwny', 'pwnypack'],
    version=__version__,
    description='Official Certified Edible Dinosaurs CTF toolkit.',
    long_description=read_file('README.rst'),
    author='Ingmar Steen',
    author_email='iksteen@gmail.com',
    url='https://github.com/iksteen/pwnypack/',
    download_url='https://github.com/iksteen/pwnypack/tarball/v%s' % __version__,
    install_requires=requires,
    tests_require=['mock', 'coverage'],
    entry_points={
        'console_scripts': [
            'pwny=pwnypack.main:main',
        ],
    },
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
