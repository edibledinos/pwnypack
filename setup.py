from setuptools import setup, find_packages
import os


README = ''
REQUIRES = [
]


try:
    import enum
except ImportError:
    REQUIRES.append('enum34')


setup(
    name='pwnypack',
    version='0.0.0',
    description='Official CTF toolkit for Certified Edible Dinosaurs.',
    long_description=README,
    classifiers=[
        "Programming Language :: Python",
    ],
    author='Ingmar Steen',
    author_email='iksteen@gmail.com',
    url='https://github.com/iksteen/pwnypack/',
    keywords='wargame ctf',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIRES,
)
