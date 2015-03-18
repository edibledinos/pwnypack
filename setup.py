from setuptools import setup, find_packages
import os


README = 'Dino Penetration Framework'
CHANGES = 'Always in flux, everything is different'
REQUIRES = [
]


try:
    import enum
except ImportError:
    REQUIRES.append('enum34')


setup(
    name='dpf',
    version='0.0.0',
    description='Dino Penetration Framework',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Programming Language :: Python",
    ],
    author='Ingmar Steen',
    author_email='iksteen@gmail.com',
    url='https://github.com/iksteen/dpf/',
    keywords='wargame ctf',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIRES,
)

