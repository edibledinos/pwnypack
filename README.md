# pwnypack

The official _Certified Edible Dinosaurs_ CTF toolkit. *pwnypack* attempts to provide a toolset which can be used to more easily develop CTF solutions.

[![Build Status](https://travis-ci.org/edibledinos/pwnypack.svg?branch=travis-ci)](https://travis-ci.org/edibledinos/pwnypack)

## Motivation

After seeing the excellent [pwntools](https://github.com/Gallopsled/pwntools) by Gallopsled, I got interested in building my own CTF toolkit. _pwntools_ is much more complete so you should probably use that. *pwnypack* was created mostly out of curiosity.

## Installation

To install the latest released version of pwnypack, use:

```bash
$ pip install pwnypack
```

## Usage

To import all of *pwnypack* into your global namespace, use:

```python
>>> from pwny import *
```

Or, if you're using python 2.7+ or python 3.3+, try the customized IPython shell:

```bash
$ pwny shell
```

I promise that effort will be put into not exposing unnecessary stuff and thus overly polluting your global namespace.

For an example, check out the [Big Prison Fence](https://github.com/iksteen/pwnypack/wiki/Big-Prison-Fence) example in the wiki.

## Documentation

*pwnypack*'s API documentation is hosted on [readthedocs](http://pwnypack.readthedocs.org/).

## Contributors

Just me for now. If you want to contribute, feel free to fork & create a pull request on GitHub.

## License

*pwnypack* is distributed under the MIT license.
