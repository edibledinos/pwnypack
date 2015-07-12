pwnypack
========

The official *Certified Edible Dinosaurs* CTF toolkit. *pwnypack*
attempts to provide a toolset which can be used to more easily develop
CTF solutions.

|Build Status|

Motivation
----------

After seeing the excellent
`pwntools <https://github.com/Gallopsled/pwntools>`__ by Gallopsled, I
got interested in building my own CTF toolkit. *pwntools* is much more
complete so you should probably use that. *pwnypack* was created mostly
out of curiosity.

Installation
------------

To install the latest released version of pwnypack, use:

.. code:: bash

    $ pip install pwnypack

If your python version is new enough to support IPython, you can optionally
choose to automatically install it as an optional dependency. The availability
of IPython enables the pwnypack shell (an IPython session with pwnypack
pre-imported).

.. code:: bash

    $ pip install pwnypack[shell]

Usage
-----

To import all of *pwnypack* into your global namespace, use:

.. code:: python

    >>> from pwny import *

Or, if you're using python 2.7+ or python 3.3+, try the customized
IPython shell:

.. code:: bash

    $ pwny shell

I promise that effort will be put into not exposing unnecessary stuff
and thus overly polluting your global namespace.

For an example, check out the `Big Prison
Fence <https://github.com/edibledinos/pwnypack/wiki/Big-Prison-Fence>`__
example in the wiki.

Documentation
-------------

*pwnypack*'s API documentation is hosted on
`readthedocs <http://pwnypack.readthedocs.org/>`__.

Contributors
------------

*pwnypack* was created by Certified Edible Dinosaurs (dsc & doskop). If you
want to contribute, feel free to fork and create a pull request on
`GitHub <https://github.com/edibledinos/pwnypack>`__.

License
-------

*pwnypack* is distributed under the MIT license.

.. |Build Status| image:: https://travis-ci.org/edibledinos/pwnypack.svg?branch=travis-ci
   :target: https://travis-ci.org/edibledinos/pwnypack
