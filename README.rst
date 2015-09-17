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

If you want to use the interactive shell I highly recommend installing
either `bpython` or `ipython` as those packages can make your time in
the shell a lot more enjoyable.

Usage
-----

To import all of *pwnypack* into your global namespace, use:

.. code:: python

    >>> from pwny import *

Or, if you're using python 2.7+ or python 3.3+, try the customized
bpython or IPython shell:

.. code:: bash

    $ pwny shell

If you have bpython and/or IPython installed you can use ``--bpython``,
``--ipython`` or ``--python`` to select which interactive kernel to use.

I promise that effort will be put into not exposing unnecessary stuff
and thus overly polluting your global namespace.

For an example, check out the `Big Prison
Fence <https://github.com/edibledinos/pwnypack/wiki/Big-Prison-Fence>`__
example in the wiki.

Documentation
-------------

*pwnypack*'s API documentation is hosted on
`readthedocs <http://pwnypack.readthedocs.org/>`__.

For information on the commandline apps use the built in help function:

.. code:: bash

   $ pwny --help
   $ pwny shell --help

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
