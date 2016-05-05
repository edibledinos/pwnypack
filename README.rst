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

First, make sure your `setuptools` and `pip` packages are up to date:

.. code:: bash

    $ pip install -U setuptools pip

To install the latest released version of pwnypack with all optional
dependencies, run:

.. code:: bash

    $ pip install --no-binary capstone pwnypack[all]

To install the latest released version of pwnypack with minimal
dependencies, run:

.. code:: bash

    $ pip install pwnypack

Other available install targets are:

- ``--no-binary capstone pwnypack[disasm]`` - installs ``capstone`` for AT&T
  and intel syntax disassembly, required to disassemble ARM binaries).

- ``--no-binary capstone pwnypack[rop]`` - installs ``capstone`` to validate
  ROP gadgets.

- ``pwnypack[ssh]`` - installs ``paramiko`` to enable the ``Flow`` module to
  connect to SSH servers.

- ``pwnypack[shell]`` - installs ``ipython`` to support the enhanced pwnypack
  REPL environment.

- ``pwnypack[pwnbook]`` - installs ``jupyter`` to support the ``pwnbook`` jupyter
  notebook.

If you want to use the interactive shell I highly recommend installing
either ``bpython`` or ``ipython`` as those packages can make your time in
the shell a lot more enjoyable.

Docker
------

You can also use our published docker images.

To start an ipython powered pwnypack shell:

.. code:: bash

    docker pull edibledinos/pwnypack:latest
    docker run --rm -it edibledinos/pwnypack:latest

Or, to run pwnbook:

.. code:: bash

    docker pull edibledinos/pwnbook:latest
    docker run --rm -it -p 8888:8888 edibledinos/pwnbook:latest

Both images expose a volume (``/projects``). Feel free to mount something
interesting there.

Three tags are available:

- ``py3`` (or: ``latest``) installs python 3 and pwnypack/pwnbook.
- ``py2`` installs python 2 and pwnypack/pwnbook.

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

Common errors
-------------

Capstone fails to import the dynamic library.

.. code::

   Traceback (most recent call last):
     File "<stdin>", line 1, in <module>
     File "/home/ingmar/.virtualenvs/pp/lib/python3.5/site-packages/capstone/__init__.py", line 230, in <module>
       raise ImportError("ERROR: fail to load the dynamic library.")
   ImportError: ERROR: fail to load the dynamic library.

The ``capstone`` package has a bug which when used with a new verion of
``pip`` will end up installing the capstone library in the wrong location on
linux. Re-install ``capstone`` using:

.. code:: bash

    $ pip install --no-binary capstone capstone

SyntaxError when importing pwnypack.

.. code::

   Traceback (most recent call last):
     File "<stdin>", line 1, in <module>
     File "pwny/__init__.py", line 9, in <module>
       from pwnypack.pwnbook import *
     File "pwnypack/pwnbook.py", line 2, in <module>
       from jupyter_client import kernelspec as kernelspec
     File "/Users/ingmar/.virtualenvs/pwny26/lib/python2.6/site-packages/jupyter_client/__init__.py", line 4, in <module>
       from .connect import *
     File "/Users/ingmar/.virtualenvs/pwny26/lib/python2.6/site-packages/jupyter_client/connect.py", line 23, in <module>
       from traitlets.config import LoggingConfigurable
     File "/Users/ingmar/.virtualenvs/pwny26/lib/python2.6/site-packages/traitlets/__init__.py", line 1, in <module>
       from .traitlets import *
     File "/Users/ingmar/.virtualenvs/pwny26/lib/python2.6/site-packages/traitlets/traitlets.py", line 1331
       return {n: t for (n, t) in cls.class_traits(**metadata).items()
                      ^
   SyntaxError: invalid syntax

You've installed jupyter notebooks on python 2.6. Use a more modern version
of python.

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

Current contributors:

- blasty <peter@haxx.in> contributed the ARM shellcode generator.

License
-------

*pwnypack* is distributed under the MIT license.

.. |Build Status| image:: https://travis-ci.org/edibledinos/pwnypack.svg?branch=travis-ci
   :target: https://travis-ci.org/edibledinos/pwnypack
