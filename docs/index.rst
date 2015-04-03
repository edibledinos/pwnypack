Welcome to pwnypack!
====================

*pwnypack* is the official CTF toolkit of Certified Edible Dinosaurs. It aims
to provide a set of command line utilities and a python library that are
useful when playing hacking CTFs.

The core functionality of *pwnypack* is defined in the modules of the
``pwnypack`` package. The ``pwny`` package imports all that
functionality into a single namespace for convenience.

Some of the functionality of the ``pwnypack`` package is also exported
through a set of commandline utilities. Run :code:`pwny help` after installing
*pwnypack* to get a list of available utilities. You can create convenience
symlinks for all the included apps by running :code:`pwny symlink`. Each app
has a help function that is accessible using the :code:`-h` parameter.

For some example of how to use *pwnypack*, check the write-ups on the
official `Certified Edible Dinosaurs <http://ced.pwned.systems/>`_ website.

Package contents:

.. toctree::

   pwny
   pwnypack

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`

