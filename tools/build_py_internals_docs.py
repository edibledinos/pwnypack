#! /usr/bin/env python

from __future__ import print_function

import sys
import os

import six

if __name__ == '__main__':
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from pwnypack.py_internals import PY_INTERNALS
    versions = sorted(version for version in six.iterkeys(PY_INTERNALS) if version is not None)

    print(''':mod:`~pwnypack.py_internals` -- Python internals
=================================================

.. automodule:: pwnypack.py_internals
''')

    for version in versions:
        print('''   .. autodata:: PY_{0}
        :annotation: = {{...}}
'''.format(version))

    print('''   .. autodata:: PY_INTERNALS
        :annotation: = {{{}}}'''.format(', '.join('{0}: PY_{0}'.format(version) for version in versions)))
