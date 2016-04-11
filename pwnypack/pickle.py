import types
import marshal

import six
from six.moves import cPickle


__all__ = ['pickle_invoke', 'pickle_func']


class PickleInvoke(object):
    def __init__(self, func, *args):
        self.func = func
        self.args = args

    def __call__(self):  # pragma: no cover
        pass

    def __reduce__(self):
        return self.func, self.args


def pickle_invoke(func, *args):
    """
    Create a byte sequence which when unpickled calls a callable with given
    arguments.

    Note:
        The function has to be importable using the same name on the system
        that unpickles this invocation.

    Arguments:
        func(callable): The function to call or class to instantiate.
        args(tuple): The arguments to call the callable with.

    Returns:
        bytes: The data that when unpickled calls ``func(*args)``.

    Example:
        >>> from pwny import *
        >>> import pickle
        >>> def hello(arg):
        ...     print('Hello, %s!' % arg)
        ...
        >>> pickle.loads(pickle_invoke(hello, 'world'))
        Hello, world!
    """

    return cPickle.dumps(PickleInvoke(func, *args), 0)


def pickle_func(func, *args):
    """
    Encode a function in such a way that when it's unpickled, the function is
    reconstructed and called with the given arguments.

    Note:
        Compatibility between python versions is not guaranteed. Some success
        has been reported when using a function pickled on python 2.6 and
        unpickling it on python 2.7, interpreter crashes have been reported
        the other way around. Use with care!

    Arguments:
        func(callable): The function to serialize and call when unpickled.
        args(tuple): The arguments to call the callable with.

    Returns:
        bytes: The data that when unpickled calls ``func(*args)``.

    Example:
        >>> from pwny import *
        >>> import pickle
        >>> def hello(arg):
        ...     print('Hello, %s!' % arg)
        ...
        >>> p = pickle_func(hello, 'world')
        >>> del hello
        >>> pickle.loads(p)
        Hello, world!
    """

    marshalled_code = marshal.dumps(six.get_function_code(func))

    orig_function_type = types.FunctionType

    def FunctionType(*args, **kwargs):  # pragma: no cover
        return orig_function_type(*args, **kwargs)
    FunctionType.__module__ = 'types'
    FunctionType.__qualname__ = 'FunctionType'

    unmarshal = PickleInvoke(marshal.loads, marshalled_code)
    build_function = PickleInvoke(FunctionType, unmarshal, PickleInvoke(globals))
    run_function = PickleInvoke(build_function, *args)

    # This has an astonishing level of evil just to convince pickle to pickle FunctionType:
    types.FunctionType = FunctionType
    try:
        return cPickle.dumps(run_function, 0)
    finally:
        types.FunctionType = orig_function_type
