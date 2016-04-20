import base64
import types
import warnings

import six
from six.moves import cPickle, copyreg
from kwonly_args import kwonly_defaults

import pwnypack.bytecode
from pwnypack.py_internals import get_py_internals


__all__ = ['pickle_invoke', 'pickle_func']


class PickleInvoke(object):
    def __init__(self, func, *args):
        self.func = func
        self.args = args

    def __call__(self):  # pragma: no cover
        pass

    def __reduce__(self):
        return self.func, self.args


def get_protocol_version(protocol=None, target=None):
    """
    Return a suitable pickle protocol version for a given target.

    Arguments:
        target: The internals description of the targeted python
            version. If this is ``None`` the specification of the currently
            running python version will be used.
        protocol(None or int): The requested protocol version (or None for the
            default of the target python version).

    Returns:
        int: A suitable pickle protocol version.
    """

    target = get_py_internals(target)

    if protocol is None:
        protocol = target['pickle_default_protocol']

    if protocol > cPickle.HIGHEST_PROTOCOL:
        warnings.warn('Downgrading pickle protocol, running python supports up to %d.' % cPickle.HIGHEST_PROTOCOL)
        protocol = cPickle.HIGHEST_PROTOCOL

    target_highest_protocol = target['pickle_highest_protocol']
    if protocol > target_highest_protocol:
        warnings.warn('Downgrading pickle protocol, target python supports up to %d.' % target_highest_protocol)
        protocol = target_highest_protocol

    return protocol


@kwonly_defaults
def pickle_invoke(func, target=None, protocol=None, *args):
    """pickle_invoke(func, *args, target=None, protocol=None)

    Create a byte sequence which when unpickled calls a callable with given
    arguments.

    Note:
        The function has to be importable using the same name on the system
        that unpickles this invocation.

    Arguments:
        func(callable): The function to call or class to instantiate.
        args(tuple): The arguments to call the callable with.
        target: The internals description of the targeted python
            version. If this is ``None`` the specification of the currently
            running python version will be used.
        protocol: The pickle protocol version to use (use None for default).

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

    protocol = get_protocol_version(protocol, target)
    return cPickle.dumps(PickleInvoke(func, *args), protocol)


def translate_opcodes(code_obj, target):
    """
    Very crude inter-python version opcode translator. Raises SyntaxError when
    the opcode doesn't exist in the destination opmap. Used to transcribe
    python code objects between python versions.

    Arguments:
        code_obj(pwnypack.bytecode.CodeObject): The code object representation
            to translate.
        target(dict): The py_internals structure for the target
            python version.
    """

    target = get_py_internals(target)
    src_ops = code_obj.disassemble()

    dst_opmap = target['opmap']
    dst_ops = []

    op_iter = enumerate(src_ops)
    for i, op in op_iter:
        if isinstance(op, pwnypack.bytecode.Label):
            dst_ops.append(op)
            continue

        if op.name not in dst_opmap:
            if op.name == 'POP_JUMP_IF_FALSE' and 'JUMP_IF_TRUE' in dst_opmap:
                lbl = pwnypack.bytecode.Label()
                dst_ops.extend([
                    pwnypack.bytecode.Op('JUMP_IF_TRUE', lbl),
                    pwnypack.bytecode.Op('POP_TOP', None),
                    pwnypack.bytecode.Op('JUMP_ABSOLUTE', op.arg),
                    lbl,
                    pwnypack.bytecode.Op('POP_TOP', None),
                ])
            elif op.name == 'POP_JUMP_IF_TRUE' and 'JUMP_IF_FALSE' in dst_opmap:
                lbl = pwnypack.bytecode.Label()
                dst_ops.extend([
                    pwnypack.bytecode.Op('JUMP_IF_FALSE', lbl),
                    pwnypack.bytecode.Op('POP_TOP', None),
                    pwnypack.bytecode.Op('JUMP_ABSOLUTE', op.arg),
                    lbl,
                    pwnypack.bytecode.Op('POP_TOP', None),
                ])
            elif op.name == 'JUMP_IF_FALSE' and 'JUMP_IF_FALSE_OR_POP' in dst_opmap and \
                    src_ops[i + 1].name == 'POP_TOP':
                next(op_iter)
                dst_ops.append(pwnypack.bytecode.Op('JUMP_IF_FALSE_OR_POP', op.arg))
            elif op.name == 'JUMP_IF_TRUE' and 'JUMP_IF_TRUE_OR_POP' in dst_opmap and \
                    src_ops[i + 1].name == 'POP_TOP':
                next(op_iter)
                dst_ops.append(pwnypack.bytecode.Op('JUMP_IF_TRUE_OR_POP', op.arg))
            else:
                raise SyntaxError('Opcode %s not supported on target.' % op.name)
        else:
            dst_ops.append(op)

    code_obj.assemble(dst_ops, target)


@kwonly_defaults
def pickle_func(func, target=None, protocol=None, b64encode=None, *args):
    """pickle_func(func, *args, target=None, protocol=None, b64encode=None)

    Encode a function in such a way that when it's unpickled, the function is
    reconstructed and called with the given arguments.

    Note:
        Compatibility between python versions is not guaranteed. Depending on
        the `target` python version, the opcodes of the provided function are
        transcribed to try to maintain compatibility. If an opcode is emitted
        which is not supported by the target python version, a KeyError will
        be raised.

        Constructs that are known to be problematic:

        - Python 2.6 and 2.7/3.0 use very different, incompatible opcodes for
          conditional jumps (if, while, etc). Serializing those is not
          always possible between python 2.6 and 2.7/3.0.

        - Exception handling uses different, incompatible opcodes between
          python 2 and 3.

        - Python 2 and python 3 handle nested functions very differently: the
          same opcode is used in a different way and leads to a crash. Avoid
          nesting functions if you want to pickle across python functions.

    Arguments:
        func(callable): The function to serialize and call when unpickled.
        args(tuple): The arguments to call the callable with.
        target: The internals description of the targeted python
            version. If this is ``None`` the specification of the currently
            running python version will be used.
        protocol(int): The pickle protocol version to use.
        b64encode(bool): Whether to base64 certain code object fields. Required
            when you prepare a pickle for python 3 on python 2. If it's
            ``None`` it defaults to ``False`` unless pickling from python 2 to
            python 3.

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

    target = get_py_internals(target)

    code = six.get_function_code(func)
    code_obj = pwnypack.bytecode.CodeObject.from_code(code)
    translate_opcodes(code_obj, target)

    def code_reduce_v2(_):
        if b64encode:
            # b64encode co_code and co_lnotab as they contain 8bit data.
            co_code = PickleInvoke(base64.b64decode, base64.b64encode(code_obj.co_code))
            co_lnotab = PickleInvoke(base64.b64decode, base64.b64encode(code_obj.co_lnotab))
        else:
            co_code = code_obj.co_code
            co_lnotab = code_obj.co_lnotab

        if six.PY3:
            # Encode unicode to bytes as python 2 doesn't support unicode identifiers.
            co_names = tuple(n.encode('ascii') for n in code_obj.co_names)
            co_varnames = tuple(n.encode('ascii') for n in code_obj.co_varnames)
            co_filename = code_obj.co_filename.encode('ascii')
            co_name = code_obj.co_name.encode('ascii')
        else:
            co_names = code_obj.co_names
            co_varnames = code_obj.co_varnames
            co_filename = code_obj.co_filename
            co_name = code_obj.co_name

        return types.CodeType, (code_obj.co_argcount, code_obj.co_nlocals, code_obj.co_stacksize, code_obj.co_flags,
                                co_code, code_obj.co_consts, co_names, co_varnames, co_filename, co_name,
                                code_obj.co_firstlineno, co_lnotab)

    def code_reduce_v3(_):
        if b64encode:
            # b64encode co_code and co_lnotab as they contain 8bit data.
            co_code = PickleInvoke(base64.b64decode, base64.b64encode(code_obj.co_code))
            co_lnotab = PickleInvoke(base64.b64decode, base64.b64encode(code_obj.co_lnotab))
        else:
            co_code = code_obj.co_code
            co_lnotab = code_obj.co_lnotab

        return types.CodeType, (code_obj.co_argcount, code_obj.co_kwonlyargcount, code_obj.co_nlocals,
                                code_obj.co_stacksize, code_obj.co_flags, co_code, code_obj.co_consts,
                                code_obj.co_names, code_obj.co_varnames, code_obj.co_filename, code_obj.co_name,
                                code_obj.co_firstlineno, co_lnotab)

    # Stubs to trick cPickle into pickling calls to CodeType/FunctionType.
    class CodeType(object):  # pragma: no cover
        pass
    CodeType.__module__ = 'types'
    CodeType.__qualname__ = 'CodeType'

    class FunctionType(object):  # pragma: no cover
        pass
    FunctionType.__module__ = 'types'
    FunctionType.__qualname__ = 'FunctionType'

    protocol = get_protocol_version(protocol, target)

    old_code_reduce = copyreg.dispatch_table.pop(types.CodeType, None)
    if target['version'] < 30:
        copyreg.pickle(types.CodeType, code_reduce_v2)
    else:
        if six.PY2:
            if b64encode is False:
                warnings.warn('Enabling b64encode, pickling from python 2 to 3.')
            b64encode = True
        copyreg.pickle(types.CodeType, code_reduce_v3)

    # This has an astonishing level of evil just to convince pickle to pickle CodeType and FunctionType:
    old_code_type, types.CodeType = types.CodeType, CodeType
    old_function_type, types.FunctionType = types.FunctionType, FunctionType

    try:
        build_func = PickleInvoke(types.FunctionType, code, PickleInvoke(globals))
        return cPickle.dumps(PickleInvoke(build_func, *args), protocol)
    finally:
        types.CodeType = old_code_type
        types.FunctionType = old_function_type

        if old_code_reduce is not None:
            copyreg.pickle(types.CodeType, old_code_reduce)
        else:
            del copyreg.dispatch_table[types.CodeType]
