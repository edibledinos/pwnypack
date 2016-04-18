import base64
import opcode
import types
import warnings

import six
from six.moves import cPickle, copyreg


__all__ = ['pickle_invoke', 'pickle_func']


class PickleInvoke(object):
    def __init__(self, func, *args):
        self.func = func
        self.args = args

    def __call__(self):  # pragma: no cover
        pass

    def __reduce__(self):
        return self.func, self.args


def pickle_invoke(func, args=(), protocol=None):
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
        >>> pickle.loads(pickle_invoke(hello, ('world',)))
        Hello, world!
    """

    if protocol is None:
        protocol = getattr(cPickle, 'DEFAULT_PROTOCOL', 2)

    return cPickle.dumps(PickleInvoke(func, *args), protocol)


# Opcode mappings for various python versions.
OPMAPS = {
    26: {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'POP_TOP': 1, 'EXTENDED_ARG': 143, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 107, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 106, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'JUMP_IF_TRUE': 112, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 104, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'MAKE_FUNCTION': 132, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 18, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'JUMP_IF_FALSE': 111, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 105, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 108, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110},
    27: {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'MAP_ADD': 147, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'BUILD_SET': 104, 'POP_TOP': 1, 'EXTENDED_ARG': 145, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 108, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 107, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'SET_ADD': 146, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 105, 'SETUP_WITH': 143, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 94, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'MAKE_FUNCTION': 132, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 106, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 109, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'POP_JUMP_IF_TRUE': 115, 'JUMP_IF_FALSE_OR_POP': 111, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'POP_JUMP_IF_FALSE': 114, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'JUMP_IF_TRUE_OR_POP': 112, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110},
    30: {'LOAD_CLOSURE': 135, 'POP_BLOCK': 87, 'DELETE_ATTR': 96, 'INPLACE_POWER': 67, 'LOAD_BUILD_CLASS': 71, 'BINARY_SUBSCR': 25, 'INPLACE_FLOOR_DIVIDE': 28, 'WITH_CLEANUP_START': 81, 'POP_TOP': 1, 'CALL_FUNCTION_VAR': 140, 'DUP_TOP_TWO': 5, 'CONTINUE_LOOP': 119, 'IMPORT_STAR': 84, 'GET_AITER': 50, 'RETURN_VALUE': 83, 'GET_AWAITABLE': 73, 'JUMP_IF_TRUE_OR_POP': 112, 'UNARY_INVERT': 15, 'YIELD_VALUE': 86, 'END_FINALLY': 88, 'BREAK_LOOP': 80, 'IMPORT_NAME': 108, 'UNPACK_SEQUENCE': 92, 'DELETE_SUBSCR': 61, 'DELETE_DEREF': 138, 'WITH_CLEANUP_FINISH': 82, 'YIELD_FROM': 72, 'UNARY_POSITIVE': 10, 'SETUP_LOOP': 120, 'STORE_ATTR': 95, 'SETUP_FINALLY': 122, 'SETUP_WITH': 143, 'MAKE_FUNCTION': 132, 'DELETE_GLOBAL': 98, 'IMPORT_FROM': 109, 'INPLACE_OR': 79, 'SET_ADD': 146, 'NOP': 9, 'BINARY_FLOOR_DIVIDE': 26, 'STORE_SUBSCR': 60, 'DELETE_FAST': 126, 'POP_JUMP_IF_TRUE': 115, 'BINARY_ADD': 23, 'BUILD_TUPLE': 102, 'LOAD_CONST': 100, 'BUILD_SET_UNPACK': 153, 'BINARY_MATRIX_MULTIPLY': 16, 'INPLACE_SUBTRACT': 56, 'INPLACE_XOR': 78, 'CALL_FUNCTION_KW': 141, 'INPLACE_MULTIPLY': 57, 'JUMP_ABSOLUTE': 113, 'BINARY_SUBTRACT': 24, 'CALL_FUNCTION_VAR_KW': 142, 'DUP_TOP': 4, 'BINARY_AND': 64, 'LOAD_ATTR': 106, 'LOAD_FAST': 124, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'BINARY_XOR': 65, 'INPLACE_AND': 77, 'MAP_ADD': 147, 'BUILD_TUPLE_UNPACK': 152, 'EXTENDED_ARG': 144, 'BUILD_SET': 104, 'LIST_APPEND': 145, 'INPLACE_MODULO': 59, 'STORE_NAME': 90, 'JUMP_FORWARD': 110, 'BUILD_MAP_UNPACK': 150, 'COMPARE_OP': 107, 'LOAD_DEREF': 136, 'BINARY_RSHIFT': 63, 'LOAD_NAME': 101, 'BUILD_SLICE': 133, 'SETUP_ASYNC_WITH': 154, 'STORE_FAST': 125, 'INPLACE_RSHIFT': 76, 'ROT_TWO': 2, 'STORE_DEREF': 137, 'STORE_GLOBAL': 97, 'INPLACE_ADD': 55, 'FOR_ITER': 93, 'LOAD_CLASSDEREF': 148, 'BUILD_MAP_UNPACK_WITH_CALL': 151, 'INPLACE_LSHIFT': 75, 'BINARY_OR': 66, 'PRINT_EXPR': 70, 'BEFORE_ASYNC_WITH': 52, 'INPLACE_MATRIX_MULTIPLY': 17, 'BINARY_MODULO': 22, 'JUMP_IF_FALSE_OR_POP': 111, 'BINARY_TRUE_DIVIDE': 27, 'UNARY_NEGATIVE': 11, 'RAISE_VARARGS': 130, 'BUILD_MAP': 105, 'UNPACK_EX': 94, 'POP_JUMP_IF_FALSE': 114, 'BINARY_POWER': 19, 'BUILD_LIST_UNPACK': 149, 'INPLACE_TRUE_DIVIDE': 29, 'GET_YIELD_FROM_ITER': 69, 'GET_ANEXT': 51, 'POP_EXCEPT': 89, 'ROT_THREE': 3, 'BINARY_MULTIPLY': 20, 'GET_ITER': 68, 'BUILD_LIST': 103, 'CALL_FUNCTION': 131, 'DELETE_NAME': 91, 'MAKE_CLOSURE': 134, 'LOAD_GLOBAL': 116, 'SETUP_EXCEPT': 121},
    None: opcode.opmap,
}


def translate_opcodes(src_code, dst_opmap):
    """
    Very crude inter-python version opcode translator. Raises key error when
    the opcode doesn't exist in the destination opmap. Used to transcribe
    python code objects between python versions.

    Arguments:
        src_code(bytes): The co_code attribute of the code object.
        dst_opmap(dict): The opcode mapping for the target.

    Returns:
        bytes: The translated opcodes.
    """

    dst_code = b''

    code_iter = six.iterbytes(src_code)
    for src_op_code in code_iter:
        src_op_name = opcode.opname[src_op_code]

        dst_code += six.int2byte(dst_opmap[src_op_name])

        if src_op_code >= opcode.HAVE_ARGUMENT:
            dst_code += six.int2byte(next(code_iter))
            dst_code += six.int2byte(next(code_iter))

    return dst_code


def pickle_func(func, args=(), protocol=None, b64encode=None, target=None):
    """
    Encode a function in such a way that when it's unpickled, the function is
    reconstructed and called with the given arguments.

    Note:
        Compatibility between python versions is not guaranteed. Depending on
        the `target` python version, the opcodes of the provided function are
        transcribed to try to maintain compatibility. If an opcode is emitted
        which is not supported by the target python version, a KeyError will
        be raised.

    Arguments:
        func(callable): The function to serialize and call when unpickled.
        args(tuple): The arguments to call the callable with.
        protocol(int): The pickle protocol version to use.
        b64encode(bool): Whether to base64 certain code object fields. Required
            when you prepare a pickle for python 3 on python 2. If it's
            ``None`` it defaults to ``False`` unless pickling from python 2 to
            python 3.
        target(int): The target python version (``26`` for python 2.6, ``27``
            for python 2.7, or ``30`` for python 3.0+). Can be ``None`` in
            which case the current python version is assumed.

    Returns:
        bytes: The data that when unpickled calls ``func(*args)``.

    Example:
        >>> from pwny import *
        >>> import pickle
        >>> def hello(arg):
        ...     print('Hello, %s!' % arg)
        ...
        >>> p = pickle_func(hello, ('world',))
        >>> del hello
        >>> pickle.loads(p)
        Hello, world!
    """

    def code_reduce_v2(code):
        # Translate the opcodes to the target python's opcode map.
        co_code = translate_opcodes(code.co_code, OPMAPS[target])

        if b64encode:
            # b64encode co_code and co_lnotab as they contain 8bit data.
            co_code = PickleInvoke(base64.b64decode, base64.b64encode(co_code))
            co_lnotab = PickleInvoke(base64.b64decode, base64.b64encode(code.co_lnotab))
        else:
            co_lnotab = code.co_lnotab

        if six.PY3:
            # Encode unicode to bytes as python 2 doesn't support unicode identifiers.
            co_names = tuple(n.encode('ascii') for n in code.co_names)
            co_varnames = tuple(n.encode('ascii') for n in code.co_varnames)
            co_filename = code.co_filename.encode('ascii')
            co_name = code.co_name.encode('ascii')
        else:
            co_names = code.co_names
            co_varnames = code.co_varnames
            co_filename = code.co_filename
            co_name = code.co_name

        return types.CodeType, (code.co_argcount, code.co_nlocals, code.co_stacksize, code.co_flags,
                                co_code, code.co_consts, co_names, co_varnames, co_filename,
                                co_name, code.co_firstlineno, co_lnotab)

    def code_reduce_v3(code):
        # Translate the opcodes to the target python's opcode map.
        co_code = translate_opcodes(code.co_code, OPMAPS[target])

        if b64encode:
            # b64encode co_code and co_lnotab as they contain 8bit data.
            co_code = PickleInvoke(base64.b64decode, base64.b64encode(co_code))
            co_lnotab = PickleInvoke(base64.b64decode, base64.b64encode(code.co_lnotab))
        else:
            co_lnotab = code.co_lnotab

        if six.PY2:
            co_kwonlyargcount = 0
        else:
            co_kwonlyargcount = code.co_kwonlyargcount

        return types.CodeType, (code.co_argcount, co_kwonlyargcount, code.co_nlocals, code.co_stacksize,
                                code.co_flags, co_code, code.co_consts, code.co_names, code.co_varnames,
                                code.co_filename, code.co_name, code.co_firstlineno, co_lnotab)

    # Stubs to trick cPickle into pickling calls to CodeType/FunctionType.
    def CodeType(*args):  # pragma: no cover
        pass
    CodeType.__module__ = 'types'
    CodeType.__qualname__ = 'CodeType'

    def FunctionType(*args, **kwargs):  # pragma: no cover
        pass
    FunctionType.__module__ = 'types'
    FunctionType.__qualname__ = 'FunctionType'

    if protocol is None:
        protocol = getattr(cPickle, 'DEFAULT_PROTOCOL', 2)

    if target and target not in (26, 27, 30):
        raise ValueError('Unsupported target python %r. Use 26, 27 or 30.' % target)

    code = six.get_function_code(func)

    old_code_reduce = copyreg.dispatch_table.pop(types.CodeType, None)
    if target in (26, 27) or (target is None and six.PY2):
        if protocol > 2:
            warnings.warn('Downgrading pickle protocol, python 2 supports versions up to 2.')
            protocol = 2
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
