"""
The bytecode module lets you manipulate python bytecode in a
version-independent way. To facilitate this, this module provides a couple
of function to disassemble and assemble python bytecode into a high-level
representation and some functions to manipulate those structures.

The python version independent function take an op_specs parameter which
represents the specifics of bytecode on that particular version of
python. The global OP_SPECS dictionary provides these opcode specifics
for various python versions.

Examples:
    Disassemble a very simple function, change an opcode and reassemble it:

    >>> from pwny import *
    >>> import six
    >>> def foo(a):
    >>>     return a - 1
    ...
    >>> print(foo, six.get_function_code(foo).co_code, foo(5))
    <function foo at 0x10590ba60> b'|\x00\x00d\x01\x00\x18S' 4
    >>> ops = bc.disassemble(foo)
    >>> print(ops)
    [LOAD_FAST 0, LOAD_CONST 1, BINARY_SUBTRACT, RETURN_VALUE]
    >>> ops[2].name = 'BINARY_ADD'
    >>> print(ops)
    [LOAD_FAST 0, LOAD_CONST 1, BINARY_ADD, RETURN_VALUE]
    >>> bar = bc.rebuild_func_from_ops(foo, ops, co_name='bar')
    >>> print(bar, six.get_function_code(bar).co_code, bar(5))
    <function bar at 0x10590bb70> b'|\x00\x00d\x01\x00\x17S' 6
"""

from __future__ import print_function

import inspect
import opcode
import types
import sys

import six
from kwonly_args import kwonly_defaults


__all__ = ['OP_SPECS', 'Op', 'Label', 'disassemble', 'assemble', 'blocks_from_ops', 'calculate_max_stack_depth',
           'rebuild_func', 'rebuild_func_from_ops']


#: Stack effects which are shared between more than one python version.
COMMON_STACK_EFFECT = {'COMPARE_OP': -1, 'STORE_SLICE+2': -3, 'INPLACE_MODULO': -1, 'DELETE_ATTR': -1,
                       'MAKE_FUNCTION': lambda arg: -arg, 'LOAD_LOCALS': 1, 'BINARY_POWER': -1,
                       'BUILD_TUPLE_UNPACK': lambda arg: 1 - arg, 'LOAD_ATTR': 0, 'PRINT_ITEM': -1,
                       'BEFORE_ASYNC_WITH': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'GET_ANEXT': 1, 'STORE_ATTR': -2,
                       'INPLACE_SUBTRACT': -1, 'UNPACK_EX': lambda arg: (arg & 255) + (arg >> 8), 'JUMP_FORWARD': 0,
                       'IMPORT_FROM': 1, 'PRINT_EXPR': -1, 'BINARY_XOR': -1, 'STORE_NAME': -1, 'BINARY_DIVIDE': -1,
                       'BINARY_ADD': -1, 'ROT_FOUR': 0, 'JUMP_IF_TRUE': 0, 'DELETE_DEREF': 0,
                       'BINARY_TRUE_DIVIDE': -1, 'IMPORT_STAR': -1, 'NOP': None, 'GET_AWAITABLE': 0,
                       'DELETE_SLICE+0': -1, 'BUILD_SLICE': lambda arg: -2 if arg == 3 else -1, 'BINARY_OR': -1,
                       'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'CONTINUE_LOOP': 0,
                       'BUILD_SET_UNPACK': lambda arg: 1 - arg, 'PRINT_NEWLINE': 0, 'SETUP_LOOP': 0,
                       'RETURN_VALUE': -1, 'UNPACK_SEQUENCE': lambda arg: arg - 1, 'STORE_MAP': -2,
                       'BINARY_MATRIX_MULTIPLY': -1, 'BUILD_CLASS': -2, 'ROT_THREE': 0, 'STORE_SUBSCR': -3,
                       'BINARY_SUBSCR': -1, 'DELETE_SLICE+3': -3, 'BUILD_MAP': 1, 'EXTENDED_ARG': None,
                       'YIELD_FROM': -1, 'UNARY_INVERT': 0, 'DELETE_FAST': 0, 'JUMP_ABSOLUTE': 0, 'DELETE_NAME': 0,
                       'PRINT_NEWLINE_TO': -1, 'YIELD_VALUE': 0, 'FOR_ITER': 1, 'DELETE_SLICE+1': -2,
                       'INPLACE_XOR': -1, 'STORE_DEREF': -1, 'DELETE_SLICE+2': -2, 'INPLACE_TRUE_DIVIDE': -1,
                       'ROT_TWO': 0, 'STORE_FAST': -1,
                       'CALL_FUNCTION_VAR_KW': lambda arg: -((arg % 256) + 2*(arg >> 8)) - 2,
                       'BUILD_LIST_UNPACK': lambda arg: 1 - arg, 'UNARY_CONVERT': 0, 'UNARY_NOT': 0, 'DUP_TOP': 1,
                       'UNARY_POSITIVE': 0, 'BINARY_MODULO': -1, 'EXEC_STMT': -3, 'POP_EXCEPT': 0,
                       'SETUP_ASYNC_WITH': 6, 'RAISE_VARARGS': lambda arg: -arg, 'INPLACE_LSHIFT': -1,
                       'CALL_FUNCTION_KW': lambda arg: -((arg % 256) + 2*(arg >> 8)) - 1, 'MAP_ADD': -2,
                       'INPLACE_ADD': -1, 'LOAD_CONST': 1, 'STORE_SLICE+0': -2, 'BREAK_LOOP': 0, 'DUP_TOP_TWO': 2,
                       'CALL_FUNCTION': lambda arg: -((arg % 256) + 2*(arg >> 8)),
                       'BUILD_MAP_UNPACK_WITH_CALL': lambda arg: 1 - (arg & 255), 'LOAD_BUILD_CLASS': 1,
                       'LOAD_FAST': 1, 'INPLACE_RSHIFT': -1, 'BINARY_RSHIFT': -1, 'STORE_GLOBAL': -1,
                       'LOAD_GLOBAL': 1, 'POP_JUMP_IF_FALSE': -1, 'GET_AITER': 0, 'INPLACE_AND': -1,
                       'BINARY_LSHIFT': -1, 'LIST_APPEND': -1, 'GET_ITER': 0, 'DELETE_GLOBAL': 0,
                       'POP_JUMP_IF_TRUE': -1, 'LOAD_CLOSURE': 1, 'INPLACE_DIVIDE': -1, 'BINARY_MULTIPLY': -1,
                       'JUMP_IF_FALSE': 0, 'DELETE_SUBSCR': -2, 'PRINT_ITEM_TO': -2, 'IMPORT_NAME': -1,
                       'BINARY_AND': -1, 'STORE_SLICE+1': -3,
                       'CALL_FUNCTION_VAR': lambda arg: -((arg % 256) + 2*(arg >> 8)) - 1,
                       'BUILD_TUPLE': lambda arg: 1 - arg, 'LOAD_DEREF': 1, 'JUMP_IF_TRUE_OR_POP': 0,
                       'LOAD_NAME': 1, 'LOAD_CLASSDEREF': 1, 'WITH_CLEANUP_FINISH': -1, 'STORE_SLICE+3': -4,
                       'INPLACE_MULTIPLY': -1, 'BUILD_MAP_UNPACK': lambda arg: 1 - arg, 'GET_YIELD_FROM_ITER': 0,
                       'BUILD_LIST': lambda arg: 1 - arg, 'POP_BLOCK': 0, 'DUP_TOPX': lambda arg: arg,
                       'INPLACE_FLOOR_DIVIDE': -1, 'INPLACE_OR': -1, 'POP_TOP': -1, 'UNARY_NEGATIVE': 0,
                       'WITH_CLEANUP': -1, 'BINARY_FLOOR_DIVIDE': -1, 'END_FINALLY': -1, 'INPLACE_POWER': -1,
                       'SET_ADD': -1, 'BINARY_SUBTRACT': -1}


#: Mapping that holds the relevant information per python version.
OP_SPECS = {
    26: {
        'opmap': {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'POP_TOP': 1, 'EXTENDED_ARG': 143, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 107, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 106, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'JUMP_IF_TRUE': 112, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 104, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'MAKE_FUNCTION': 132, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 18, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'JUMP_IF_FALSE': 111, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 105, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 108, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110},
        'hasjrel': [93, 110, 111, 112, 120, 121, 122],
        'hasjabs': [113, 119],
        'have_argument': 90,
        'extended_arg': 143,
        'stackeffect': {
            'SETUP_EXCEPT': 3,
            'SLICE+2': 0,
            'LIST_APPEND': -2,
            'SLICE+1': 0,
            'SETUP_FINALLY': 3,
            'IMPORT_NAME': 0,
            'MAKE_CLOSURE': lambda arg: -arg,
            'SLICE+0': 1,
            'SLICE+3': -1
        },
        'stackeffect_traits': 0,
    },
    27: {
        'opmap': {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'MAP_ADD': 147, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'BUILD_SET': 104, 'POP_TOP': 1, 'EXTENDED_ARG': 145, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 108, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 107, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'SET_ADD': 146, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 105, 'SETUP_WITH': 143, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 94, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'MAKE_FUNCTION': 132, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 106, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 109, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'POP_JUMP_IF_TRUE': 115, 'JUMP_IF_FALSE_OR_POP': 111, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'POP_JUMP_IF_FALSE': 114, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'JUMP_IF_TRUE_OR_POP': 112, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110},
        'hasjrel': [93, 110, 120, 121, 122, 143],
        'hasjabs': [111, 112, 113, 114, 115, 119],
        'have_argument': 90,
        'extended_arg': 145,
        'stackeffect': {
            'BUILD_SET': None,
            'SETUP_EXCEPT': 0,
            'SLICE+2': -1,
            'SLICE+1': -1,
            'SETUP_FINALLY': 0,
            'MAKE_CLOSURE': lambda arg: -arg - 1,
            'SLICE+0': 0,
            'SLICE+3': -2,
            'SETUP_WITH': None,
            'END_FINALLY': -3
        },
        'stackeffect_traits': 1,
    },
    30: {
        'opmap': {'LOAD_CLOSURE': 135, 'POP_BLOCK': 87, 'DELETE_ATTR': 96, 'INPLACE_POWER': 67, 'LOAD_BUILD_CLASS': 71, 'BINARY_SUBSCR': 25, 'INPLACE_FLOOR_DIVIDE': 28, 'WITH_CLEANUP_START': 81, 'POP_TOP': 1, 'CALL_FUNCTION_VAR': 140, 'DUP_TOP_TWO': 5, 'CONTINUE_LOOP': 119, 'IMPORT_STAR': 84, 'GET_AITER': 50, 'RETURN_VALUE': 83, 'GET_AWAITABLE': 73, 'JUMP_IF_TRUE_OR_POP': 112, 'UNARY_INVERT': 15, 'YIELD_VALUE': 86, 'END_FINALLY': 88, 'BREAK_LOOP': 80, 'IMPORT_NAME': 108, 'UNPACK_SEQUENCE': 92, 'DELETE_SUBSCR': 61, 'DELETE_DEREF': 138, 'WITH_CLEANUP_FINISH': 82, 'YIELD_FROM': 72, 'UNARY_POSITIVE': 10, 'SETUP_LOOP': 120, 'STORE_ATTR': 95, 'SETUP_FINALLY': 122, 'SETUP_WITH': 143, 'MAKE_FUNCTION': 132, 'DELETE_GLOBAL': 98, 'IMPORT_FROM': 109, 'INPLACE_OR': 79, 'SET_ADD': 146, 'NOP': 9, 'BINARY_FLOOR_DIVIDE': 26, 'STORE_SUBSCR': 60, 'DELETE_FAST': 126, 'POP_JUMP_IF_TRUE': 115, 'BINARY_ADD': 23, 'BUILD_TUPLE': 102, 'LOAD_CONST': 100, 'BUILD_SET_UNPACK': 153, 'BINARY_MATRIX_MULTIPLY': 16, 'INPLACE_SUBTRACT': 56, 'INPLACE_XOR': 78, 'CALL_FUNCTION_KW': 141, 'INPLACE_MULTIPLY': 57, 'JUMP_ABSOLUTE': 113, 'BINARY_SUBTRACT': 24, 'CALL_FUNCTION_VAR_KW': 142, 'DUP_TOP': 4, 'BINARY_AND': 64, 'LOAD_ATTR': 106, 'LOAD_FAST': 124, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'BINARY_XOR': 65, 'INPLACE_AND': 77, 'MAP_ADD': 147, 'BUILD_TUPLE_UNPACK': 152, 'EXTENDED_ARG': 144, 'BUILD_SET': 104, 'LIST_APPEND': 145, 'INPLACE_MODULO': 59, 'STORE_NAME': 90, 'JUMP_FORWARD': 110, 'BUILD_MAP_UNPACK': 150, 'COMPARE_OP': 107, 'LOAD_DEREF': 136, 'BINARY_RSHIFT': 63, 'LOAD_NAME': 101, 'BUILD_SLICE': 133, 'SETUP_ASYNC_WITH': 154, 'STORE_FAST': 125, 'INPLACE_RSHIFT': 76, 'ROT_TWO': 2, 'STORE_DEREF': 137, 'STORE_GLOBAL': 97, 'INPLACE_ADD': 55, 'FOR_ITER': 93, 'LOAD_CLASSDEREF': 148, 'BUILD_MAP_UNPACK_WITH_CALL': 151, 'INPLACE_LSHIFT': 75, 'BINARY_OR': 66, 'PRINT_EXPR': 70, 'BEFORE_ASYNC_WITH': 52, 'INPLACE_MATRIX_MULTIPLY': 17, 'BINARY_MODULO': 22, 'JUMP_IF_FALSE_OR_POP': 111, 'BINARY_TRUE_DIVIDE': 27, 'UNARY_NEGATIVE': 11, 'RAISE_VARARGS': 130, 'BUILD_MAP': 105, 'UNPACK_EX': 94, 'POP_JUMP_IF_FALSE': 114, 'BINARY_POWER': 19, 'BUILD_LIST_UNPACK': 149, 'INPLACE_TRUE_DIVIDE': 29, 'GET_YIELD_FROM_ITER': 69, 'GET_ANEXT': 51, 'POP_EXCEPT': 89, 'ROT_THREE': 3, 'BINARY_MULTIPLY': 20, 'GET_ITER': 68, 'BUILD_LIST': 103, 'CALL_FUNCTION': 131, 'DELETE_NAME': 91, 'MAKE_CLOSURE': 134, 'LOAD_GLOBAL': 116, 'SETUP_EXCEPT': 121},
        'hasjrel': [93, 110, 120, 121, 122, 143, 154],
        'hasjabs': [111, 112, 113, 114, 115, 119],
        'have_argument': 90,
        'extended_arg': 144,
        'stackeffect': {
            'BUILD_SET': lambda arg: 1-arg,
            'CALL_FUNCTION_KW': lambda arg: -((arg % 256) + 2*((arg >> 8) % 256)) - 1,
            'SETUP_EXCEPT': 6,
            'SETUP_FINALLY': 6,
            'MAKE_FUNCTION': lambda arg: -1 - ((arg % 256) + 2*((arg >> 8) % 256)) - ((arg >> 16) & 0xffff),
            'BUILD_MAP': lambda arg: 1 - 2*arg,
            'CALL_FUNCTION_VAR': lambda arg: -((arg % 256) + 2*((arg >> 8) % 256)) - 1,
            'MAKE_CLOSURE': lambda arg: -2 - ((arg % 256) + 2*((arg >> 8) % 256)) - ((arg >> 16) & 0xffff),
            'CALL_FUNCTION_VAR_KW': lambda arg: -((arg % 256) + 2*((arg >> 8) % 256)) - 2,
            'CALL_FUNCTION': lambda arg: -((arg % 256) + 2*((arg >> 8) % 256)),
            'SETUP_WITH': 7
        },
        'stackeffect_traits': 1,
    },
    None: {
        'opmap': opcode.opmap,
        'hasjrel': opcode.hasjrel,
        'hasjabs': opcode.hasjabs,
        'have_argument': opcode.HAVE_ARGUMENT,
        'extended_arg': opcode.EXTENDED_ARG,
    },
}


def _build_opnames():
    """
    Takes each python version's opmap and makes an opname list out of it.
    """

    for version, op_spec in six.iteritems(OP_SPECS):
        reverse_opmap = dict((v, k) for k, v in six.iteritems(op_spec['opmap']))
        op_spec['opname'] = [
            reverse_opmap[op_code] if op_code in reverse_opmap else '<%d>' % op_code
            for op_code in range(256)
        ]
_build_opnames()


def _build_stack_effect():
    """
    Merge common stack effects with version specific ones.

    Also defines the stack effects of the currently running version.
    """

    for version, op_spec in six.iteritems(OP_SPECS):
        if version is None:
            continue
        stackeffect = op_spec['stackeffect']
        op_spec['stackeffect'] = COMMON_STACK_EFFECT.copy()
        op_spec['stackeffect'].update(stackeffect)

    if sys.version_info < (2, 7, 0):
        OP_SPECS[None]['stackeffect'] = OP_SPECS[26]['stackeffect']
        OP_SPECS[None]['stackeffect_traits'] = 0
    elif sys.version_info < (3, 0, 0):
        OP_SPECS[None]['stackeffect'] = OP_SPECS[27]['stackeffect']
        OP_SPECS[None]['stackeffect_traits'] = 1
    else:
        OP_SPECS[None]['stackeffect'] = OP_SPECS[30]['stackeffect']
        OP_SPECS[None]['stackeffect_traits'] = 1
_build_stack_effect()


class Label(object):
    """
    Used to define a label in a series of opcodes.
    """


class Op(object):
    """
    Describe a single bytecode operation.

    Arguments:
        name(str): The name of the opcode.
        arg: The argument of the opcode. Should be ``None`` for opcodes
            without arguments, should be a :class:`Label` for opcodes that
            define a jump, should be an ``int`` otherwise.
    """

    def __init__(self, name, arg=None):
        self.name = name  #: The name of the opcode.
        self.arg = arg  #: The opcode's argument (or ``None``).

    def __repr__(self):
        if self.arg is not None:
            return '%s %r' % (self.name, self.arg)
        else:
            return self.name


def disassemble(code, op_specs=None):
    """
    Disassemble python bytecode into a series of :class:`Op` and
    :class:`Label` instances.

    Arguments:
        code(bytes): The bytecode (a code object's ``co_code`` property). You
            can also provide a function.
        op_specs(dict): The opcode specification of the python version that
            generated ``code``. If you provide ``None``, the specs for the
            currently running python version will be used.

    Returns:
        list: A list of opcodes and labels.
    """

    if inspect.isfunction(code):
        code = six.get_function_code(code).co_code

    if op_specs is None:
        op_specs = OP_SPECS[None]

    opname = op_specs['opname']
    hasjrel = op_specs['hasjrel']
    hasjabs = op_specs['hasjabs']
    hasjump = set(hasjrel) | set(hasjabs)

    ext_arg_name = opname[op_specs['extended_arg']]
    ext_arg = 0

    addr_labels = {}
    addr_ops = []

    code_iter = enumerate(six.iterbytes(code))
    for op_addr, op_code in code_iter:
        if op_code >= op_specs['have_argument']:
            _, a = next(code_iter)
            _, b = next(code_iter)
            arg = a + (b << 8) + ext_arg

            if op_code in hasjrel:
                arg += op_addr + 3

            if op_code in hasjump:
                arg = addr_labels.setdefault(arg, Label())
        else:
            arg = None
        ext_arg = 0

        op_name = opname[op_code]

        if op_name == ext_arg_name:
            ext_arg = arg << 16
            op = None
        else:
            op = Op(op_name, arg)

        addr_ops.append((op_addr, op))

    ops = []
    for op_addr, op in addr_ops:
        label = addr_labels.get(op_addr)
        if label is not None:
            ops.append(label)

        if op is not None:
            ops.append(op)

    return ops


def assemble(ops, op_specs=None):
    """
    Assemble a set of :class:`Op` and :class:`Label` instance back into
    bytecode.

    Arguments:
        ops(list): A list of opcodes and labels (as returned by
            :func:`disassemble`).
        op_specs: The opcode specification of the targeted python version. If
            this is ``None`` the specification of the currently running python
            version will be used.

    Returns:
        bytes: The assembled bytecode.
    """

    def encode_op(op_code, op_arg=None):
        if op_arg is None:
            return six.int2byte(op_code)
        else:
            return six.int2byte(op_code) + six.int2byte(op_arg & 255) + six.int2byte(op_arg >> 8)

    if op_specs is None:
        op_specs = OP_SPECS[None]

    opmap = op_specs['opmap']
    hasjrel = op_specs['hasjrel']
    hasjabs = op_specs['hasjabs']
    hasjump = set(hasjrel) | set(hasjabs)
    have_argument = op_specs['have_argument']
    extended_arg = op_specs['extended_arg']

    # A bit of a chicken and egg problem: The address of a label depends on the instructions before it. However,
    # the instructions before a label might depend on the label itself: For very large functions, jumps may
    # require an EXTENDED_ARG opcode if the jump destination is far away. Which we only know when the label
    # has materialized, which means the address of the label will change on the next pass, which might mean
    # a different jump offset might become larger, etc... We run passes until no label changes address.

    output = b''
    label_address = {}
    retry = True
    while retry:
        retry = False
        output = b''
        address = 0
        for op in ops:
            if isinstance(op, Label):
                if label_address.get(op) != address:
                    retry = True
                    label_address[op] = address
                continue

            op_code = opmap[op.name]
            op_arg = op.arg

            if op_arg is None:
                if op_code >= have_argument:
                    # Sanity check.
                    raise ValueError('Opcode %s requires argument.' % op)

                # Encode a single-byte opcode.
                output += encode_op(op_code)
                address += 1
                continue

            if op_code < have_argument:
                # Sanity check.
                raise ValueError('Opcode %s should not have an argument.' % op)

            if isinstance(op_arg, Label):
                if op_code not in hasjump:
                    # Sanity check.
                    raise ValueError('Did not expect label as argument for opcode %s.' % op)

                if op_arg not in ops:
                    # Sanity check.
                    raise ValueError('Label is not part of this op list.')

                # Try to turn the label argument into an address.
                op_arg = label_address.get(op_arg)
                if op_arg is None:
                    # Label hasn't materialized yet, we'll catch it on the next pass.
                    if op_code in hasjabs and address > 65535:
                        # Educated guess that we'll need an extended arg. Might save us a pass.
                        address += 6
                    else:
                        address += 3
                    continue

                if op_code in hasjrel:
                    # Fixup address for relative jump.
                    op_arg -= address + 3
            elif op_code in hasjump:
                # Sanity check.
                raise ValueError('Expected label as argument for opcode %s.' % op)

            if op_arg >= 65536:
                # Encode the extended argument (upper 16 bit of the argument).
                output += encode_op(extended_arg, op_arg >> 16)
                address += 3
                # Adjust the argument to only contain the lower 16 bits.
                op_arg &= 65535

            # Encode the opcode and the argument.
            output += encode_op(op_code, op_arg)
            address += 3

    return output


class Block(object):
    """
    A group of python bytecode ops. Produced by :func:`blocks_from_ops`.

    Arguments:
        label(:class:`Label`): The label of this block. Will be ``None`` for
            the first block.
    """

    def __init__(self, label=None):
        self.label = label  #: The label the block represents.
        self.ops = []  #: The opcodes contained within this block.
        self.next = None  #: A pointer to the next block.


def blocks_from_ops(ops):
    """
    Group a list of :class:`Op` and :class:`Label` instances by label.

    Everytime a label is found, a new :class:`Block` is created. The resulting
    blocks are returned as a dictionary to easily access the target block of a
    jump operation. The keys of this dictionary will be the labels, the values
    will be the :class:`Block` instances. The initial block can be accessed
    by getting the ``None`` item from the dictionary.

    Arguments:
        ops(list): The list of :class:`Op` and :class:`Label` instances (as
            returned by :func:`disassemble`.

    Returns:
        dict: The resulting dictionary of blocks grouped by label.
    """

    blocks = {}
    current_block = blocks[None] = Block()
    for op in ops:
        if isinstance(op, Label):
            next_block = blocks[op] = Block(op)
            current_block.next = next_block
            current_block = next_block
            continue
        current_block.ops.append(op)
    return blocks


def calculate_max_stack_depth(ops, op_specs=None):
    """
    Calculate the maximum stack depth (and required stack size) from a series
    of :class:`Op` and :class:`Label` instances. This is required when you
    manipulate the opcodes in such a way that the stack layout might change
    and you want to re-create a working function from it.

    This is a fairly literal re-implementation of python's stackdepth and
    stackdepth_walk.

    Arguments:
        ops(list): A list of opcodes and labels (as returned by
            :func:`disassemble`).

    Returns:
        int: The calculated maximum stack depth.
    """

    blocks = blocks_from_ops(ops)

    block = blocks[None]
    while block:
        block.seen = False
        block.startdepth = -1
        block = block.next

    if op_specs is None:
        op_specs = OP_SPECS[None]

    stackeffect = op_specs['stackeffect']
    stackeffect_traits = op_specs['stackeffect_traits']

    def walk(block=None, depth=0, max_depth=0):
        if not isinstance(block, Block):
            block = blocks[block]

        if block.seen or block.startdepth >= depth:
            return max_depth

        block.seen = True
        block.startdepth = depth

        for op in block.ops:
            effect = stackeffect[op.name]
            if callable(effect):
                effect = effect(op.arg)

            depth += effect
            if depth > max_depth:
                max_depth = depth

            op_code = op_specs['opmap'][op.name]
            if op_code in op_specs['hasjrel'] or op_code in op_specs['hasjabs']:
                target_depth = depth

                if stackeffect_traits & 1:
                    if op.name == 'FOR_ITER':
                        target_depth -= 2
                    elif op.name in ('SETUP_FINALLY', 'SETUP_EXCEPT'):
                        target_depth += 3
                        if target_depth > max_depth:
                            max_depth = target_depth
                    elif op.name in ('JUMP_IF_TRUE_OR_POP', 'JUMP_IF_FALSE_OR_POP'):
                        depth -= 1

                max_depth = walk(op.arg, target_depth, max_depth)
            if op.name in ('JUMP_ABSOLUTE', 'JUMP_FORWARD'):
                break

        else:
            if block.next:
                max_depth = walk(block.next, depth, max_depth)

        block.seen = False

        return max_depth

    return walk()


BORROW = object()


@kwonly_defaults
def rebuild_func(func, co_argcount=BORROW, co_kwonlyargcount=BORROW, co_nlocals=BORROW, co_stacksize=BORROW,
                 co_flags=BORROW, co_code=BORROW, co_consts=BORROW, co_names=BORROW, co_varnames=BORROW,
                 co_filename=BORROW, co_name=BORROW, co_firstlineno=BORROW, co_lnotab=BORROW, co_freevars=BORROW,
                 co_cellvars=BORROW):
    """rebuild_func(func, *, co_argcount=BORROW, co_kwonlyargcount=BORROW, co_nlocals=BORROW, co_stacksize=BORROW,
                    co_flags=BORROW, co_code=BORROW, co_consts=BORROW, co_names=BORROW, co_varnames=BORROW,
                    co_filename=BORROW, co_name=BORROW, co_firstlineno=BORROW, co_lnotab=BORROW, co_freevars=BORROW,
                    co_cellvars=BORROW)

    Create a new function from a donor but replace the code object
    properties that are specified. If this function is run on python 2,
    ``co_kwonlyargcount`` is ignored as it is only available on python 3.

    Arguments:
        func(function): The donor function. All code object properties not
            explicitly specified will be borrowed from this function.

    Returns:
        func: The new function with the provided and borrowed functions in
            place.
    """

    func_code = six.get_function_code(func)

    co_argcount = co_argcount if co_argcount is not BORROW else func_code.co_argcount
    co_nlocals = co_nlocals if co_nlocals is not BORROW else func_code.co_nlocals
    co_stacksize = co_stacksize if co_stacksize is not BORROW else func_code.co_stacksize
    co_flags = co_flags if co_flags is not BORROW else func_code.co_flags
    co_code = co_code if co_code is not BORROW else func_code.co_code
    co_consts = co_consts if co_consts is not BORROW else func_code.co_consts
    co_names = co_names if co_names is not BORROW else func_code.co_names
    co_varnames = co_varnames if co_varnames is not BORROW else func_code.co_varnames
    co_filename = co_filename if co_filename is not BORROW else func_code.co_filename
    co_name = co_name if co_name is not BORROW else func_code.co_name
    co_firstlineno = co_firstlineno if co_firstlineno is not BORROW else func_code.co_firstlineno
    co_lnotab = co_lnotab if co_lnotab is not BORROW else func_code.co_lnotab
    co_freevars = co_freevars if co_freevars is not BORROW else func_code.co_freevars
    co_cellvars = co_cellvars if co_cellvars is not BORROW else func_code.co_cellvars

    if six.PY2:
        code_obj = types.CodeType(
            co_argcount, co_nlocals, co_stacksize, co_flags, co_code, co_consts, co_names, co_varnames, co_filename,
            co_name, co_firstlineno, co_lnotab, co_freevars, co_cellvars
        )
    else:
        co_kwonlyargcount = co_kwonlyargcount if co_kwonlyargcount is not BORROW else func_code.co_kwonlyargcount
        code_obj = types.CodeType(
            co_argcount, co_kwonlyargcount, co_nlocals, co_stacksize, co_flags, co_code, co_consts, co_names,
            co_varnames, co_filename, co_name, co_firstlineno, co_lnotab, co_freevars, co_cellvars
        )

    return types.FunctionType(code_obj, globals())


def rebuild_func_from_ops(func, ops, **kwargs):
    """
    Rebuild a function from a list of :class:`Op` and :class:`Label`
    instances. It will assemble the opcodes to bytecode and calculate the new
    maximum stack depth. All other properties will be borrowed from the donor
    function unless explicitly specified.

    Arguments:
        func(function): The donor function.
        ops(list): A list of opcodes and labels (as returned by
            :func:`disassemble`).
        **kwargs: All specified keyword arguments will be passed to
            :func:`rebuild_func` except for ``co_code`` and ``co_stacksize``.
    """

    kwargs.update({
        'co_code': assemble(ops),
        'co_stacksize': calculate_max_stack_depth(ops),
    })
    return rebuild_func(func, **kwargs)
