#! /usr/bin/env python

"""
This program will iterate all pyenv installed python version,
extracts the required opcode maps and outputs the contents for
the py_internals.py file.
"""


from __future__ import print_function

import os
import sys
import subprocess


# These are pretty much hand-crafted dicts from various python version's Python/compile.c.
import six

STACK_EFFECT = {
    26: {'EXTENDED_ARG': None, 'STOP_CODE': None, 'NOP': 0, 'POP_TOP': -1, 'ROT_TWO': 0, 'ROT_THREE': 0, 'DUP_TOP': 1, 'ROT_FOUR': 0, 'UNARY_POSITIVE': 0, 'UNARY_NEGATIVE': 0, 'UNARY_NOT': 0, 'UNARY_CONVERT': 0, 'UNARY_INVERT': 0, 'LIST_APPEND': -2, 'BINARY_POWER': -1, 'BINARY_MULTIPLY': -1, 'BINARY_DIVIDE': -1, 'BINARY_MODULO': -1, 'BINARY_ADD': -1, 'BINARY_SUBTRACT': -1, 'BINARY_SUBSCR': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_TRUE_DIVIDE': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'INPLACE_TRUE_DIVIDE': -1, 'SLICE+0': 1, 'SLICE+1': 0, 'SLICE+2': 0, 'SLICE+3': -1, 'STORE_SLICE+0': -2, 'STORE_SLICE+1': -3, 'STORE_SLICE+2': -3, 'STORE_SLICE+3': -4, 'DELETE_SLICE+0': -1, 'DELETE_SLICE+1': -2, 'DELETE_SLICE+2': -2, 'DELETE_SLICE+3': -3, 'INPLACE_ADD': -1, 'INPLACE_SUBTRACT': -1, 'INPLACE_MULTIPLY': -1, 'INPLACE_DIVIDE': -1, 'INPLACE_MODULO': -1, 'STORE_SUBSCR': -3, 'STORE_MAP': -2, 'DELETE_SUBSCR': -2, 'BINARY_LSHIFT': -1, 'BINARY_RSHIFT': -1, 'BINARY_AND': -1, 'BINARY_XOR': -1, 'BINARY_OR': -1, 'INPLACE_POWER': -1, 'GET_ITER': 0, 'PRINT_EXPR': -1, 'PRINT_ITEM': -1, 'PRINT_NEWLINE': 0, 'PRINT_ITEM_TO': -2, 'PRINT_NEWLINE_TO': -1, 'INPLACE_LSHIFT': -1, 'INPLACE_RSHIFT': -1, 'INPLACE_AND': -1, 'INPLACE_XOR': -1, 'INPLACE_OR': -1, 'BREAK_LOOP': 0, 'WITH_CLEANUP': -1, 'LOAD_LOCALS': 1, 'RETURN_VALUE': -1, 'IMPORT_STAR': -1, 'EXEC_STMT': -3, 'YIELD_VALUE': 0, 'POP_BLOCK': 0, 'END_FINALLY': -1, 'BUILD_CLASS': -2, 'STORE_NAME': -1, 'DELETE_NAME': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'FOR_ITER': 1, 'STORE_ATTR': -2, 'DELETE_ATTR': -1, 'STORE_GLOBAL': -1, 'DELETE_GLOBAL': 0, 'DUP_TOPX': 'lambda arg: arg', 'LOAD_CONST': 1, 'LOAD_NAME': 1, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'BUILD_LIST': 'lambda arg: 1 - arg', 'BUILD_MAP': 1, 'LOAD_ATTR': 0, 'COMPARE_OP': -1, 'IMPORT_NAME': 0, 'IMPORT_FROM': 1, 'JUMP_FORWARD': 0, 'JUMP_IF_FALSE': 0, 'JUMP_IF_TRUE': 0, 'JUMP_ABSOLUTE': 0, 'LOAD_GLOBAL': 1, 'CONTINUE_LOOP': 0, 'SETUP_LOOP': 0, 'SETUP_EXCEPT': 3, 'SETUP_FINALLY': 3, 'LOAD_FAST': 1, 'STORE_FAST': -1, 'DELETE_FAST': 0, 'RAISE_VARARGS': 'lambda arg: -arg', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * (arg >> 8))', 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * (arg >> 8)) - 1', 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * (arg >> 8)) - 1', 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * (arg >> 8)) - 2', 'MAKE_FUNCTION': 'lambda arg: -arg', 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'MAKE_CLOSURE': 'lambda arg: -arg', 'LOAD_CLOSURE': 1, 'LOAD_DEREF': 1, 'STORE_DEREF': -1},
    27: {'EXTENDED_ARG': None, 'STOP_CODE': None, 'NOP': 0, 'POP_TOP': -1, 'ROT_TWO': 0, 'ROT_THREE': 0, 'DUP_TOP': 1, 'ROT_FOUR': 0, 'UNARY_POSITIVE': 0, 'UNARY_NEGATIVE': 0, 'UNARY_NOT': 0, 'UNARY_CONVERT': 0, 'UNARY_INVERT': 0, 'SET_ADD': -1, 'LIST_APPEND': -1, 'MAP_ADD': -2, 'BINARY_POWER': -1, 'BINARY_MULTIPLY': -1, 'BINARY_DIVIDE': -1, 'BINARY_MODULO': -1, 'BINARY_ADD': -1, 'BINARY_SUBTRACT': -1, 'BINARY_SUBSCR': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_TRUE_DIVIDE': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'INPLACE_TRUE_DIVIDE': -1, 'SLICE+0': 0, 'SLICE+1': -1, 'SLICE+2': -1, 'SLICE+3': -2, 'STORE_SLICE+0': -2, 'STORE_SLICE+1': -3, 'STORE_SLICE+2': -3, 'STORE_SLICE+3': -4, 'DELETE_SLICE+0': -1, 'DELETE_SLICE+1': -2, 'DELETE_SLICE+2': -2, 'DELETE_SLICE+3': -3, 'INPLACE_ADD': -1, 'INPLACE_SUBTRACT': -1, 'INPLACE_MULTIPLY': -1, 'INPLACE_DIVIDE': -1, 'INPLACE_MODULO': -1, 'STORE_SUBSCR': -3, 'STORE_MAP': -2, 'DELETE_SUBSCR': -2, 'BINARY_LSHIFT': -1, 'BINARY_RSHIFT': -1, 'BINARY_AND': -1, 'BINARY_XOR': -1, 'BINARY_OR': -1, 'INPLACE_POWER': -1, 'GET_ITER': 0, 'PRINT_EXPR': -1, 'PRINT_ITEM': -1, 'PRINT_NEWLINE': 0, 'PRINT_ITEM_TO': -2, 'PRINT_NEWLINE_TO': -1, 'INPLACE_LSHIFT': -1, 'INPLACE_RSHIFT': -1, 'INPLACE_AND': -1, 'INPLACE_XOR': -1, 'INPLACE_OR': -1, 'BREAK_LOOP': 0, 'SETUP_WITH': 4, 'WITH_CLEANUP': -1, 'LOAD_LOCALS': 1, 'RETURN_VALUE': -1, 'IMPORT_STAR': -1, 'EXEC_STMT': -3, 'YIELD_VALUE': 0, 'POP_BLOCK': 0, 'END_FINALLY': -3, 'BUILD_CLASS': -2, 'STORE_NAME': -1, 'DELETE_NAME': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'FOR_ITER': 1, 'STORE_ATTR': -2, 'DELETE_ATTR': -1, 'STORE_GLOBAL': -1, 'DELETE_GLOBAL': 0, 'DUP_TOPX': 'lambda arg: arg', 'LOAD_CONST': 1, 'LOAD_NAME': 1, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'BUILD_LIST': 'lambda arg: 1 - arg', 'BUILD_SET': 'lambda arg: 1 - arg', 'BUILD_MAP': 1, 'LOAD_ATTR': 0, 'COMPARE_OP': -1, 'IMPORT_NAME': -1, 'IMPORT_FROM': 1, 'JUMP_FORWARD': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'JUMP_IF_TRUE_OR_POP': 0, 'JUMP_ABSOLUTE': 0, 'POP_JUMP_IF_FALSE': -1, 'POP_JUMP_IF_TRUE': -1, 'LOAD_GLOBAL': 1, 'CONTINUE_LOOP': 0, 'SETUP_LOOP': 0, 'SETUP_EXCEPT': 0, 'SETUP_FINALLY': 0, 'LOAD_FAST': 1, 'STORE_FAST': -1, 'DELETE_FAST': 0, 'RAISE_VARARGS': 'lambda arg: -arg', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * (arg >> 8))', 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * (arg >> 8)) - 1', 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * (arg >> 8)) - 1', 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * (arg >> 8)) - 2', 'MAKE_FUNCTION': 'lambda arg: -arg', 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'MAKE_CLOSURE': 'lambda arg: -arg - 1', 'LOAD_CLOSURE': 1, 'LOAD_DEREF': 1, 'STORE_DEREF': -1},
    30: {'JUMP_IF_TRUE': 0, 'JUMP_IF_FALSE': 0, 'DUP_TOPX': 'lambda arg: arg', 'WITH_CLEANUP': -1, 'STORE_LOCALS': -1, 'STORE_MAP': -2, 'STOP_CODE': None, 'ROT_FOUR': 0, 'DELETE_SUBSCR': -2, 'LOAD_CLASSDEREF': 1, 'SET_ADD': -2, 'GET_AWAITABLE': 0, 'SETUP_WITH': 7, 'DELETE_DEREF': 0, 'WITH_CLEANUP_FINISH': -1, 'IMPORT_STAR': -1, 'POP_TOP': -1, 'RETURN_VALUE': -1, 'STORE_ATTR': -2, 'GET_AITER': 0, 'BINARY_MATRIX_MULTIPLY': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_POWER': -1, 'YIELD_VALUE': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'INPLACE_SUBTRACT': -1, 'END_FINALLY': -1, 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'LOAD_CLOSURE': 1, 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'BUILD_TUPLE_UNPACK': 'lambda arg: 1 - arg', 'BINARY_MULTIPLY': -1, 'BEFORE_ASYNC_WITH': 1, 'JUMP_ABSOLUTE': 0, 'IMPORT_NAME': 0, 'INPLACE_POWER': -1, 'INPLACE_ADD': -1, 'MAP_ADD': -2, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'STORE_GLOBAL': -1, 'NOP': 0, 'BINARY_OR': -1, 'POP_JUMP_IF_FALSE': -1, 'BINARY_LSHIFT': -1, 'CONTINUE_LOOP': 0, 'COMPARE_OP': -1, 'JUMP_IF_TRUE_OR_POP': 0, 'INPLACE_MODULO': -1, 'BINARY_MODULO': -1, 'MAKE_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'DUP_TOP': 1, 'INPLACE_LSHIFT': -1, 'LIST_APPEND': -2, 'BINARY_TRUE_DIVIDE': -1, 'BUILD_LIST': 'lambda arg: 1 - arg', 'STORE_DEREF': -1, 'DELETE_ATTR': -1, 'INPLACE_XOR': -1, 'INPLACE_MULTIPLY': -1, 'BINARY_XOR': -1, 'LOAD_DEREF': 1, 'BINARY_SUBTRACT': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'LOAD_NAME': 1, 'BINARY_ADD': -1, 'EXTENDED_ARG': None, 'BUILD_SET_UNPACK': 'lambda arg: 1 - arg', 'BINARY_AND': -1, 'UNARY_NEGATIVE': 0, 'LOAD_GLOBAL': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'BUILD_MAP': 1, 'BUILD_MAP_UNPACK': 'lambda arg: 1 - arg', 'SETUP_EXCEPT': 6, 'GET_ANEXT': 1, 'POP_BLOCK': 0, 'STORE_SUBSCR': -3, 'BUILD_SET': 'lambda arg: 1 - arg', 'LOAD_ATTR': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'UNARY_NOT': 0, 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256))', 'LOAD_BUILD_CLASS': 1, 'JUMP_FORWARD': 0, 'GET_ITER': 0, 'SETUP_FINALLY': 6, 'SETUP_ASYNC_WITH': 6, 'POP_JUMP_IF_TRUE': -1, 'IMPORT_FROM': 1, 'INPLACE_RSHIFT': -1, 'LOAD_CONST': 1, 'DELETE_GLOBAL': 0, 'STORE_FAST': -1, 'UNARY_INVERT': 0, 'LOAD_FAST': 1, 'RAISE_VARARGS': 'lambda arg: -arg', 'PRINT_EXPR': -1, 'POP_EXCEPT': 0, 'INPLACE_AND': -1, 'UNARY_POSITIVE': 0, 'DELETE_NAME': 0, 'BREAK_LOOP': 0, 'BINARY_SUBSCR': -1, 'ROT_THREE': 0, 'YIELD_FROM': -1, 'DUP_TOP_TWO': 2, 'UNPACK_EX': 'lambda arg: (arg & 255) + (arg >> 8)', 'FOR_ITER': 1, 'DELETE_FAST': 0, 'STORE_NAME': -1, 'ROT_TWO': 0, 'INPLACE_TRUE_DIVIDE': -1, 'SETUP_LOOP': 0, 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 2', 'BUILD_LIST_UNPACK': 'lambda arg: 1 - arg', 'MAKE_CLOSURE': 'lambda arg: -1 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'BUILD_MAP_UNPACK_WITH_CALL': 'lambda arg: 1 - (arg & 255)', 'GET_YIELD_FROM_ITER': 0, 'INPLACE_OR': -1, 'BINARY_RSHIFT': -1},
    31: {'DUP_TOPX': 'lambda arg: arg', 'WITH_CLEANUP': -1, 'STORE_LOCALS': -1, 'STORE_MAP': -2, 'STOP_CODE': None, 'ROT_FOUR': 0, 'DELETE_SUBSCR': -2, 'LOAD_CLASSDEREF': 1, 'SET_ADD': -1, 'GET_AWAITABLE': 0, 'SETUP_WITH': 7, 'DELETE_DEREF': 0, 'WITH_CLEANUP_FINISH': -1, 'IMPORT_STAR': -1, 'POP_TOP': -1, 'RETURN_VALUE': -1, 'STORE_ATTR': -2, 'GET_AITER': 0, 'BINARY_MATRIX_MULTIPLY': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_POWER': -1, 'YIELD_VALUE': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'INPLACE_SUBTRACT': -1, 'END_FINALLY': -1, 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'LOAD_CLOSURE': 1, 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'BUILD_TUPLE_UNPACK': 'lambda arg: 1 - arg', 'BINARY_MULTIPLY': -1, 'BEFORE_ASYNC_WITH': 1, 'JUMP_ABSOLUTE': 0, 'IMPORT_NAME': 0, 'INPLACE_POWER': -1, 'INPLACE_ADD': -1, 'MAP_ADD': -2, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'STORE_GLOBAL': -1, 'NOP': 0, 'BINARY_OR': -1, 'POP_JUMP_IF_FALSE': -1, 'BINARY_LSHIFT': -1, 'CONTINUE_LOOP': 0, 'COMPARE_OP': -1, 'JUMP_IF_TRUE_OR_POP': 0, 'INPLACE_MODULO': -1, 'BINARY_MODULO': -1, 'MAKE_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'DUP_TOP': 1, 'INPLACE_LSHIFT': -1, 'LIST_APPEND': -1, 'BINARY_TRUE_DIVIDE': -1, 'BUILD_LIST': 'lambda arg: 1 - arg', 'STORE_DEREF': -1, 'DELETE_ATTR': -1, 'INPLACE_XOR': -1, 'INPLACE_MULTIPLY': -1, 'BINARY_XOR': -1, 'LOAD_DEREF': 1, 'BINARY_SUBTRACT': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'LOAD_NAME': 1, 'BINARY_ADD': -1, 'EXTENDED_ARG': None, 'BUILD_SET_UNPACK': 'lambda arg: 1 - arg', 'BINARY_AND': -1, 'UNARY_NEGATIVE': 0, 'LOAD_GLOBAL': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'BUILD_MAP': 1, 'BUILD_MAP_UNPACK': 'lambda arg: 1 - arg', 'SETUP_EXCEPT': 6, 'GET_ANEXT': 1, 'POP_BLOCK': 0, 'STORE_SUBSCR': -3, 'BUILD_SET': 'lambda arg: 1 - arg', 'LOAD_ATTR': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'UNARY_NOT': 0, 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256))', 'LOAD_BUILD_CLASS': 1, 'JUMP_FORWARD': 0, 'GET_ITER': 0, 'SETUP_FINALLY': 6, 'SETUP_ASYNC_WITH': 6, 'POP_JUMP_IF_TRUE': -1, 'IMPORT_FROM': 1, 'INPLACE_RSHIFT': -1, 'LOAD_CONST': 1, 'DELETE_GLOBAL': 0, 'STORE_FAST': -1, 'UNARY_INVERT': 0, 'LOAD_FAST': 1, 'RAISE_VARARGS': 'lambda arg: -arg', 'PRINT_EXPR': -1, 'POP_EXCEPT': 0, 'INPLACE_AND': -1, 'UNARY_POSITIVE': 0, 'DELETE_NAME': 0, 'BREAK_LOOP': 0, 'BINARY_SUBSCR': -1, 'ROT_THREE': 0, 'YIELD_FROM': -1, 'DUP_TOP_TWO': 2, 'UNPACK_EX': 'lambda arg: (arg & 255) + (arg >> 8)', 'FOR_ITER': 1, 'DELETE_FAST': 0, 'STORE_NAME': -1, 'ROT_TWO': 0, 'INPLACE_TRUE_DIVIDE': -1, 'SETUP_LOOP': 0, 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 2', 'BUILD_LIST_UNPACK': 'lambda arg: 1 - arg', 'MAKE_CLOSURE': 'lambda arg: -1 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'BUILD_MAP_UNPACK_WITH_CALL': 'lambda arg: 1 - (arg & 255)', 'GET_YIELD_FROM_ITER': 0, 'INPLACE_OR': -1, 'BINARY_RSHIFT': -1},
    32: {'DUP_TOPX': 'lambda arg: arg', 'WITH_CLEANUP': -1, 'STORE_LOCALS': -1, 'STORE_MAP': -2, 'STOP_CODE': None, 'ROT_FOUR': 0, 'DELETE_SUBSCR': -2, 'LOAD_CLASSDEREF': 1, 'SET_ADD': -1, 'GET_AWAITABLE': 0, 'SETUP_WITH': 7, 'DELETE_DEREF': 0, 'WITH_CLEANUP_FINISH': -1, 'IMPORT_STAR': -1, 'POP_TOP': -1, 'RETURN_VALUE': -1, 'STORE_ATTR': -2, 'GET_AITER': 0, 'BINARY_MATRIX_MULTIPLY': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_POWER': -1, 'YIELD_VALUE': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'INPLACE_SUBTRACT': -1, 'END_FINALLY': -1, 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'LOAD_CLOSURE': 1, 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'BUILD_TUPLE_UNPACK': 'lambda arg: 1 - arg', 'BINARY_MULTIPLY': -1, 'BEFORE_ASYNC_WITH': 1, 'JUMP_ABSOLUTE': 0, 'IMPORT_NAME': -1, 'INPLACE_POWER': -1, 'INPLACE_ADD': -1, 'MAP_ADD': -2, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'STORE_GLOBAL': -1, 'NOP': 0, 'BINARY_OR': -1, 'POP_JUMP_IF_FALSE': -1, 'BINARY_LSHIFT': -1, 'CONTINUE_LOOP': 0, 'COMPARE_OP': -1, 'JUMP_IF_TRUE_OR_POP': 0, 'INPLACE_MODULO': -1, 'BINARY_MODULO': -1, 'MAKE_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'DUP_TOP': 1, 'INPLACE_LSHIFT': -1, 'LIST_APPEND': -1, 'BINARY_TRUE_DIVIDE': -1, 'BUILD_LIST': 'lambda arg: 1 - arg', 'STORE_DEREF': -1, 'DELETE_ATTR': -1, 'INPLACE_XOR': -1, 'INPLACE_MULTIPLY': -1, 'BINARY_XOR': -1, 'LOAD_DEREF': 1, 'BINARY_SUBTRACT': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'LOAD_NAME': 1, 'BINARY_ADD': -1, 'EXTENDED_ARG': None, 'BUILD_SET_UNPACK': 'lambda arg: 1 - arg', 'BINARY_AND': -1, 'UNARY_NEGATIVE': 0, 'LOAD_GLOBAL': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'BUILD_MAP': 1, 'BUILD_MAP_UNPACK': 'lambda arg: 1 - arg', 'SETUP_EXCEPT': 6, 'GET_ANEXT': 1, 'POP_BLOCK': 0, 'STORE_SUBSCR': -3, 'BUILD_SET': 'lambda arg: 1 - arg', 'LOAD_ATTR': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'UNARY_NOT': 0, 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256))', 'LOAD_BUILD_CLASS': 1, 'JUMP_FORWARD': 0, 'GET_ITER': 0, 'SETUP_FINALLY': 6, 'SETUP_ASYNC_WITH': 6, 'POP_JUMP_IF_TRUE': -1, 'IMPORT_FROM': 1, 'INPLACE_RSHIFT': -1, 'LOAD_CONST': 1, 'DELETE_GLOBAL': 0, 'STORE_FAST': -1, 'UNARY_INVERT': 0, 'LOAD_FAST': 1, 'RAISE_VARARGS': 'lambda arg: -arg', 'PRINT_EXPR': -1, 'POP_EXCEPT': 0, 'INPLACE_AND': -1, 'UNARY_POSITIVE': 0, 'DELETE_NAME': 0, 'BREAK_LOOP': 0, 'BINARY_SUBSCR': -1, 'ROT_THREE': 0, 'YIELD_FROM': -1, 'DUP_TOP_TWO': 2, 'UNPACK_EX': 'lambda arg: (arg & 255) + (arg >> 8)', 'FOR_ITER': 1, 'DELETE_FAST': 0, 'STORE_NAME': -1, 'ROT_TWO': 0, 'INPLACE_TRUE_DIVIDE': -1, 'SETUP_LOOP': 0, 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 2', 'BUILD_LIST_UNPACK': 'lambda arg: 1 - arg', 'MAKE_CLOSURE': 'lambda arg: -1 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'BUILD_MAP_UNPACK_WITH_CALL': 'lambda arg: 1 - (arg & 255)', 'GET_YIELD_FROM_ITER': 0, 'INPLACE_OR': -1, 'BINARY_RSHIFT': -1},
    33: {'DUP_TOPX': 'lambda arg: arg', 'WITH_CLEANUP': -1, 'STORE_LOCALS': -1, 'STORE_MAP': -2, 'STOP_CODE': None, 'ROT_FOUR': 0, 'DELETE_SUBSCR': -2, 'LOAD_CLASSDEREF': 1, 'SET_ADD': -1, 'GET_AWAITABLE': 0, 'SETUP_WITH': 7, 'DELETE_DEREF': 0, 'WITH_CLEANUP_FINISH': -1, 'IMPORT_STAR': -1, 'POP_TOP': -1, 'RETURN_VALUE': -1, 'STORE_ATTR': -2, 'GET_AITER': 0, 'BINARY_MATRIX_MULTIPLY': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_POWER': -1, 'YIELD_VALUE': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'INPLACE_SUBTRACT': -1, 'END_FINALLY': -1, 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'LOAD_CLOSURE': 1, 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'BUILD_TUPLE_UNPACK': 'lambda arg: 1 - arg', 'BINARY_MULTIPLY': -1, 'BEFORE_ASYNC_WITH': 1, 'JUMP_ABSOLUTE': 0, 'IMPORT_NAME': -1, 'INPLACE_POWER': -1, 'INPLACE_ADD': -1, 'MAP_ADD': -2, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'STORE_GLOBAL': -1, 'NOP': 0, 'BINARY_OR': -1, 'POP_JUMP_IF_FALSE': -1, 'BINARY_LSHIFT': -1, 'CONTINUE_LOOP': 0, 'COMPARE_OP': -1, 'JUMP_IF_TRUE_OR_POP': 0, 'INPLACE_MODULO': -1, 'BINARY_MODULO': -1, 'MAKE_FUNCTION': 'lambda arg: -1 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'DUP_TOP': 1, 'INPLACE_LSHIFT': -1, 'LIST_APPEND': -1, 'BINARY_TRUE_DIVIDE': -1, 'BUILD_LIST': 'lambda arg: 1 - arg', 'STORE_DEREF': -1, 'DELETE_ATTR': -1, 'INPLACE_XOR': -1, 'INPLACE_MULTIPLY': -1, 'BINARY_XOR': -1, 'LOAD_DEREF': 1, 'BINARY_SUBTRACT': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'LOAD_NAME': 1, 'BINARY_ADD': -1, 'EXTENDED_ARG': None, 'BUILD_SET_UNPACK': 'lambda arg: 1 - arg', 'BINARY_AND': -1, 'UNARY_NEGATIVE': 0, 'LOAD_GLOBAL': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'BUILD_MAP': 1, 'BUILD_MAP_UNPACK': 'lambda arg: 1 - arg', 'SETUP_EXCEPT': 6, 'GET_ANEXT': 1, 'POP_BLOCK': 0, 'STORE_SUBSCR': -3, 'BUILD_SET': 'lambda arg: 1 - arg', 'LOAD_ATTR': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'UNARY_NOT': 0, 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256))', 'LOAD_BUILD_CLASS': 1, 'JUMP_FORWARD': 0, 'GET_ITER': 0, 'SETUP_FINALLY': 6, 'SETUP_ASYNC_WITH': 6, 'POP_JUMP_IF_TRUE': -1, 'IMPORT_FROM': 1, 'INPLACE_RSHIFT': -1, 'LOAD_CONST': 1, 'DELETE_GLOBAL': 0, 'STORE_FAST': -1, 'UNARY_INVERT': 0, 'LOAD_FAST': 1, 'RAISE_VARARGS': 'lambda arg: -arg', 'PRINT_EXPR': -1, 'POP_EXCEPT': 0, 'INPLACE_AND': -1, 'UNARY_POSITIVE': 0, 'DELETE_NAME': 0, 'BREAK_LOOP': 0, 'BINARY_SUBSCR': -1, 'ROT_THREE': 0, 'YIELD_FROM': -1, 'DUP_TOP_TWO': 2, 'UNPACK_EX': 'lambda arg: (arg & 255) + (arg >> 8)', 'FOR_ITER': 1, 'DELETE_FAST': 0, 'STORE_NAME': -1, 'ROT_TWO': 0, 'INPLACE_TRUE_DIVIDE': -1, 'SETUP_LOOP': 0, 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 2', 'BUILD_LIST_UNPACK': 'lambda arg: 1 - arg', 'MAKE_CLOSURE': 'lambda arg: -2 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'BUILD_MAP_UNPACK_WITH_CALL': 'lambda arg: 1 - (arg & 255)', 'GET_YIELD_FROM_ITER': 0, 'INPLACE_OR': -1, 'BINARY_RSHIFT': -1},
    34: {'DUP_TOPX': 'lambda arg: arg', 'WITH_CLEANUP': -1, 'STORE_LOCALS': -1, 'STORE_MAP': -2, 'STOP_CODE': None, 'ROT_FOUR': 0, 'DELETE_SUBSCR': -2, 'LOAD_CLASSDEREF': 1, 'SET_ADD': -1, 'GET_AWAITABLE': 0, 'SETUP_WITH': 7, 'DELETE_DEREF': 0, 'WITH_CLEANUP_FINISH': -1, 'IMPORT_STAR': -1, 'POP_TOP': -1, 'RETURN_VALUE': -1, 'STORE_ATTR': -2, 'GET_AITER': 0, 'BINARY_MATRIX_MULTIPLY': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_POWER': -1, 'YIELD_VALUE': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'INPLACE_SUBTRACT': -1, 'END_FINALLY': -1, 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'LOAD_CLOSURE': 1, 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'BUILD_TUPLE_UNPACK': 'lambda arg: 1 - arg', 'BINARY_MULTIPLY': -1, 'BEFORE_ASYNC_WITH': 1, 'JUMP_ABSOLUTE': 0, 'IMPORT_NAME': -1, 'INPLACE_POWER': -1, 'INPLACE_ADD': -1, 'MAP_ADD': -2, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'STORE_GLOBAL': -1, 'NOP': 0, 'BINARY_OR': -1, 'POP_JUMP_IF_FALSE': -1, 'BINARY_LSHIFT': -1, 'CONTINUE_LOOP': 0, 'COMPARE_OP': -1, 'JUMP_IF_TRUE_OR_POP': 0, 'INPLACE_MODULO': -1, 'BINARY_MODULO': -1, 'MAKE_FUNCTION': 'lambda arg: -1 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'DUP_TOP': 1, 'INPLACE_LSHIFT': -1, 'LIST_APPEND': -1, 'BINARY_TRUE_DIVIDE': -1, 'BUILD_LIST': 'lambda arg: 1 - arg', 'STORE_DEREF': -1, 'DELETE_ATTR': -1, 'INPLACE_XOR': -1, 'INPLACE_MULTIPLY': -1, 'BINARY_XOR': -1, 'LOAD_DEREF': 1, 'BINARY_SUBTRACT': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'LOAD_NAME': 1, 'BINARY_ADD': -1, 'EXTENDED_ARG': None, 'BUILD_SET_UNPACK': 'lambda arg: 1 - arg', 'BINARY_AND': -1, 'UNARY_NEGATIVE': 0, 'LOAD_GLOBAL': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'BUILD_MAP': 1, 'BUILD_MAP_UNPACK': 'lambda arg: 1 - arg', 'SETUP_EXCEPT': 6, 'GET_ANEXT': 1, 'POP_BLOCK': 0, 'STORE_SUBSCR': -3, 'BUILD_SET': 'lambda arg: 1 - arg', 'LOAD_ATTR': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'UNARY_NOT': 0, 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256))', 'LOAD_BUILD_CLASS': 1, 'JUMP_FORWARD': 0, 'GET_ITER': 0, 'SETUP_FINALLY': 6, 'SETUP_ASYNC_WITH': 6, 'POP_JUMP_IF_TRUE': -1, 'IMPORT_FROM': 1, 'INPLACE_RSHIFT': -1, 'LOAD_CONST': 1, 'DELETE_GLOBAL': 0, 'STORE_FAST': -1, 'UNARY_INVERT': 0, 'LOAD_FAST': 1, 'RAISE_VARARGS': 'lambda arg: -arg', 'PRINT_EXPR': -1, 'POP_EXCEPT': 0, 'INPLACE_AND': -1, 'UNARY_POSITIVE': 0, 'DELETE_NAME': 0, 'BREAK_LOOP': 0, 'BINARY_SUBSCR': -1, 'ROT_THREE': 0, 'YIELD_FROM': -1, 'DUP_TOP_TWO': 2, 'UNPACK_EX': 'lambda arg: (arg & 255) + (arg >> 8)', 'FOR_ITER': 1, 'DELETE_FAST': 0, 'STORE_NAME': -1, 'ROT_TWO': 0, 'INPLACE_TRUE_DIVIDE': -1, 'SETUP_LOOP': 0, 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 2', 'BUILD_LIST_UNPACK': 'lambda arg: 1 - arg', 'MAKE_CLOSURE': 'lambda arg: -2 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'BUILD_MAP_UNPACK_WITH_CALL': 'lambda arg: 1 - (arg & 255)', 'GET_YIELD_FROM_ITER': 0, 'INPLACE_OR': -1, 'BINARY_RSHIFT': -1},
    35: {'DUP_TOPX': 'lambda arg: arg', 'WITH_CLEANUP': -1, 'STORE_LOCALS': -1, 'STORE_MAP': -2, 'STOP_CODE': None, 'ROT_FOUR': 0, 'DELETE_SUBSCR': -2, 'LOAD_CLASSDEREF': 1, 'SET_ADD': -1, 'GET_AWAITABLE': 0, 'SETUP_WITH': 7, 'DELETE_DEREF': 0, 'WITH_CLEANUP_FINISH': -1, 'IMPORT_STAR': -1, 'POP_TOP': -1, 'RETURN_VALUE': -1, 'STORE_ATTR': -2, 'GET_AITER': 0, 'BINARY_MATRIX_MULTIPLY': -1, 'BINARY_FLOOR_DIVIDE': -1, 'BINARY_POWER': -1, 'YIELD_VALUE': 0, 'JUMP_IF_FALSE_OR_POP': 0, 'WITH_CLEANUP_START': 1, 'INPLACE_SUBTRACT': -1, 'END_FINALLY': -1, 'BUILD_SLICE': 'lambda arg: -2 if arg == 3 else -1', 'LOAD_CLOSURE': 1, 'CALL_FUNCTION_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'BUILD_TUPLE_UNPACK': 'lambda arg: 1 - arg', 'BINARY_MULTIPLY': -1, 'BEFORE_ASYNC_WITH': 1, 'JUMP_ABSOLUTE': 0, 'IMPORT_NAME': -1, 'INPLACE_POWER': -1, 'INPLACE_ADD': -1, 'MAP_ADD': -2, 'BUILD_TUPLE': 'lambda arg: 1 - arg', 'STORE_GLOBAL': -1, 'NOP': 0, 'BINARY_OR': -1, 'POP_JUMP_IF_FALSE': -1, 'BINARY_LSHIFT': -1, 'CONTINUE_LOOP': 0, 'COMPARE_OP': -1, 'JUMP_IF_TRUE_OR_POP': 0, 'INPLACE_MODULO': -1, 'BINARY_MODULO': -1, 'MAKE_FUNCTION': 'lambda arg: -1 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'DUP_TOP': 1, 'INPLACE_LSHIFT': -1, 'LIST_APPEND': -1, 'BINARY_TRUE_DIVIDE': -1, 'BUILD_LIST': 'lambda arg: 1 - arg', 'STORE_DEREF': -1, 'DELETE_ATTR': -1, 'INPLACE_XOR': -1, 'INPLACE_MULTIPLY': -1, 'BINARY_XOR': -1, 'LOAD_DEREF': 1, 'BINARY_SUBTRACT': -1, 'INPLACE_FLOOR_DIVIDE': -1, 'LOAD_NAME': 1, 'BINARY_ADD': -1, 'EXTENDED_ARG': None, 'BUILD_SET_UNPACK': 'lambda arg: 1 - arg', 'BINARY_AND': -1, 'UNARY_NEGATIVE': 0, 'LOAD_GLOBAL': 1, 'INPLACE_MATRIX_MULTIPLY': -1, 'BUILD_MAP': 'lambda arg: 1 - 2 * arg', 'BUILD_MAP_UNPACK': 'lambda arg: 1 - arg', 'SETUP_EXCEPT': 6, 'GET_ANEXT': 1, 'POP_BLOCK': 0, 'STORE_SUBSCR': -3, 'BUILD_SET': 'lambda arg: 1 - arg', 'LOAD_ATTR': 0, 'UNPACK_SEQUENCE': 'lambda arg: arg - 1', 'UNARY_NOT': 0, 'CALL_FUNCTION_VAR': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 1', 'CALL_FUNCTION': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256))', 'LOAD_BUILD_CLASS': 1, 'JUMP_FORWARD': 0, 'GET_ITER': 0, 'SETUP_FINALLY': 6, 'SETUP_ASYNC_WITH': 6, 'POP_JUMP_IF_TRUE': -1, 'IMPORT_FROM': 1, 'INPLACE_RSHIFT': -1, 'LOAD_CONST': 1, 'DELETE_GLOBAL': 0, 'STORE_FAST': -1, 'UNARY_INVERT': 0, 'LOAD_FAST': 1, 'RAISE_VARARGS': 'lambda arg: -arg', 'PRINT_EXPR': -1, 'POP_EXCEPT': 0, 'INPLACE_AND': -1, 'UNARY_POSITIVE': 0, 'DELETE_NAME': 0, 'BREAK_LOOP': 0, 'BINARY_SUBSCR': -1, 'ROT_THREE': 0, 'YIELD_FROM': -1, 'DUP_TOP_TWO': 2, 'UNPACK_EX': 'lambda arg: (arg & 255) + (arg >> 8)', 'FOR_ITER': 1, 'DELETE_FAST': 0, 'STORE_NAME': -1, 'ROT_TWO': 0, 'INPLACE_TRUE_DIVIDE': -1, 'SETUP_LOOP': 0, 'CALL_FUNCTION_VAR_KW': 'lambda arg: -((arg % 256) + 2 * ((arg >> 8) % 256)) - 2', 'BUILD_LIST_UNPACK': 'lambda arg: 1 - arg', 'MAKE_CLOSURE': 'lambda arg: -2 - ((arg % 256) + 2 * ((arg >> 8) % 256)) - ((arg >> 16) & 0xffff)', 'BUILD_MAP_UNPACK_WITH_CALL': 'lambda arg: 1 - (arg & 255)', 'GET_YIELD_FROM_ITER': 0, 'INPLACE_OR': -1, 'BINARY_RSHIFT': -1},
}


STACK_TRAITS = {
    26: 0,
    27: 3,
    30: 0,
    31: 0,
    32: 1,
    33: 1,
    34: 3,
    35: 3,
}


SCRIPT_PY2 = '''
import opcode, imp, pickle, struct
print repr({
    'magic': struct.unpack('<H', imp.get_magic()[:2])[0],
    'pickle_highest_protocol': pickle.HIGHEST_PROTOCOL,
    'pickle_default_protocol': getattr(pickle, 'DEFAULT_PROTOCOL', 0),
    'have_argument': opcode.HAVE_ARGUMENT,
    'extended_arg': opcode.EXTENDED_ARG,
    'hascompare': opcode.hascompare,
    'hasconst': opcode.hasconst,
    'hasfree': opcode.hasfree,
    'haslocal': opcode.haslocal,
    'hasname': opcode.hasname,
    'hasjrel': opcode.hasjrel,
    'hasjabs': opcode.hasjabs,
    'opmap': opcode.opmap,
    'opname': opcode.opname,
    'cmp_op': opcode.cmp_op,
})'''


SCRIPT_PY3 = '''
import opcode, imp, pickle, struct
print(repr({
    'magic': struct.unpack('<H', imp.get_magic()[:2])[0],
    'pickle_highest_protocol': pickle.HIGHEST_PROTOCOL,
    'pickle_default_protocol': getattr(pickle, 'DEFAULT_PROTOCOL', 0),
    'have_argument': opcode.HAVE_ARGUMENT,
    'extended_arg': opcode.EXTENDED_ARG,
    'hascompare': opcode.hascompare,
    'hasconst': opcode.hasconst,
    'hasfree': opcode.hasfree,
    'haslocal': opcode.haslocal,
    'hasname': opcode.hasname,
    'hasjrel': opcode.hasjrel,
    'hasjabs': opcode.hasjabs,
    'opmap': opcode.opmap,
    'opname': opcode.opname,
    'cmp_op': opcode.cmp_op,
}))'''


def collect_version_info():
    pyenv_root = subprocess.check_output(['pyenv', 'root']).decode('latin1').split('\n')[0]
    versions = subprocess.check_output(['pyenv', 'versions', '--bare']).decode('latin1')

    version_info = {}

    for py_version in versions.split():
        version = int(''.join(py_version.split('.')[:2]))

        py_executable = os.path.join(pyenv_root, 'versions', py_version, 'bin', 'python')
        try:
            if py_version.startswith('3'):
                output = subprocess.check_output([py_executable, '-c', SCRIPT_PY3]).decode('ascii')
            else:
                output = subprocess.check_output([py_executable, '-c', SCRIPT_PY2]).decode('ascii')
        except:
            print('%s failed' % py_version, file=sys.stderr)
            continue

        version_data = version_info[version] = eval(output)
        opnames = version_data['opname']
        version_data.update({
            'stackeffect': dict((k, v) for k, v in six.iteritems(STACK_EFFECT[version]) if k in opnames),
            'stackeffect_traits': STACK_TRAITS[version],
        })

    return version_info


if __name__ == '__main__':
    version_info = collect_version_info()

    print('''# DO NOT EDIT THIS FILE!
# This file is automatically generated by build_py_internals.py.
"""
This module provides a dictionary that describes the internals of carious
python versions. It is used in various parts of pwnypack (
:mod:`pwnypack.bytecode` and :mod:`pwnypack.pickle`).

Please note that this module is automatically generated by
the ``build_py_internals.py`` script.
"""


import sys


__all__ = ['PY_INTERNALS']


#: This dictionary describes the internals of various python versions.
PY_INTERNALS = {''')
    for version in sorted(version_info):
        info = version_info[version]
        print('''    {version}: {{
        'version': {version},
        'magic': {info[magic]},
        'pickle_highest_protocol': {info[pickle_highest_protocol]},
        'pickle_default_protocol': {info[pickle_default_protocol]},
        'extended_arg': {info[extended_arg]},
        'have_argument': {info[have_argument]},
        'hascompare': {info[hascompare]!r},
        'hasconst': {info[hasconst]!r},
        'hasfree': {info[hasfree]!r},
        'haslocal': {info[haslocal]!r},
        'hasname': {info[hasname]!r},
        'hasjrel': {info[hasjrel]!r},
        'hasjabs': {info[hasjabs]!r},
        'cmp_op': {info[cmp_op]},
        'opmap': {info[opmap]},
        'opname': {info[opname]},
        'stackeffect': {stackeffect},
        'stackeffect_traits': {stackeffect_traits},
    }},'''.format(
            version=version,
            info=info,
            stackeffect='{{{}}}'.format(', '.join('{0!r}: {1}'.format(k, v) for k, v in six.iteritems(info['stackeffect']))),
            stackeffect_traits=STACK_TRAITS[version]
        ))
    print('}')
    print('PY_INTERNALS[None] = PY_INTERNALS[sys.version_info[0] * 10 + sys.version_info[1]]')
