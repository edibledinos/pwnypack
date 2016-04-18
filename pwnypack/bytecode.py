from __future__ import print_function

import inspect
import opcode
import types

import six
from kwonly_args import kwonly_defaults


OP_SPECS = {
    26: {
        'opmap': {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'POP_TOP': 1, 'EXTENDED_ARG': 143, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 107, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 106, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'JUMP_IF_TRUE': 112, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 104, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'MAKE_FUNCTION': 132, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 18, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'JUMP_IF_FALSE': 111, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 105, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 108, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110},
        'hasjrel': [93, 110, 111, 112, 120, 121, 122],
        'hasjabs': [113, 119],
        'have_argument': 90,
        'extended_arg': 143,
    },
    27: {
        'opmap': {'CALL_FUNCTION': 131, 'DUP_TOP': 4, 'INPLACE_FLOOR_DIVIDE': 28, 'MAP_ADD': 147, 'BINARY_XOR': 65, 'END_FINALLY': 88, 'RETURN_VALUE': 83, 'POP_BLOCK': 87, 'SETUP_LOOP': 120, 'BUILD_SET': 104, 'POP_TOP': 1, 'EXTENDED_ARG': 145, 'SETUP_FINALLY': 122, 'INPLACE_TRUE_DIVIDE': 29, 'CALL_FUNCTION_KW': 141, 'INPLACE_AND': 77, 'SETUP_EXCEPT': 121, 'STORE_NAME': 90, 'IMPORT_NAME': 108, 'LOAD_GLOBAL': 116, 'LOAD_NAME': 101, 'FOR_ITER': 93, 'EXEC_STMT': 85, 'DELETE_NAME': 91, 'BUILD_LIST': 103, 'COMPARE_OP': 107, 'BINARY_OR': 66, 'INPLACE_MULTIPLY': 57, 'STORE_FAST': 125, 'CALL_FUNCTION_VAR': 140, 'SET_ADD': 146, 'LOAD_LOCALS': 82, 'CONTINUE_LOOP': 119, 'PRINT_EXPR': 70, 'DELETE_GLOBAL': 98, 'GET_ITER': 68, 'STOP_CODE': 0, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'LOAD_CLOSURE': 135, 'IMPORT_STAR': 84, 'INPLACE_OR': 79, 'BINARY_SUBTRACT': 24, 'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_LSHIFT': 75, 'INPLACE_MODULO': 59, 'STORE_ATTR': 95, 'BUILD_MAP': 105, 'SETUP_WITH': 143, 'BINARY_DIVIDE': 21, 'INPLACE_RSHIFT': 76, 'PRINT_ITEM_TO': 73, 'UNPACK_SEQUENCE': 92, 'BINARY_MULTIPLY': 20, 'PRINT_NEWLINE_TO': 74, 'NOP': 9, 'LIST_APPEND': 94, 'INPLACE_XOR': 78, 'STORE_GLOBAL': 97, 'INPLACE_SUBTRACT': 56, 'INPLACE_POWER': 67, 'ROT_FOUR': 5, 'DELETE_SUBSCR': 61, 'BINARY_AND': 64, 'BREAK_LOOP': 80, 'MAKE_FUNCTION': 132, 'DELETE_SLICE+1': 51, 'DELETE_SLICE+0': 50, 'DUP_TOPX': 99, 'CALL_FUNCTION_VAR_KW': 142, 'LOAD_ATTR': 106, 'BINARY_TRUE_DIVIDE': 27, 'ROT_TWO': 2, 'IMPORT_FROM': 109, 'DELETE_FAST': 126, 'BINARY_ADD': 23, 'LOAD_CONST': 100, 'STORE_DEREF': 137, 'UNARY_NEGATIVE': 11, 'UNARY_POSITIVE': 10, 'STORE_SUBSCR': 60, 'BUILD_TUPLE': 102, 'BINARY_POWER': 19, 'BUILD_CLASS': 89, 'UNARY_CONVERT': 13, 'BINARY_MODULO': 22, 'DELETE_SLICE+3': 53, 'DELETE_SLICE+2': 52, 'WITH_CLEANUP': 81, 'DELETE_ATTR': 96, 'POP_JUMP_IF_TRUE': 115, 'JUMP_IF_FALSE_OR_POP': 111, 'PRINT_ITEM': 71, 'RAISE_VARARGS': 130, 'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33, 'POP_JUMP_IF_FALSE': 114, 'LOAD_DEREF': 136, 'LOAD_FAST': 124, 'JUMP_IF_TRUE_OR_POP': 112, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_RSHIFT': 63, 'BINARY_SUBSCR': 25, 'YIELD_VALUE': 86, 'ROT_THREE': 3, 'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41, 'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43, 'UNARY_INVERT': 15, 'PRINT_NEWLINE': 72, 'INPLACE_DIVIDE': 58, 'BUILD_SLICE': 133, 'JUMP_ABSOLUTE': 113, 'MAKE_CLOSURE': 134, 'JUMP_FORWARD': 110},
        'hasjrel': [93, 110, 120, 121, 122, 143],
        'hasjabs': [111, 112, 113, 114, 115, 119],
        'have_argument': 90,
        'extended_arg': 145,
    },
    30: {
        'opmap': {'LOAD_CLOSURE': 135, 'POP_BLOCK': 87, 'DELETE_ATTR': 96, 'INPLACE_POWER': 67, 'LOAD_BUILD_CLASS': 71, 'BINARY_SUBSCR': 25, 'INPLACE_FLOOR_DIVIDE': 28, 'WITH_CLEANUP_START': 81, 'POP_TOP': 1, 'CALL_FUNCTION_VAR': 140, 'DUP_TOP_TWO': 5, 'CONTINUE_LOOP': 119, 'IMPORT_STAR': 84, 'GET_AITER': 50, 'RETURN_VALUE': 83, 'GET_AWAITABLE': 73, 'JUMP_IF_TRUE_OR_POP': 112, 'UNARY_INVERT': 15, 'YIELD_VALUE': 86, 'END_FINALLY': 88, 'BREAK_LOOP': 80, 'IMPORT_NAME': 108, 'UNPACK_SEQUENCE': 92, 'DELETE_SUBSCR': 61, 'DELETE_DEREF': 138, 'WITH_CLEANUP_FINISH': 82, 'YIELD_FROM': 72, 'UNARY_POSITIVE': 10, 'SETUP_LOOP': 120, 'STORE_ATTR': 95, 'SETUP_FINALLY': 122, 'SETUP_WITH': 143, 'MAKE_FUNCTION': 132, 'DELETE_GLOBAL': 98, 'IMPORT_FROM': 109, 'INPLACE_OR': 79, 'SET_ADD': 146, 'NOP': 9, 'BINARY_FLOOR_DIVIDE': 26, 'STORE_SUBSCR': 60, 'DELETE_FAST': 126, 'POP_JUMP_IF_TRUE': 115, 'BINARY_ADD': 23, 'BUILD_TUPLE': 102, 'LOAD_CONST': 100, 'BUILD_SET_UNPACK': 153, 'BINARY_MATRIX_MULTIPLY': 16, 'INPLACE_SUBTRACT': 56, 'INPLACE_XOR': 78, 'CALL_FUNCTION_KW': 141, 'INPLACE_MULTIPLY': 57, 'JUMP_ABSOLUTE': 113, 'BINARY_SUBTRACT': 24, 'CALL_FUNCTION_VAR_KW': 142, 'DUP_TOP': 4, 'BINARY_AND': 64, 'LOAD_ATTR': 106, 'LOAD_FAST': 124, 'UNARY_NOT': 12, 'BINARY_LSHIFT': 62, 'BINARY_XOR': 65, 'INPLACE_AND': 77, 'MAP_ADD': 147, 'BUILD_TUPLE_UNPACK': 152, 'EXTENDED_ARG': 144, 'BUILD_SET': 104, 'LIST_APPEND': 145, 'INPLACE_MODULO': 59, 'STORE_NAME': 90, 'JUMP_FORWARD': 110, 'BUILD_MAP_UNPACK': 150, 'COMPARE_OP': 107, 'LOAD_DEREF': 136, 'BINARY_RSHIFT': 63, 'LOAD_NAME': 101, 'BUILD_SLICE': 133, 'SETUP_ASYNC_WITH': 154, 'STORE_FAST': 125, 'INPLACE_RSHIFT': 76, 'ROT_TWO': 2, 'STORE_DEREF': 137, 'STORE_GLOBAL': 97, 'INPLACE_ADD': 55, 'FOR_ITER': 93, 'LOAD_CLASSDEREF': 148, 'BUILD_MAP_UNPACK_WITH_CALL': 151, 'INPLACE_LSHIFT': 75, 'BINARY_OR': 66, 'PRINT_EXPR': 70, 'BEFORE_ASYNC_WITH': 52, 'INPLACE_MATRIX_MULTIPLY': 17, 'BINARY_MODULO': 22, 'JUMP_IF_FALSE_OR_POP': 111, 'BINARY_TRUE_DIVIDE': 27, 'UNARY_NEGATIVE': 11, 'RAISE_VARARGS': 130, 'BUILD_MAP': 105, 'UNPACK_EX': 94, 'POP_JUMP_IF_FALSE': 114, 'BINARY_POWER': 19, 'BUILD_LIST_UNPACK': 149, 'INPLACE_TRUE_DIVIDE': 29, 'GET_YIELD_FROM_ITER': 69, 'GET_ANEXT': 51, 'POP_EXCEPT': 89, 'ROT_THREE': 3, 'BINARY_MULTIPLY': 20, 'GET_ITER': 68, 'BUILD_LIST': 103, 'CALL_FUNCTION': 131, 'DELETE_NAME': 91, 'MAKE_CLOSURE': 134, 'LOAD_GLOBAL': 116, 'SETUP_EXCEPT': 121},
        'hasjrel': [93, 110, 120, 121, 122, 143, 154],
        'hasjabs': [111, 112, 113, 114, 115, 119],
        'have_argument': 90,
        'extended_arg': 144,
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
    for version, op_spec in six.iteritems(OP_SPECS):
        reverse_opmap = dict((v, k) for k, v in six.iteritems(op_spec['opmap']))
        op_spec['opname'] = [
            reverse_opmap[op_code] if op_code in reverse_opmap else '<%d>' % op_code
            for op_code in range(256)
        ]
_build_opnames()


class Op(object):
    def __init__(self, name, arg):
        self.name = name
        self.arg = arg

    def __repr__(self):
        if self.arg is not None:
            return '%s %r' % (self.name, self.arg)
        else:
            return self.name


class Label(object):
    pass


def disassemble(code, op_specs=None):
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


BORROW = object()


@kwonly_defaults
def rebuild_func(func, co_argcount=BORROW, co_kwonlyargcount=BORROW, co_nlocals=BORROW, co_stacksize=BORROW,
                 co_flags=BORROW, co_code=BORROW, co_consts=BORROW, co_names=BORROW, co_varnames=BORROW,
                 co_filename=BORROW, co_name=BORROW, co_firstlineno=BORROW, co_lnotab=BORROW, co_freevars=BORROW,
                 co_cellvars=BORROW):
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
