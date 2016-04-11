from __future__ import print_function

import inspect
import opcode

import six

from pwnypack.shellcode.ops import SyscallInvoke, LoadRegister
from pwnypack.shellcode.types import Register, Offset, Buffer
from pwnypack import bytecode as bc


__all__ = ['translate']


def translate(env, func, *args, **kwargs):
    """
    Given a shellcode environment, a function and its parameters, translate
    the function to binary shellcode.

    Arguments:
        env(~pwnypack.shellcode.base.Base): An instance of a shellcode
            environment.
        func(callable): The function to translate to shellcode.
        args(...): The positional arguments for the function.
        kwargs(...): The keyword arguments for the function.

    Returns:
        bytes: The translated shellcode.
    """

    func_code = six.get_function_code(func)
    ops = bc.disassemble(func_code.co_code)

    program = []

    f_args = inspect.getcallargs(func, *args, **kwargs)
    variables = dict(
        (func_code.co_varnames.index(arg_name), arg_value)
        for arg_name, arg_value in six.iteritems(f_args)
    )

    stack = []
    for op in ops:
        if op.name == 'LOAD_CONST':
            stack.append(func_code.co_consts[op.arg])

        elif op.name == 'LOAD_GLOBAL':
            stack.append(getattr(env, func_code.co_names[op.arg]))

        elif op.name == 'LOAD_FAST':
            var_name = func_code.co_varnames[op.arg]
            env_var = getattr(env, var_name, None)
            if isinstance(env_var, Register):
                stack.append(env_var)
            else:
                stack.append(variables[op.arg])

        elif op.name == 'BUILD_LIST':
            items = stack[-op.arg:]
            del stack[-op.arg:]
            stack.append(items)

        elif op.name == 'LOAD_ATTR':
            obj = stack.pop()
            stack.append(getattr(obj, func_code.co_names[op.arg]))

        elif op.name == 'CALL_FUNCTION':
            if op.arg:
                f_args = stack[-op.arg:]
                del stack[-op.arg:]
            else:
                f_args = []

            f = stack.pop()
            stack.append(f(*f_args))

        elif op.name == 'STORE_FAST':
            value = stack.pop()
            var_name = func_code.co_varnames[op.arg]
            env_var = getattr(env, var_name, None)

            if isinstance(env_var, Register):
                program.append(LoadRegister(env_var, value))
            elif isinstance(value, (Buffer, Offset)):
                variables[op.arg] = value
            else:
                variables[op.arg] = env.alloc_data(value)

        elif op.name == 'POP_TOP':
            value = stack.pop()
            if isinstance(value, SyscallInvoke):
                program.append(value)
            else:
                raise ValueError('No idea how to compile %s' % value)

        elif op.name == 'RETURN_VALUE':
            stack.pop()

        else:
            raise RuntimeError('Unsupported opcode: %s' % op.name)

    return program
