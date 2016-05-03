from __future__ import print_function

import inspect

import six

from pwnypack.shellcode.ops import SyscallInvoke, LoadRegister
from pwnypack.shellcode.types import Register, Offset, Buffer
from pwnypack import bytecode as bc


__all__ = ['translate']


def translate(env, func, *args, **kwargs):
    """
    Given a shellcode environment, a function and its parameters, translate
    the function to a list of shellcode operations ready to be compiled or
    assembled using :meth:`~pwnypack.shellcode.base.BaseEnvironment.compile`
    or :meth:`~pwnypack.shellcode.base.BaseEnvironment.assemble`.

    Arguments:
        env(~pwnypack.shellcode.base.Base): An instance of a shellcode
            environment.
        func(callable): The function to translate to shellcode.
        args(...): The positional arguments for the function.
        kwargs(...): The keyword arguments for the function.

    Returns:
        list: The high-level shellcode operations.
    """

    func_code = six.get_function_code(func)
    func_globals = dict(__builtins__)
    func_globals.update(six.get_function_globals(func))

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
            global_name = func_code.co_names[op.arg]
            stack.append(getattr(env, global_name, func_globals.get(global_name)))

        elif op.name == 'LOAD_FAST':
            var_name = func_code.co_varnames[op.arg]
            stack.append(getattr(env, var_name, variables[op.arg]))

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
            var = getattr(env, var_name, variables.get(op.arg, None))
            if isinstance(var, Register):
                program.append(LoadRegister(var, value))
            else:
                variables[op.arg] = value

        elif op.name == 'POP_TOP':
            value = stack.pop()
            if isinstance(value, SyscallInvoke):
                program.append(value)
            elif isinstance(value, list):
                program.extend(value)
            else:
                raise ValueError('No idea how to compile %s' % value)

        elif op.name == 'RETURN_VALUE':
            stack.pop()

        elif op.name == 'DUP_TOP':
            value = stack[-1]
            if isinstance(value, SyscallInvoke):
                stack.insert(-1, env.SYSCALL_RET_REG)
            else:
                stack.append(value)

        else:
            raise RuntimeError('Unsupported opcode: %s' % op.name)

    return program
