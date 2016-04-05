import functools
import shlex
import pwny
import pwnypack.main


__all__ = []


def call_main_func(func_name, ipython, line):
    pwnypack.main.main([func_name] + shlex.split(line))


def load_ipython_extension(ipython):
    ipython.push(vars(pwny))
    for f_name in pwnypack.main.MAIN_FUNCTIONS:
        ipython.define_magic(f_name, functools.partial(call_main_func, f_name))


def unload_ipython_extension(ipython):
    ipython.drop_by_id(vars(pwny))
