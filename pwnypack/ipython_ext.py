import shlex
import pwny
import pwnypack.main
from IPython.core.magic import register_line_magic


__all__ = []


def wrap_main(func_name):
    def wrapper(line):
        pwnypack.main.main([func_name] + shlex.split(line))
    return wrapper


for f_name, f_dict in pwnypack.main.MAIN_FUNCTIONS.items():
    register_line_magic(f_name)(wrap_main(f_name))


def load_ipython_extension(ipython):
    ipython.push(vars(pwny))


def unload_ipython_extension(ipython):
    ipython.drop_by_id(vars(pwny))
