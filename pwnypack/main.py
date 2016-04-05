from __future__ import print_function
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
import io
import os
import sys
import argparse
import six
import pwnypack.target


__all__ = []


MAIN_FUNCTIONS = OrderedDict()


def register(name=None, symlink=True):
    def wrapper(f):
        if name is None:
            f_name = f.__name__
        else:
            f_name = name
        if f_name in MAIN_FUNCTIONS:
            raise ValueError('Duplicate application %s' % f_name)
        MAIN_FUNCTIONS[f_name] = {
            'callable': f,
            'symlink': symlink,
        }
        return f
    return wrapper


def binary_value_or_stdin(value):
    """
    Return fsencoded value or read raw data from stdin if value is None.
    """
    if value is None:
        reader = io.open(sys.stdin.fileno(), mode='rb', closefd=False)
        return reader.read()
    elif six.PY3:
        return os.fsencode(value)
    else:
        return value


def string_value_or_stdin(value):
    """
    Return value or read string from stdin if value is None.
    """
    if value is None:
        return sys.stdin.read()
    else:
        return value


def add_target_arguments(parser):
    parser.add_argument(
        '--arch', '-a',
        choices=[v.value for v in pwnypack.target.Target.Arch.__members__.values()],
        default=None,
        help='the target architecture',
    )
    parser.add_argument(
        '--bits', '-b',
        type=int,
        choices=[v.value for v in pwnypack.target.Target.Bits.__members__.values()],
        default=None,
        help='the target word size',
    )
    parser.add_argument(
        '--endian', '-e',
        choices=pwnypack.target.Target.Endian.__members__.keys(),
        default=None,
        help='the target endianness',
    )


def target_from_arguments(args):
    if args.endian is not None:
        endian = pwnypack.target.Target.Endian.__members__[args.endian]
    else:
        endian = None
    return pwnypack.target.Target(arch=args.arch, bits=args.bits, endian=endian)


@register(symlink=False)
def symlink(parser, cmd, args):
    """
    Set up symlinks for (a subset of) the pwny apps.
    """

    parser.add_argument(
        'apps',
        nargs=argparse.REMAINDER,
        help='Which apps to create symlinks for.'
    )
    args = parser.parse_args(args)

    base_dir, pwny_main = os.path.split(sys.argv[0])

    for app_name, config in MAIN_FUNCTIONS.items():
        if not config['symlink'] or (args.apps and app_name not in args.apps):
            continue
        dest = os.path.join(base_dir, app_name)
        if not os.path.exists(dest):
            print('Creating symlink %s' % dest)
            os.symlink(pwny_main, dest)
        else:
            print('Not creating symlink %s (file already exists)' % dest)


def main(args=sys.argv):
    def usage():
        global MAIN_FUNCTIONS
        print('Welcome to pwny!')
        print()
        print('Available apps:')
        longest_app_name = max(len(app) for app in MAIN_FUNCTIONS)
        for app, config in MAIN_FUNCTIONS.items():
            f = config['callable']
            fmt = ' - %%-%ds   %%s' % longest_app_name
            print(fmt % (app, f.__doc__.strip().split('\n')[0]))
        print()
        sys.exit(1)

    # Import everything so all main functions are registered.
    import pwny

    global MAIN_FUNCTIONS

    app = os.path.basename(args[0])
    app_args = args[1:]

    if app not in MAIN_FUNCTIONS:
        if len(args) < 2 or app_args[0] not in MAIN_FUNCTIONS:
            usage()
        prog = '%s %s' % (app, app_args[0])
        app, app_args = app_args[0], app_args[1:]
    else:
        prog = app

    f = MAIN_FUNCTIONS[app]['callable']
    parser = argparse.ArgumentParser(
        prog=prog,
        description=f.__doc__,
    )
    parser.add_argument(
        '-f', '--format',
        dest='format',
        choices=['raw', 'hex', 'py', 'sh', 'b64'],
        default='raw',
        help='set output format'
    )
    parser.add_argument(
        '-n', '--no-newline',
        dest='no_newline',
        action='store_const',
        const=True,
        help='inhibit newline after output (off when run from tty)'
    )

    output = f(parser, app, app_args)

    if output is not None:
        if six.PY3:
            output_bytes = os.fsencode(output)
        else:
            output_bytes = output

        args = parser.parse_args(app_args)
        if args.no_newline or not sys.stdout.isatty():
            end = ''
        else:
            end = '\n'

        if args.format == 'raw':
            if isinstance(output, six.binary_type):
                writer = io.open(sys.stdout.fileno(), mode='wb', closefd=False)
                writer.write(output)
                writer.write(end if not six.PY3 else os.fsencode(end))
                writer.close()
            else:
                print(output, end=end)
        elif args.format == 'hex':
            print(pwny.enhex(output_bytes), end=end)
        elif args.format == 'py':
            print(repr(output), end=end)
        elif args.format == 'sh':
            r = repr(output)
            if r.startswith('b\''):
                r = r[1:]
            print('$' + r, end=end)
        elif args.format == 'b64':
            print(pwny.enb64(output_bytes), end=end)
