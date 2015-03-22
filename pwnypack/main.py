from __future__ import print_function
from collections import OrderedDict
import io
import os
import sys
import argparse
import six


MAIN_FUNCTIONS = OrderedDict()


def register(name=None):
    def wrapper(f):
        if name is None:
            f_name = f.__name__
        else:
            f_name = name
        if f_name in MAIN_FUNCTIONS:
            raise ValueError('Duplicate application %s' % f_name)
        MAIN_FUNCTIONS[f_name] = f
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


def main():
    def usage():
        global MAIN_FUNCTIONS
        print('Welcome to pwny!')
        print()
        print('Available apps:')
        longest_app_name = max(len(app) for app in MAIN_FUNCTIONS)
        for app, f in MAIN_FUNCTIONS.items():
            fmt = ' - %%-%ds   %%s' % longest_app_name
            print(fmt % (app, f.__doc__.strip().split('\n')[0]))
        print()
        sys.exit(1)

    # Import everything so all main functions are registered.
    import pwny

    global MAIN_FUNCTIONS
    if len(sys.argv) < 2 or sys.argv[1] not in MAIN_FUNCTIONS:
        usage()
    else:
        app, app_args = sys.argv[1], sys.argv[2:]

        f = MAIN_FUNCTIONS[app]
        parser = argparse.ArgumentParser(
            prog='%s %s' % (os.path.split(sys.argv[0])[1], app),
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
            help='inhibit newline after output'
        )

        output = f(parser, app, app_args)

        if output is not None:
            if six.PY3:
                output_bytes = os.fsencode(output)
            else:
                output_bytes = output

            args = parser.parse_args(app_args)
            if args.no_newline:
                end = ''
            else:
                end = '\n'

            if args.format == 'raw':
                writer = io.open(sys.stdout.fileno(), mode='wb', closefd=False)
                writer.write(output_bytes)
                if not args.no_newline:
                    writer.write(b'\n')
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
