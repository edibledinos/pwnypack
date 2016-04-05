import argparse
import pwnypack.main


__all__ = []


BANNER = 'Welcome to the interactive pwnypack shell.\n'


try:
    import bpython
    have_bpython = True
except ImportError:
    have_bpython = False


try:
    import IPython
    have_IPython = True
except ImportError:
    have_IPython = False


@pwnypack.main.register()
def shell(_parser, cmd, args):  # pragma: no cover
    """
    Start an interactive python interpreter with pwny imported globally.
    """

    parser = argparse.ArgumentParser(
        prog=_parser.prog,
        description=_parser.description,
    )

    group = parser.add_mutually_exclusive_group()
    group.set_defaults(shell=have_bpython and 'bpython' or (have_IPython and 'ipython' or 'python'))
    if have_bpython:
        group.add_argument(
            '--bpython',
            action='store_const',
            dest='shell',
            const='bpython',
            help='Use the bpython interpreter'
        )
    if have_IPython:
        group.add_argument(
            '--ipython',
            action='store_const',
            dest='shell',
            const='ipython',
            help='Use the IPython interpreter'
        )
    group.add_argument(
        '--python',
        action='store_const',
        dest='shell',
        const='python',
        help='Use the default python interpreter'
    )

    args = parser.parse_args(args)

    import pwny
    pwny_locals = dict(
        (key, getattr(pwny, key))
        for key in dir(pwny)
        if not key.startswith('__') and not key == 'shell'
    )

    if args.shell == 'bpython':
        from bpython import embed
        embed(pwny_locals, banner=BANNER)
    elif args.shell == 'ipython':
        from IPython import start_ipython
        start_ipython(
            argv=['--ext=pwnypack.ipython_ext'],
        )
    else:
        import code
        code.interact(BANNER, local=pwny_locals)
