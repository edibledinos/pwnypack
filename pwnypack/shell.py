import pwnypack.main


__all__ = []


try:
    import IPython
    have_IPython = True
except ImportError:
    have_IPython = False


def shell(argparse, cmd, args):  # pragma: no cover
    """
    Start an interactive IPython shell with pwny imported globally.
    """

    import pwny
    from IPython import start_ipython
    from IPython.config import get_config

    pwny_locals = dict(
        (key, getattr(pwny, key))
        for key in dir(pwny)
        if not key.startswith('__') and not key == 'shell'
    )

    config = get_config()
    config.InteractiveShell.confirm_exit = False
    start_ipython(
        argv=args,
        config=config,
        user_ns=pwny_locals,
    )
if have_IPython:
    pwnypack.main.register()(shell)
