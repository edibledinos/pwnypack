import pwnypack.main


__all__ = [
    'shell',
]


@pwnypack.main.register()
def shell(argparse, cmd, args):
    """
    Start an interactive IPython shell with pwny imported globally.
    """

    import pwny
    from IPython import start_ipython
    from IPython.config import get_config

    pwny_locals = {
        key: getattr(pwny, key)
        for key in dir(pwny)
        if not key.startswith('__') and not key == 'shell'
    }

    config = get_config()
    config.InteractiveShell.confirm_exit = False
    start_ipython(
        argv=args,
        config=config,
        user_ns=pwny_locals,
    )
