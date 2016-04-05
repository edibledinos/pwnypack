try:
    from jupyter_client import kernelspec as kernelspec
    import ipykernel.kernelspec as ipy_kernelspec
    from notebook.notebookapp import NotebookApp
    have_notebook = True
except ImportError as e:
    have_notebook = False

import pwnypack.main


__all__ = []


if have_notebook:
    class KSM(kernelspec.KernelSpecManager):
        """
        A custom jupyter KernelSpecManager which adds a pwnypack KernelSpec
        that is the same as the native kernel (python 2 / 3) but with the
        pwnypack ipython extension preloaded.
        """

        def _get_kernel_spec_by_name(self, kernel_name, resource_dir):
            if kernel_name == 'pwnypack':
                d = ipy_kernelspec.get_kernel_dict()
                d['display_name'] = 'pwnypack (%s)' % d['display_name']
                d['argv'].append('--ext=pwnypack.ipython_ext')
                return kernelspec.KernelSpec(resource_dir=resource_dir, **d)
            else:
                return super(KSM, self)._get_kernel_spec_by_name(kernel_name, resource_dir)

        def find_kernel_specs(self):
            specs = super(KSM, self).find_kernel_specs()
            if not 'pwnypack' in specs:
                specs['pwnypack'] = ipy_kernelspec.RESOURCES
            return specs


    @pwnypack.main.register()
    def pwnbook(_parser, cmd, args):  # pragma: no cover
        """
        Start a jupyter notebook with the pwnypack enhanced kernel pre-loaded.
        """

        notebook = NotebookApp(kernel_spec_manager_class=KSM)
        notebook.initialize(args)
        notebook.start()
