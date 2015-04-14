Release history
###############

0.6.0 (2015-04-14)
==================

* Bugfixes (and travis-ci integration).
* `API documentation <http://pwnypack.readthedocs.org/>`_ and docstrings.
* Cycle-find can read from stdin.
* Major refactoring of ELF class. It can now parse section headers, program
  headers, symbol tables and extract section, symbols.
* Major refactoring of Target class. It's no longer tied to ELF (ELF is still
  a subclass of Target though).
* A reghex compiler.
* Verifying ROP gadget finder.
* Disassembler functionality (based on ndisasm or capstone).
* A more
* The ability to redirect stderr to stdout in flow.ProcessChannel.
* The ability to create symlinks for commandline apps.
* New commandline apps:
    * ``asm`` to assemble from commandline.
    * ``symbols`` to list the symbol table of an ELF file.
    * ``gadget`` to find ROP gadgets in an ELF file.
    * ``symbol-extract`` to extract a symbol from an ELF file.
    * ``symbol-disasm`` to disassemble a symbol in an ELF file.

0.5.2 (2015-03-22)
==================

* Added command line apps and a customized IPython shell.

0.5.1 (2015-03-21)
==================

* Python3 fixes for flow:
    * Use latin1 for echo mode as not everything will be encodable as utf-8.
    * Disable buffering on subprocess.

0.5.0 (2015-03-21)
==================

* Initial release.
