import six

from pwnypack.shellcode.x86 import X86


class X86MutableData(X86):
    """
    Simple strategy that code to be in a writable segment. We just append the
    data to the end of the code.
    """

    def prepare_data(self, data):
        return [], data

    def finalize_data(self, data):
        if data:
            return ['__data:'] + \
               [
                   '\tdb ' + ','.join(hex(b) for b in six.iterbytes(datum)) + '  ; ' + repr(orig_datum)
                   for datum, (_, orig_datum) in six.iteritems(data)
               ]
        else:
            return []
