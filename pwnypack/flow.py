import subprocess
import sys
import socket


__all__ = [
    'ProcessChannel',
    'SocketChannel',
    'TCPSocketChannel',
    'Flow',
]


class ProcessChannel(object):
    def __init__(self, *arguments):
        self._process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def read(self, n):
        d = ''
        while n:
            try:
                block = self._process.stdout.read(n)
            except ValueError:
                block = None
            if not block:
                self._process.poll()
                raise EOFError('Process ended')
            d += block
            n -= len(block)
        return d

    def write(self, data):
        self._process.poll()
        if not self._process.returncode is None:
            raise EOFError('Process ended')
        return self._process.stdin.write(data)

    def close(self):
        self._process.communicate()

    def kill(self):
        self._process.kill()


class SocketChannel(object):
    def __init__(self, socket):
        self._socket = socket

    def read(self, n):
        d = ''
        while n:
            try:
                block = self._socket.recv(n)
            except socket.error:
                block = None
            if not block:
                raise EOFError('Socket closed')
            d += block
            n -= len(block)
        return d

    def write(self, data):
        while data:
            try:
                n = self._socket.send(data)
            except socket.error:
                n = None
            if not n:
                raise EOFError('Socket closed')
            data = data[n:]

    def close(self):
        self._socket.close()

    def kill(self):
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()


class TCPSocketChannel(SocketChannel):
    def __init__(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        super(TCPSocketChannel, self).__init__(s)


class Flow(object):
    def __init__(self, channel, echo=False):
        self.channel = channel
        self.echo = echo

    def read(self, n, echo=None):
        d = self.channel.read(n)
        if echo or (echo is None and self.echo):
            sys.stdout.write(d)
        return d

    def read_eof(self, echo=None):
        d = ''
        while True:
            try:
                d += self.read(1, echo)
            except EOFError:
                return d

    def read_until(self, s, echo=None):
        s = list(s)
        s_len = len(s)
        buf = list(self.read(s_len, echo))

        while buf[-s_len:] != s:
            buf.append(self.read(1, echo))

        return ''.join(buf)

    until = read_until

    def readlines(self, n, echo=None):
        return [
            self.until('\n', echo)
            for i in range(n)
        ]

    def readline(self, echo=None):
        return self.readlines(1, echo)[0]

    def write(self, data, echo=None):
        if echo or (echo is None and self.echo):
            sys.stdout.write(data)
        self.channel.write(data)

    def writelines(self, lines, echo=None):
        self.write('\n'.join(lines) + '\n', echo)

    def writeline(self, line='', echo=None):
        self.writelines([line], echo)

    def close(self):
        self.channel.close()

    def kill(self):
        self.channel.kill()

    @classmethod
    def execute(cls, *args, **kwargs):
        echo = kwargs.pop('echo', False)
        return cls(ProcessChannel(*args), echo=echo)

    @classmethod
    def connect_tcp(cls, *args, **kwargs):
        echo = kwargs.pop('echo', False)
        return cls(TCPSocketChannel(*args, **kwargs), echo=echo)
