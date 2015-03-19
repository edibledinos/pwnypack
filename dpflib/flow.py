import subprocess
import sys
import socket


__all__ = [
    'Process',
    'Flow',
]


class Process(object):
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


class Socket(object):
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


class TCPSocket(Socket):
    def __init__(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        super(TCPSocket, self).__init__(s)


class Flow(object):
    def __init__(self, subject):
        self._subject = subject

    def read(self, n):
        return self._subject.read(n)

    def read_until(self, s):
        s = list(s)
        s_len = len(s)
        buf = list(self.read(s_len))

        while buf[-s_len:] != s:
            buf.append(self.read(1))

        return ''.join(buf)

    until = read_until

    def readlines(self, n):
        return [
            self.until('\n')
            for i in range(n)
        ]

    def readline(self):
        return self.readlines(1)[0]

    def write(self, data):
        self._subject.write(data)

    def writelines(self, lines):
        self.write('\n'.join(lines) + '\n')

    def writeline(self, line):
        self.writelines([line])

    def close(self):
        self._subject.close()

    def kill(self):
        self._subject.kill()

    @classmethod
    def execute(cls, *args):
        return cls(Process(*args))

    @classmethod
    def connect_tcp(cls, *args):
        return cls(TCPSocket(*args))
