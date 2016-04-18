"""
The Flow module lets you connect to processes or network services using a
unified API. It is primarily designed for synchronous communication flows.

It is based around the central :class:`Flow` class which uses a ``Channel``
to connect to a process. The :class:`Flow` class then uses the primitives
exposed by the ``Channel`` to provide a high level API for reading/receiving
and writing/sending data.


Examples:
    >>> from pwny import *
    >>> f = Flow.connect_tcp('ced.pwned.systems', 80)
    >>> f.writelines([
    ...     b'GET / HTTP/1.0',
    ...     b'Host: ced.pwned.systems',
    ...     b'',
    ... ])
    >>> line = f.readline().strip()
    >>> print(line == b'HTTP/1.0 200 OK')
    True
    >>> f.until(b'\\r\\n\\r\\n')
    >>> f.read_eof(echo=True)
    ... lots of html ...

    >>> from pwny import *
    >>> f = Flow.execute('cat')
    >>> f.writeline(b'hello')
    >>> f.readline(echo=True)
"""

import subprocess
import sys
import socket
import select
try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False


__all__ = [
    'ProcessChannel',
    'SocketChannel',
    'TCPClientSocketChannel',
    'Flow',
]


class ProcessChannel(object):
    """ProcessChannel(executable, argument..., redirect_stderr=False)

    This channel type allows controlling processes. It uses python's
    ``subprocess.Popen`` class to execute a process and allows you to
    communicate with it.

    Args:
        executable(str): The executable to start.
        argument...(list of str): The arguments to pass to the executable.
        redirect_stderr(bool): Whether to also capture the output of stderr.
    """

    def __init__(self, executable, *arguments, **kwargs):
        if kwargs.get('redirect_stderr'):
            stderr = subprocess.STDOUT
        else:
            stderr = None

        self._process = subprocess.Popen(
            (executable,) + tuple(arguments),
            bufsize=0,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
        )

    def fileno(self):
        """
        Return the file descriptor number for the stdout channel of this
        process.
        """

        return self._process.stdout.fileno()

    def read(self, n):
        """
        Read *n* bytes from the subprocess' output channel.

        Args:
            n(int): The number of bytes to read.

        Returns:
            bytes: *n* bytes of output.

        Raises:
            EOFError: If the process exited.
        """

        d = b''
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
        """
        Write *n* bytes to the subprocess' input channel.

        Args:
            data(bytes): The data to write.

        Raises:
            EOFError: If the process exited.
        """

        self._process.poll()
        if self._process.returncode is not None:
            raise EOFError('Process ended')
        self._process.stdin.write(data)

    def close(self):
        """
        Wait for the subprocess to exit.
        """

        self._process.communicate()

    def kill(self):
        """
        Terminate the subprocess.
        """

        self._process.kill()


class SocketChannel(object):
    """
    This channel type allows controlling sockets.

    Args:
        socket(socket.socket): The (already connected) socket to control.
    """

    def __init__(self, sock):
        self._socket = sock

    def fileno(self):
        """
        Return the file descriptor number for the socket.
        """

        return self._socket.fileno()

    def read(self, n):
        """
        Receive *n* bytes from the socket.

        Args:
            n(int): The number of bytes to read.

        Returns:
            bytes: *n* bytes read from the socket.

        Raises:
            EOFError: If the socket was closed.
        """

        d = b''
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
        """
        Send *n* bytes to socket.

        Args:
            data(bytes): The data to send.

        Raises:
            EOFError: If the socket was closed.
        """

        while data:
            try:
                n = self._socket.send(data)
            except socket.error:
                n = None
            if not n:
                raise EOFError('Socket closed')
            data = data[n:]

    def close(self):
        """
        Close the socket gracefully.
        """

        self._socket.close()

    def kill(self):
        """
        Shut down the socket immediately.
        """

        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()


class TCPClientSocketChannel(SocketChannel):
    """
    Convenience subclass of :class:`SocketChannel` that allows you to connect
    to a TCP hostname / port pair easily.

    Args:
        host(str): The hostname or IP address to connect to.
        port(int): The port number to connect to.
    """

    def __init__(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        super(TCPClientSocketChannel, self).__init__(s)


class TCPServerSocketChannel(SocketChannel):
    """
    Convenience subclass of :class:`SocketChannel` that waits for a remote
    client to connect.

    Args:
        host(str): The hostname or IP address to connect to. Defaults to all
            IP adresses.
        port(int): The port number to connect to. Defaults to a random port
            chosen by the OS.
    """

    def __init__(self, host='', port=0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        cs, _ = s.accept()
        s.close()
        super(TCPServerSocketChannel, self).__init__(cs)


if HAVE_PARAMIKO:
    class SSHClient(paramiko.client.SSHClient):
        """
        Wrapper around Paramiko's SSHClient that produces Flow instances when
        calling :meth:`SSHClient.execute` and :meth:`SSHClient.invoke_shell`.

        Since `pwnypack` is usually used for CTFs, the missing host key policy
        is set to warn and accept.
        """

        def __init__(self):
            super(SSHClient, self).__init__()
            self.set_missing_host_key_policy(paramiko.client.WarningPolicy())

        def execute(self, command, pty=False, echo=False):
            """
            Execute `command` on the server this :class:`SSHClient` instance is connected
            to.

            Args:
                command(str): The command to execute on the remote server.
                pty(bool): Request a pseudo-terminal from the server. Note: If
                    this is `False` (the default) then `stderr` will be combined
                    into `stdout` to prevent the buffers from filling up.
                echo(bool): Whether to write the read data to stdout.

            Returns:
                :class:`Flow`: A Flow instance initialised with the SSH channel.
            """

            channel = self.get_transport().open_session()
            if pty:
                channel.get_pty()
            else:
                channel.set_combine_stderr(True)
            channel.exec_command(command)
            return Flow(SocketChannel(channel), echo=echo)

        def invoke_shell(self, pty=True, echo=False):
            """
            Start a new shell on the server this :class:`SSHClient` is connected
            to.

            Args:
                pty(bool): Request a pseudo-terminal from the server. Note: If
                    this is `False` then `stderr` will be combined into `stdout`
                    to prevent the buffers from filling up.
                echo(bool): Whether to write the read data to stdout.

            Returns:
                :class:`Flow`: A Flow instance initialised with the SSH channel.
            """

            channel = self.get_transport().open_session()
            if pty:
                channel.get_pty()
            else:
                channel.set_combine_stderr(True)
            channel.invoke_shell()
            return Flow(SocketChannel(channel), echo=echo)
else:
    class SSHClient(object):
        def __init__(self):
            raise NotImplementedError('pwnypack\'s ssh functionality depends on paramiko, please install it.')


class Flow(object):
    """
    The core class of *Flow*. Takes a channel and exposes synchronous
    utility functions for communications.

    Usually, you'll use the convenience classmethods :meth:`connect_tcp`
    or :meth:`execute` instead of manually creating the constructor
    directly.

    Args:
        channel(``Channel``): A channel.
        echo(bool): Whether or not to echo all input / output.
    """

    def __init__(self, channel, echo=False):
        self.channel = channel
        self.echo = echo

    def read(self, n, echo=None):
        """
        Read *n* bytes from the channel.

        Args:
            n(int): The number of bytes to read from the channel.
            echo(bool): Whether to write the read data to stdout.

        Returns:
            bytes: *n* bytes of data.

        Raises:
            EOFError: If the channel was closed.
        """

        d = self.channel.read(n)
        if echo or (echo is None and self.echo):
            sys.stdout.write(d.decode('latin1'))
            sys.stdout.flush()
        return d

    def read_eof(self, echo=None):
        """
        Read until the channel is closed.

        Args:
            echo(bool): Whether to write the read data to stdout.

        Returns:
            bytes: The read data.
        """

        d = b''
        while True:
            try:
                d += self.read(1, echo)
            except EOFError:
                return d

    def read_until(self, s, echo=None):
        """
        Read until a certain string is encountered..

        Args:
            s(bytes): The string to wait for.
            echo(bool): Whether to write the read data to stdout.

        Returns:
            bytes: The data up to and including *s*.

        Raises:
            EOFError: If the channel was closed.
        """

        s_len = len(s)
        buf = self.read(s_len, echo)

        while buf[-s_len:] != s:
            buf += self.read(1, echo)

        return buf

    until = read_until  #: Alias of :meth:`read_until`.

    def readlines(self, n, echo=None):
        """
        Read *n* lines from channel.

        Args:
            n(int): The number of lines to read.
            echo(bool): Whether to write the read data to stdout.

        Returns:
            list of bytes: *n* lines which include new line characters.

        Raises:
            EOFError: If the channel was closed before *n* lines were read.
        """

        return [
            self.until(b'\n', echo)
            for _ in range(n)
        ]

    def readline(self, echo=None):
        """
        Read 1 line from channel.

        Args:
            echo(bool): Whether to write the read data to stdout.

        Returns:
            bytes: The read line which includes new line character.

        Raises:
            EOFError: If the channel was closed before a line was read.
        """

        return self.readlines(1, echo)[0]

    def write(self, data, echo=None):
        """
        Write data to channel.

        Args:
            data(bytes): The data to write to the channel.
            echo(bool): Whether to echo the written data to stdout.

        Raises:
            EOFError: If the channel was closed before all data was sent.
        """

        if echo or (echo is None and self.echo):
            sys.stdout.write(data.decode('latin1'))
            sys.stdout.flush()
        self.channel.write(data)

    def writelines(self, lines, sep=b'\n', echo=None):
        """
        Write a list of byte sequences to the channel and terminate them
        with a separator (line feed).

        Args:
            lines(list of bytes): The lines to send.
            sep(bytes): The separator to use after each line.
            echo(bool): Whether to echo the written data to stdout.

        Raises:
            EOFError: If the channel was closed before all data was sent.
        """

        self.write(sep.join(lines + [b'']), echo)

    def writeline(self, line=b'', sep=b'\n', echo=None):
        """
        Write a byte sequences to the channel and terminate it with carriage
        return and line feed.

        Args:
            line(bytes): The line to send.
            sep(bytes): The separator to use after each line.
            echo(bool): Whether to echo the written data to stdout.

        Raises:
            EOFError: If the channel was closed before all data was sent.
        """

        self.writelines([line], sep, echo)

    def close(self):
        """
        Gracefully close the channel.
        """

        self.channel.close()

    def kill(self):
        """
        Terminate the channel immediately.
        """

        self.channel.kill()

    def interact(self):
        """
        Interact with the socket. This will send all keyboard input to the
        socket and input from the socket to the console until an EOF occurs.
        """

        sockets = [sys.stdin, self.channel]
        while True:
            ready = select.select(sockets, [], [])[0]

            if sys.stdin in ready:
                line = sys.stdin.readline().encode('latin1')
                if not line:
                    break
                self.write(line)

            if self.channel in ready:
                self.read(1, echo=True)

    @classmethod
    def execute(cls, executable, *arguments, **kwargs):
        """execute(executable, argument..., redirect_stderr=False, echo=False):

        Set up a :class:`ProcessChannel` and create a :class:`Flow` instance
        for it.

        Args:
            executable(str): The executable to start.
            argument...(list of str): The arguments to pass to the executable.
            redirect_stderr(bool): Whether to also capture the output of stderr.
            echo(bool): Whether to echo read/written data to stdout by default.

        Returns:
            :class:`Flow`: A Flow instance initialised with the process
                channel.
        """

        echo = kwargs.pop('echo', False)
        return cls(ProcessChannel(executable, *arguments, **kwargs), echo=echo)

    @classmethod
    def connect_tcp(cls, host, port, echo=False):
        """
        Set up a :class:`TCPClientSocketChannel` and create a :class:`Flow`
        instance for it.

        Args:
            host(str): The hostname or IP address to connect to.
            port(int): The port number to connect to.
            echo(bool): Whether to echo read/written data to stdout by default.

        Returns:
            :class:`Flow`: A Flow instance initialised with the TCP socket
                channel.
        """

        return cls(TCPClientSocketChannel(host, port), echo=echo)

    @classmethod
    def listen_tcp(cls, host='', port=0, echo=False):
        """
        Set up a :class:`TCPServerSocketChannel` and create a :class:`Flow`
        instance for it.

        Args:
            host(str): The hostname or IP address to bind to.
            port(int): The port number to listen on.
            echo(bool): Whether to echo read/written data to stdout by default.

        Returns:
            :class:`Flow`: A Flow instance initialised with the TCP socket
                channel.
        """

        return cls(TCPServerSocketChannel(host, port), echo=echo)

    @staticmethod
    def connect_ssh(*args, **kwargs):
        """
        Create a new connected :class:`SSHClient` instance. All arguments
        are passed to :meth:`SSHClient.connect`.
        """

        client = SSHClient()
        client.connect(*args, **kwargs)
        return client

    @classmethod
    def execute_ssh(cls, command, *args, **kwargs):
        """execute_ssh(command, arguments..., pty=False, echo=False)

        Execute `command` on a remote server. It first calls
        :meth:`Flow.connect_ssh` using all positional and keyword
        arguments, then calls :meth:`SSHClient.execute` with the command
        and pty / echo options.

        Args:
            command(str): The command to execute on the remote server.
            arguments...: The options for the SSH connection.
            pty(bool): Request a pseudo-terminal from the server.
            echo(bool): Whether to echo read/written data to stdout by default.

        Returns:
            :class:`Flow`: A Flow instance initialised with the SSH channel.
        """

        pty = kwargs.pop('pty', False)
        echo = kwargs.pop('echo', False)
        client = cls.connect_ssh(*args, **kwargs)
        f = client.execute(command, pty=pty, echo=echo)
        f.client = client
        return f


    @classmethod
    def invoke_ssh_shell(cls, *args, **kwargs):
        """invoke_ssh(arguments..., pty=False, echo=False)

        Star a new shell on a remote server. It first calls
        :meth:`Flow.connect_ssh` using all positional and keyword
        arguments, then calls :meth:`SSHClient.invoke_shell` with the
        pty / echo options.

        Args:
            arguments...: The options for the SSH connection.
            pty(bool): Request a pseudo-terminal from the server.
            echo(bool): Whether to echo read/written data to stdout by default.

        Returns:
            :class:`Flow`: A Flow instance initialised with the SSH channel.
        """

        pty = kwargs.pop('pty', True)
        echo = kwargs.pop('echo', False)
        client = cls.connect_ssh(*args, **kwargs)
        f = client.invoke_shell(pty=pty, echo=echo)
        f.client = client
        return f
