import ast
import string

import six
from pyparsing import *


__all__ = ['GDB']


class Output(object):
    prefix = ''

    def __init__(self, token, class_, data):
        self.token = token
        self.class_ = class_
        self.data = data if data is not None else {}

    @classmethod
    def parse(cls, s, l, t):
        return cls(*(list(t) + [None, None, None])[:3])

    def __repr__(self):
        data = self.data or {}
        data = ','.join('{}={}'.format(key, repr(value)) for key, value in data.items())
        if data:
            data = ',{}'.format(data)
        return '{}{}{}{}'.format(self.token if self.token is not None else '', self.prefix, self.class_, data)


class ExecAsyncOutput(Output):
    prefix = '*'


class StatusAsyncOutput(Output):
    prefix = '+'


class NotifyAsyncOutput(Output):
    prefix = '='


class ResultRecord(Output):
    prefix = ''


class StreamOutput(str):
    @classmethod
    def parse(cls, s, l, t):
        return cls(t[0])


class LogStreamOutput(StreamOutput):
    pass


class TargetStreamOutput(StreamOutput):
    pass


class ConsoleStreamOutput(StreamOutput):
    pass


def parse_tuple(s, l, t):
    result = {}
    for key, value in zip(t[::2], t[1::2]):
        result[key] = value
    return result


def parse_list(s, l, t):
    return tuple(t)


# Primitives

EOL = (Optional(White(ws=' \t')) + LineEnd()).suppress()
LT_EQUALS = Literal('=').suppress()
LT_COMMA = Literal(',').suppress()

TOKEN = Optional(Word(nums), None)
C_STRING = dblQuotedString().setParseAction(lambda s, l, t: ast.literal_eval(t[0]))
VARIABLE = Combine(Word(string.ascii_lowercase) + Optional(Word(string.ascii_lowercase + '-') + Optional(Word(string.ascii_lowercase))))
VALUE = Forward()
RESULT = VARIABLE + LT_EQUALS + VALUE

VALUE_LIST = delimitedList(VALUE).setParseAction(parse_list)
RESULT_LIST = delimitedList(RESULT).setParseAction(parse_tuple)
OPTIONAL_RESULT_LIST = Optional(LT_COMMA + RESULT_LIST)

# Value types

CONST = C_STRING
TUPLE = nestedExpr('{', '}', RESULT_LIST, None).setParseAction(lambda s, l, t: t[0])
LIST = nestedExpr('[', ']', VALUE_LIST, None).setParseAction(lambda s, l, t: t[0])
VALUE << (CONST | LIST | TUPLE)

# Async records

ASYNC_CLASS = VARIABLE
ASYNC_OUTPUT = ASYNC_CLASS + OPTIONAL_RESULT_LIST

ASYNC_EXEC_MARKER = Literal('*').suppress()
EXEC_ASYNC_OUTPUT = (TOKEN + ASYNC_EXEC_MARKER + ASYNC_OUTPUT) \
    .setParseAction(ExecAsyncOutput.parse)

ASYNC_STATUS_MARKER = Literal('+').suppress()
STATUS_ASYNC_OUTPUT = (TOKEN + ASYNC_STATUS_MARKER + ASYNC_OUTPUT) \
    .setParseAction(StatusAsyncOutput.parse)

ASYNC_NOTIFY_MARKER = Literal('=').suppress()
NOTIFY_ASYNC_OUTPUT = (TOKEN + ASYNC_NOTIFY_MARKER + ASYNC_OUTPUT) \
    .setParseAction(NotifyAsyncOutput.parse)

ASYNC_RECORD = EXEC_ASYNC_OUTPUT | STATUS_ASYNC_OUTPUT | NOTIFY_ASYNC_OUTPUT

# Stream records

CONSOLE_STREAM_MARKER = Literal('~').suppress()
CONSOLE_STREAM_OUTPUT = (CONSOLE_STREAM_MARKER + C_STRING).setParseAction(ConsoleStreamOutput.parse)

TARGET_STREAM_MARKER = Literal('@').suppress()
TARGET_STREAM_OUTPUT = (TARGET_STREAM_MARKER + C_STRING).setParseAction(TargetStreamOutput.parse)

LOG_STREAM_MARKER = Literal('&').suppress()
LOG_STREAM_OUTPUT = (LOG_STREAM_MARKER + C_STRING).setParseAction(LogStreamOutput.parse)

STREAM_RECORD = CONSOLE_STREAM_OUTPUT | TARGET_STREAM_OUTPUT | LOG_STREAM_OUTPUT

# Out of band records / lines

OUT_OF_BAND_RECORD = ((ASYNC_RECORD | STREAM_RECORD) + EOL).leaveWhitespace()

# Result record

RESULT_MARKER = Suppress(Literal('^'))

RESULT_CLASS = Literal('done') | Literal('running') | Literal('connected') | Literal('error') | Literal('exit')
RESULT_OUTPUT = RESULT_CLASS + OPTIONAL_RESULT_LIST()

RESULT_RECORD = (TOKEN + RESULT_MARKER + RESULT_OUTPUT + EOL).setParseAction(ResultRecord.parse).leaveWhitespace()

# Command output

END_OF_OUTPUT = Literal('(gdb)').suppress()

GdbmiParser = ZeroOrMore(OUT_OF_BAND_RECORD) + Optional(RESULT_RECORD) + ZeroOrMore(OUT_OF_BAND_RECORD) + END_OF_OUTPUT


class GDB(object):
    def __init__(self, flow, echo=False):
        self.flow = flow
        self.echo = echo
        self.breakpoints = {}
        self.thread_groups = {}
        self.threads = {}
        self.next()

    def _update_breakpoint(self, bkpt):
        bkpt['number'] = bkpt_number = int(bkpt['number'])
        if bkpt['type'] == 'breakpoint':
            bkpt['addr'] = int(bkpt['addr'], 0) if bkpt['addr'] != '<PENDING>' else None
        bkpt['times'] = int(bkpt['times'])
        bkpt['enabled'] = bkpt['enabled'] == 'y'
        self.breakpoints[bkpt_number] = bkpt
        return bkpt

    def __call__(self, command):
        self.flow.writeline(command, echo=self.echo)
        return self.next()

    def __iter__(self):
        return self

    def __next__(self):
        lines = GdbmiParser.parseString(self.flow.until('(gdb) \n', echo=self.echo))

        console_output = []
        result_record = None

        for line in lines:
            if isinstance(line, ConsoleStreamOutput):
                console_output.append(line)
            elif isinstance(line, NotifyAsyncOutput):
                if line.class_ == 'breakpoint-created':
                    self._update_breakpoint(line.data['bkpt'])
                elif line.class_ == 'breakpoint-modified':
                    self._update_breakpoint(line.data['bkpt'])
                elif line.class_ == 'breakpoint-deleted':
                    del self.breakpoints[int(line.data['id'])]
                elif line.class_ == 'thread-group-added':
                    self.thread_groups[line.data['id']] = {
                        'id': line.data['id'],
                        'running': False,
                        'pid': None,
                        'threads': [],
                    }
                elif line.class_ == 'thread-group-removed':
                    thread_group_id = line.data['id']
                    for thread in self.thread_groups[thread_group_id]:
                        del self.threads[thread['id']]
                    del self.thread_groups[thread_group_id]
                elif line.class_ == 'thread-group-started':
                    self.thread_groups[line.data['id']].update({
                        'running': True,
                        'pid': int(line.data['pid']),
                    })
                elif line.class_ == 'thread-group-exited':
                    thread_group_id = line.data['id']
                    for thread in self.thread_groups[thread_group_id]['threads']:
                        thread['running'] = False
                    self.thread_groups[line.data['id']].update({
                        'running': False,
                        'pid': None,
                    })
                elif line.class_ == 'thread-created':
                    thread_id = int(line.data['id'])
                    group_id = line.data['group-id']
                    group = self.thread_groups[group_id]
                    self.threads[thread_id] = thread = {
                        'id': thread_id,
                        'group': group,
                        'running': False,
                    }
                    group['threads'].append(thread)
                elif line.class_ == 'thread-exited':
                    thread_id = int(line.data['id'])
                    self.threads[thread_id]['running'] = False
            elif isinstance(line, ExecAsyncOutput):
                if line.class_ == 'running':
                    thread_id = line.data['thread-id']
                    if thread_id == 'all':
                        running_thread_id = None
                    else:
                        running_thread_id = int(thread_id)
                    for thread_id, thread in six.iteritems(self.threads):
                        if running_thread_id is None or thread_id == running_thread_id:
                            thread['running'] = True
                elif line.class_ == 'stopped':
                    stopped_threads = line.data.get('stopped-threads', 'all')
                    if stopped_threads == 'all':
                        stopped_threads = None
                    else:
                        stopped_threads = map(int, stopped_threads)
                    for thread_id, thread in six.iteritems(self.threads):
                        if stopped_threads is None or thread_id in stopped_threads:
                            thread['running'] = False
            elif isinstance(line, ResultRecord):
                result_record = line

        console_output = ''.join(console_output)
        if result_record is not None:
            if result_record.class_ == 'error':
                raise Exception(result_record.data['msg'])
            return console_output, result_record.class_, result_record.data
        else:
            return console_output, None, None

    def next(self):
        return self.__next__()

    def exec_continue(self, reverse=False, thread_group=None):
        command = ['-exec-continue']
        if reverse:
            command.append('--reverse')
        if thread_group is not None:
            command.extend(['--thread-group', thread_group])
        return self(' '.join(command))

    def exec_finish(self, reverse=False):
        command = ['-exec-finish']
        if reverse:
            command.append('--reverse')
        return self(' '.join(command))

    def exec_run(self, all=False, thread_group=None, start=False):
        command = ['-exec-run']
        if all:
            command.append('--all')
        elif thread_group is not None:
            command.extend(['--thread-group', thread_group])
        if start:
            command.append('--start')
        return self(' '.join(command))

    def break_after(self, number, count):
        return self('-break-after {} {}'.format(number, count))

    def break_insert(self, location, temporary=False, hardware=False, future=False, disabled=False,
                     tracepoint=False, condition=None, ignore=None, thread_id=None):
        if isinstance(location, int):
            location = '*{}'.format(hex(location))

        command = ['-break-insert']
        if temporary:
            command.append('-t')
        if hardware:
            command.append('-h')
        if future:
            command.append('-f')
        if disabled:
            command.append('-d')
        if tracepoint:
            command.append('-a')
        if condition is not None:
            command.extend(['-c', condition])
        if ignore is not None:
            command.extend(['-i', str(ignore)])
        if thread_id is not None:
            command.extend(['-p', thread_id])
        command.append(str(location))

        token, console, result = self(' '.join(command))
        return token, console, self._update_breakpoint(result['bkpt'])

    def break_delete(self, *breakpoints):
        return self('-break-delete ' + ' '.join(map(str, breakpoints)))

    def start_pie(self):
        self.break_insert('dl_main', temporary=True, future=True)
        self.exec_run()
        self.next()

        output, _, _ = self('info files')
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Entry point: '):
                entrypoint = int(line.split(': ')[1], 0)
                break
        else:
            raise RuntimeError('Could not determine entry point')

        self.break_insert(entrypoint, temporary=True)
        self.exec_continue()
        return self.next()  # Wait for *stopped
