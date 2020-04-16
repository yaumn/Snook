#!/usr/bin/python3


from argparse import ArgumentParser
from base64 import b64decode, b64encode
from cmd import Cmd
from glob import glob
from json import dumps, JSONDecodeError, loads
import logging
from os.path import abspath, getsize, isdir, join
from ntpath import basename
from readline import get_completer_delims, set_completer_delims
from shlex import split
from socket import AF_INET, SHUT_RDWR, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

from alive_progress import alive_bar
from colorama import Fore, init


# Little trick to enable correct path autocompletion on Unix
old_delims = get_completer_delims()
set_completer_delims(old_delims.replace('/', ''))

logger = logging.getLogger('Snook')


class SilentArgumentParser(ArgumentParser):

    def error(message):
        self.exit(2)


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

    def cmdloop(self, intro=None):
        while True:
            try:
                super().cmdloop(intro=intro)
                break
            except KeyboardInterrupt:
                print('^C')

    def complete_download(self, text, line, begidx, endidx):
        parser = SilentArgumentParser()
        parser.add_argument('file', nargs='?', type=str)
        parser.add_argument('-d', '--destination', type=str)

        try:
            args = parser.parse_args(self.split_line_for_completion(line[8:]))
        except SystemExit:
            return

        if args.destination and line.index(args.destination) != begidx:
            return

        path_to_complete = args.destination[:endidx - begidx]
        paths = glob(path_to_complete + '*')

        return paths

    def complete_upload(self, text, line, begidx, endidx):
        parser = SilentArgumentParser()
        parser.add_argument('file', type=str)
        parser.add_argument('-d', '--destination', type=str)

        try:
            args = parser.parse_args(self.split_line_for_completion(line[6:]))
        except SystemExit:
            return

        if args.file and line.index(args.file) != begidx:
            return

        path_to_complete = args.file[:endidx - begidx]
        paths = glob(path_to_complete + '*')

        return paths

    def do_download(self, line):
        parser = ArgumentParser(prog='download',
            description='Download file from remote host')
        parser.add_argument('file', type=str,
            help='Path to the file on the remote host')
        parser.add_argument('-d', '--destination', type=str, default='.',
            help='Destination of the downloaded file')
        try:
            args = parser.parse_args(split(line))
        except SystemExit:
            return

        if not line:
            parser.print_usage()
            return

        logger.debug('Running command: download {}'.format(line))

        self.task_args = args

        p = Packet()
        p.action = 'download'
        p.add_argument('path', args.file)
        self.send_packet(p)
        return self.receive_loop()

    def do_EOF(self, line):
        return self.do_exit()

    def do_exit(self, line=''):
        logger.debug('Running command: {}'.format(line))
        self.sock.shutdown(SHUT_RDWR)
        self.sock.close()
        return True

    def do_upload(self, line):
        parser = ArgumentParser(prog='upload',
            description='Upload file to remote host')
        parser.add_argument('file', type=str,
            help='Path to the file to upload')
        parser.add_argument('-d', '--destination', type=str, default='.',
            help='Destination of the uploaded file')
        try:
            args = parser.parse_args(split(line))
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

        logger.debug('Running command: upload {}'.format(line))

        p.add_argument('dest', args.destination)
        p.add_argument('filename', basename(args.file))
        self.send_packet(p)
        return self.receive_loop()

    def default(self, line):
        logger.debug('Running command: {}'.format(line))
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

        self.print_message('File successfully saved to {}'.format(abspath(file_path)))

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
                        break
                    self.sock.send(data)
                    bar(incr=len(data))


        p = self.receive_json_packet()
        if not isinstance(p, Packet):
            return p

        self.print_message('File successfully uploaded to {}'.format(p.message))

    def print_error(self, text):
        logger.error(Fore.RED + text + Fore.RESET)

    def print_message(self, text):
        logger.info(text)

    def print_warning(self, text):
        logger.warning(Fore.YELLOW + text + Fore.RESET)

    def receive_json_packet(self):
        # TODO: Find a better mechanism for this function that can
        # return a Packet, True or None
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
                logger.error('An unexcepted error happened:', e)
                return None

            break

        return p

    def receive_loop(self):
        p = self.receive_json_packet()
        if not isinstance(p, Packet):
            return p

        try:
            f = getattr(self, 'handle_' + p.action)
        except AttributeError:
            f = getattr(self, 'handle_default')

        if p.cwd:
            self.prompt = 'PS {}> '.format(p.cwd)
        return f(p)

    def send_packet(self, packet):
        self.sock.send(packet.dumps().encode('utf-8'))

    def split_line_for_completion(self, line):
        """ 
        Split a command line like a shell would do but still keep
        empty arguments (i.e. two spaces in a row) to enable autocompletion       
        """
        if not line.endswith('  '):
            line += ' '
        return split(line.replace('  ', ' "" '))


if __name__ == '__main__':
    parser = ArgumentParser(description='Listen for incoming connections')
    parser.add_argument('-H', '--host', type=str, default='0.0.0.0',
        help='Local hostname or IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=1337,
        help='Local port to bind to (default: 1337)')
    parser.add_argument('-l', '--log', nargs='?', type=str,
        help='Path to the file where to log commands and outputs')
    args = parser.parse_args()

    # Setup logger
    logger.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.INFO)
    consoleFormatter = logging.Formatter('%(message)s')
    consoleHandler.setFormatter(consoleFormatter)
    logger.addHandler(consoleHandler)

    if args.log:
        fileHandler = logging.FileHandler(args.log)
        fileHandler.setLevel(logging.DEBUG)
        fileFormatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
        fileHandler.setFormatter(fileFormatter)
        logger.addHandler(fileHandler)

    init()  # colorama

    sock = socket(AF_INET, SOCK_STREAM)

    try:
        # Setup socket
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server_address = (args.host, args.port)
        sock.bind(server_address)
        sock.listen()
        logger.info('Listening on {}:{}'.format(*server_address))
        client_socket, client_address = sock.accept()

        logger.info('Received connection from {}:{}\n'.format(*client_address))
        prompt = Prompt(client_socket)
        prompt.cmdloop()
    except Exception as e:
        logger.exception(e)
        client_socket.shutdown(SHUT_RDWR)
        client_socket.close()
        raise
    finally:
        sock.shutdown(SHUT_RDWR)
        sock.close()
