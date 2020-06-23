import ssl
import socket
import random
import os.path
from multiprocessing import Process
import sys


from .util import cert_path


class EchoServer:
    def __init__(self, **kwargs):
        self.port = random.randint(4000, 6000)
        self.address = ('127.0.0.1', self.port)
        kwargs['purpose'] = ssl.Purpose.CLIENT_AUTH
        self.context = ssl.create_default_context(**kwargs)
        self.context.load_cert_chain(
            certfile=cert_path('jimmies.local.pem'),
            keyfile=cert_path('jimmies.local-key.pem'),
        )
        self.process = Process(target=self._echo, daemon=True)

    def __enter__(self):
        self.socket = socket.create_server(self.address)
        self.process.start()
        self.client = socket.create_connection(self.address)
        return self.client

    def _echo(self):
        while True:
            (sock, _) = self.socket.accept()
            sslsock = self.context.wrap_socket(sock, server_side=True)
            try:
                data = sslsock.recv(1024)
                sslsock.sendall(data)
            finally:
                sslsock.shutdown(socket.SHUT_RDWR)
                sslsock.close()

    def __exit__(self, type_, value, traceback):
        self.process.terminate()
        self.client.close()
        self.socket.close()
