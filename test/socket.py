import unittest
import jimmies
import ssl
import socket
import sys
import time
import tempfile

from .util import cert_path
from .echo import EchoServer

class SocketTest(unittest.TestCase):
    TESTSTRING = b'whose woods these are, I think I know'

    def test_echo(self):
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        with EchoServer() as sock:
            conn = ctx.wrap_socket(sock, server_hostname='jimmies.local')
            conn.sendall(self.TESTSTRING)
            recv = conn.recv(1024)
            self.assertEqual(recv, self.TESTSTRING)

    def test_echo_bytearray(self):
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        with EchoServer() as sock:
            conn = ctx.wrap_socket(sock, server_hostname='jimmies.local')
            conn.sendall(self.TESTSTRING)
            buf = bytearray(1024)
            recv = conn.recv_into(buf)
            self.assertEqual(buf[0:recv], self.TESTSTRING)

    def test_bad_certname(self):
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        with EchoServer() as sock:
            with self.assertRaisesRegex(jimmies.TLSException, 'invalid certificate'):
                ctx.wrap_socket(sock, server_hostname='other.domain')

    def test_non_socket(self):
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        with self.assertRaises(TypeError):
            with tempfile.TemporaryFile() as f:
                ctx.wrap_socket(f)
