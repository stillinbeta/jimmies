import unittest
import jimmies
import tempfile
import ssl

from .util import cert_path
from .echo import EchoServer


class SocketTest(unittest.TestCase):
    TESTSTRING = b"""whose woods these are, I think I know'
    his house is in the village though
    he will not see me stopping here
    to watch his woods fill up with snow
    """

    def test_echo(self):
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        with EchoServer() as sock:
            conn = ctx.wrap_socket(sock, server_hostname='jimmies.local')
            conn.sendall(self.TESTSTRING)
            recv = conn.recv(1024)
            self.assertEqual(recv, self.TESTSTRING)

    def test_negotiated_proto(self):
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        srv = EchoServer()
        srv.context.maximum_version = ssl.TLSVersion.TLSv1_2
        with srv as sock:
            conn = ctx.wrap_socket(sock, server_hostname='jimmies.local')
            self.assertEqual('TLSv1.2', conn.version())

    def test_negotiated_cipher(self):
        # TODO(EKF): this test is extremely brittle based on local openssl version
        ctx = jimmies.create_default_context(cafile=cert_path('rootCA.pem'))
        srv = EchoServer()
        # doesn't work
        # srv.context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256')
        with srv as sock:
            conn = ctx.wrap_socket(sock, server_hostname='jimmies.local')
            self.assertEqual(
                ('TLS13_AES_256_GCM_SHA384', 'TLSv1.3', 256),
                conn.cipher()
            )

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
