import socket
import jimmies as ssl
# import ssl
import pprint
import time

hostname = 'steven'
context = ssl.create_default_context(cafile="ssl/rootCA.pem")

def main():
    with socket.create_connection((hostname, 4433)) as sock:
        conn =  context.wrap_socket(sock, server_hostname=hostname)
        context is conn.context
        conn.do_handshake()
        print(conn.version())
        buf = bytearray(1024)
        conn.sendall(b"GET /test.py HTTP/1.0\r\nHost: steven\r\n\r\n")
        num = conn.recv_into(buf)
        pprint.pprint(buf[0:num].split(b"\r\n"))
        print(conn.cipher())


if __name__ == "__main__":
    main()
