import socket
import jimmies as ssl
import pprint
import time

hostname = 'steven'
context = ssl.create_default_context(cafile="myCA.pem")

def main():
    with socket.create_connection((hostname, 4433)) as sock:
        conn =  context.wrap_socket(sock, server_hostname=hostname)
        conn.do_handshake()
        print(conn.version())
        conn.sendall(b"HEAD / HTTP/1.0\r\nHost: www.python.org\r\n\r\n")
        time.sleep(1)
        pprint.pprint(conn.recv(1024).split(b"\r\n"))

if __name__ == "__main__":
    main()
