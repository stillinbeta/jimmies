import socket
import jimmies as ssl

hostname = 'www.python.org'
context = ssl.create_default_context()

def main():
    with socket.create_connection((hostname, 443)) as sock:
        ctx =  context.wrap_socket(sock, server_hostname=hostname)
        ctx.do_handshake()
        print(ctx.version())

if __name__ == "__main__":
    main()
