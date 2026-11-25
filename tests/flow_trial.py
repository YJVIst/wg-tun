"""Exercise independent inbound and upstream sockets in node_trial's namespaces."""
import socket
import sys
from pathlib import Path


def exchange(protocol, local, address, port, message):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(family, kind) as sock:
        sock.settimeout(5)
        if local:
            sock.bind((local, 0))
        sock.connect((address, port))
        sock.sendall(message)
        return sock.recv(512)


def serve(role, protocol, address, ready, upstream=None, upstream_port=None):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(family, kind) as listener:
        listener.bind((address, 0))
        if protocol == "tcp":
            listener.listen()
        listener.settimeout(10)
        Path(ready).write_text(str(listener.getsockname()[1]))
        if protocol == "tcp":
            sock, peer = listener.accept()
            with sock:
                data = sock.recv(512)
                sock.sendall(answer(role, protocol, peer, data, upstream, upstream_port))
        else:
            data, peer = listener.recvfrom(512)
            listener.sendto(answer(role, protocol, peer, data, upstream, upstream_port), peer)


def answer(role, protocol, peer, data, upstream, port):
    if role == "upstream":
        return peer[0].encode() + b" " + data
    return exchange(protocol, None, upstream, int(port), data)


if __name__ == "__main__":
    if sys.argv[1] == "client":
        _, _, proto, local, dst, port = sys.argv
        print(exchange(proto, local, dst, int(port), b"return-path").decode())
    else:
        serve(*sys.argv[1:])
