import socket
from .segment import Segment

BUFFER_SIZE = 1450


class SocketUDP:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def bind(self, ip, port):
        self.sock.bind((ip, port))

    def connect(self, hostname, port):
        self.sock.connect((hostname, port))

    def send(self, segment: Segment):
        self.sock.send(segment.to_bytes())

    def recv(self) -> Segment:
        return Segment.from_bytes(self.sock.recv(BUFFER_SIZE))

    def send_to(self, segment: Segment, addr):
        self.sock.sendto(segment.to_bytes(), addr)

    def recv_from(self):
        data, addr = self.sock.recvfrom(BUFFER_SIZE)
        return Segment.from_bytes(data), addr

    def close(self):
        self.sock.close()

    def set_timeout(self, timeout):
        self.sock.settimeout(timeout)
