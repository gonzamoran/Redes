from .socket_udp import SocketUDP
from .segment import Segment
from .logger import logger


class Connection:

    def __init__(self, sock: SocketUDP):
        self.sock = sock
        self.is_connected = False

        self.expected_seq_num = 0
        self.seq_num = 0

        self.timeout = 0.5
        self.max_retries = 5

        self.retransmissions = 0
        self.duplicate_received = 0
        self.original_segments = 0
        self.received_segments = 0

    def connect(self, ip, port, ope, payload: bytes = b"", pro=False):
        self.sock.set_timeout(self.timeout)
        syn = Segment(self.seq_num, syn=True, ope=ope, payload=payload, pro=pro)

        for _ in range(self.max_retries):
            try:
                self.sock.send_to(syn, (ip, port))
                response, addr = self.sock.recv_from()

                if response.err_flag:
                    raise ConnectionRefusedError(response.payload.decode())

                if response.is_ack() and response.ack_number == self.seq_num:
                    self.sock.connect(addr[0], addr[1])
                    self.is_connected = True
                    self.seq_num += 1
                    return True
            except TimeoutError:  # Permite retransmitir si se pierde el paquete
                self.retransmissions += 1
                logger.debug(f"[TIMEOUT]: Retransmitiendo SYN hacia {ip}:{port}")
                continue

        raise ConnectionError(" [TIMEOUT] El servidor no respondió al handshake")

    def accept(self, segment: Segment, addr):
        self.sock.connect(addr[0], addr[1])
        self.expected_seq_num = (
            segment.sequence_number + 1
        )  # Para que esten sincronizados los numeros de secuencia de ambos lados
        self._send_ack(segment.sequence_number)
        self.is_connected = True

    def close(self):
        self.sock.set_timeout(self.timeout)
        self._send_fin()

        for _ in range(self.max_retries):
            try:
                response, _ = self.sock.recv_from()

                if response.is_ack() and response.ack_number == self.seq_num + 1:
                    self.is_connected = False
                    self.sock.close()
                    return
            except TimeoutError:
                self.retransmissions += 1
                logger.debug("[TIMEOUT]: Retransmitiendo FIN")
                self._send_fin()
            except ConnectionRefusedError:
                break

        self.is_connected = False
        self.sock.close()

    def send(self, data: bytes):
        raise NotImplementedError("Las clases hijas se encargan")

    def recv(self) -> bytes:
        raise NotImplementedError("Las clases hijas se encargan")

    def send_error(self, message):
        error = Segment(
            sequence_number=self.seq_num,
            ack_number=self.expected_seq_num,
            err=True,
            payload=message.encode(),
        )
        self.sock.send(error)

    def _send_ack(self, ack_number):
        ack_segment = Segment(self.seq_num, ack_number, ack=True)
        self.sock.send(ack_segment)

    def _send_fin(self):
        fin_segment = Segment(self.seq_num, fin=True)
        self.sock.send(fin_segment)

    def get_stats(self):
        total_sent = self.original_segments + self.retransmissions
        pct_retrans = (
            (self.retransmissions / total_sent * 100) if total_sent > 0 else 0.0
        )
        total_received = self.received_segments + self.duplicate_received
        pct_dup = (
            (self.duplicate_received / total_received * 100)
            if total_received > 0
            else 0.0
        )
        return {
            "original_segments": self.original_segments,
            "retransmissions": self.retransmissions,
            "total_sent": total_sent,
            "retransmission_pct": pct_retrans,
            "received_segments": self.received_segments,
            "duplicate_received": self.duplicate_received,
            "total_received": total_received,
            "duplicate_pct": pct_dup,
        }
