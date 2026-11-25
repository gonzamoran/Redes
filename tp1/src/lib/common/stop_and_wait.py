# ------------------------------- IMPLEMENTACION STOP & WAIT -------------------------------#
from .fragmentation import fragment_data
from .connection import Connection
from .logger import logger


class StopAndWait(Connection):

    def send(self, data: bytes):
        self.sock.set_timeout(self.timeout)

        segments = fragment_data(data, self.seq_num)
        self.original_segments = len(segments)
        for segment in segments:
            for _ in range(self.max_retries):
                try:
                    self.sock.send(segment)
                    logger.debug("Enviando seq=%s, ahora espero ACK", self.seq_num)
                    response = self.sock.recv()

                    if response.err_flag:
                        message = response.payload.decode(errors="replace")
                        raise ConnectionError(message)

                    next_expected_ack = self.seq_num + segment.payload_length

                    if response.is_ack() and response.ack_number == next_expected_ack:
                        logger.debug("Llego ACK=%s", response.ack_number)
                        self.seq_num = next_expected_ack
                        break
                except TimeoutError:
                    self.retransmissions += 1
                    logger.debug(
                        "[TIMEOUT]: Retransmitiendo seq=%s (retransmision #%s)",
                        self.seq_num,
                        self.retransmissions,
                    )
                    continue
            else:
                raise ConnectionError(
                    "[TIMEOUT] No se pudo confirmar el envio del segmento"
                )

    def recv(self) -> bytes:
        self.sock.set_timeout(None)
        while True:

            segment = self.sock.recv()

            if (
                segment.is_ack()
                and segment.payload_length == 0
                and not segment.is_fin()
            ):
                continue

            if segment.err_flag:
                message = segment.payload.decode(errors="replace")
                raise ConnectionError(message)

            if segment.is_fin():
                self._send_ack(segment.sequence_number + 1)
                self.is_connected = False
                return b""

            if segment.sequence_number == self.expected_seq_num:
                self.expected_seq_num += segment.payload_length
                self.received_segments += 1
                self._send_ack(self.expected_seq_num)
                return segment.payload

            self.duplicate_received += 1
            logger.debug(
                "Segmento duplicado recibido seq=%s (esperado=%s, total duplicados=%s)",
                segment.sequence_number,
                self.expected_seq_num,
                self.duplicate_received,
            )
            self._send_ack(self.expected_seq_num)
