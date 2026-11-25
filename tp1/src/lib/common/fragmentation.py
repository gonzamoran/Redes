from .segment import Segment

MAX_PAYLOAD_SIZE = 1438  # 1450 bytes de limite de socket_udp.py - 12 bytes del header


def fragment_data(data: bytes, initial_seq_num: int) -> list[Segment]:
    """
    Fragmenta los datos en segmentos de tamaño MAX_PAYLOAD_SIZE como maximo.
    """
    segments = []
    seq_num = initial_seq_num
    for i in range(0, len(data), MAX_PAYLOAD_SIZE):
        payload = data[i : i + MAX_PAYLOAD_SIZE]
        segment = Segment(seq_num, payload=payload)
        segments.append(segment)
        seq_num += len(payload)
    return segments
