# ------------------------------ Header de la capa de aplicación + Payload ------------------------------#

HEADER_SIZE = 12
TAMANO_BLOQUE_SACK = 8


class Segment:

    # Esto es asi para indicar que son numeros binarios. Se usan potencias de 2. (1, 2, 4, 8, 16)
    # Para los flags quedan 2 bits libres por ahora.
    FLAG_SYN = 0b00000001
    FLAG_FIN = 0b00000010
    FLAG_OPE = 0b00000100
    FLAG_ACK = 0b00001000
    FLAG_PRO = 0b00010000
    FLAG_ERR = 0b00100000

    def __init__(
        self,
        sequence_number=0,
        ack_number=0,
        payload=b"",
        syn=False,
        fin=False,
        ope=False,
        ack=False,
        pro=False,
        err=False,
        sack_blocks=(),
    ):
        self.sequence_number = sequence_number
        self.ack_number = ack_number
        self.payload = payload
        self.payload_length = len(payload)

        self.syn_flag = syn
        self.fin_flag = fin
        self.ope_flag = ope
        self.ack_flag = ack
        self.pro_flag = pro
        self.err_flag = err

        # Lista de tuplas (inicio, fin). Vacia en el Stop & Wait, es para cuando utiliza SACK.
        self.sack_blocks = list(sack_blocks)

    def to_bytes(self) -> bytes:
        flags_byte = 0

        if self.syn_flag:
            # esto de |= es un OR.
            flags_byte |= Segment.FLAG_SYN
        if self.fin_flag:
            flags_byte |= Segment.FLAG_FIN
        if self.ope_flag:
            flags_byte |= Segment.FLAG_OPE
        if self.ack_flag:
            flags_byte |= Segment.FLAG_ACK
        if self.pro_flag:
            flags_byte |= Segment.FLAG_PRO
        if self.err_flag:
            flags_byte |= Segment.FLAG_ERR

        # Bloques SACK irán al principio del payload.
        # Son una lista de tuplas.
        # Cada tupla es un intervalo [inicio, fin) de
        # numeros de secuencia que el receptor recibió fuera de orden.

        sack_bytes = b""  # El b indica que son bytes y no un string.
        for start, end in self.sack_blocks:
            sack_bytes += start.to_bytes(4, "big") + end.to_bytes(4, "big")
        body = sack_bytes + self.payload

        header = (
            # esto es to_bytes(tamaño, byte_order).
            # El tamaño es cuantos bytes queremos darle, todavia no estan fijos, version inicial
            # El big significa que el bit mas significativo es el primero.
            self.sequence_number.to_bytes(4, "big")
            + self.ack_number.to_bytes(4, "big")
            + flags_byte.to_bytes(1, "big")
            + len(body).to_bytes(2, "big")
            + len(self.sack_blocks).to_bytes(1, "big")
        )
        return header + body

    # Agarra bytes que llegan de la red y lo convierte en un Segment
    @classmethod
    def from_bytes(cls, data: bytes) -> "Segment":

        if len(data) < HEADER_SIZE:
            raise ValueError("segmento demasiado corto")

        sequence_number = int.from_bytes(data[0:4], "big")
        ack_number = int.from_bytes(data[4:8], "big")
        flags = data[8]
        payload_length = int.from_bytes(data[9:11], "big")
        n_sack = data[11]

        if len(data) < HEADER_SIZE + payload_length:
            raise ValueError("payload incompleto")
        if n_sack * TAMANO_BLOQUE_SACK > payload_length:
            raise ValueError("cantidad de bloques SACK invalida")

        body = data[HEADER_SIZE : HEADER_SIZE + payload_length]

        sack_blocks = []
        for i in range(n_sack):
            desde = i * TAMANO_BLOQUE_SACK
            block = body[desde : desde + TAMANO_BLOQUE_SACK]
            start = int.from_bytes(block[0:4], "big")
            end = int.from_bytes(block[4:8], "big")
            sack_blocks.append((start, end))

        payload = body[n_sack * TAMANO_BLOQUE_SACK :]

        syn = bool(flags & cls.FLAG_SYN)
        fin = bool(flags & cls.FLAG_FIN)
        ope = bool(flags & cls.FLAG_OPE)
        ack = bool(flags & cls.FLAG_ACK)
        pro = bool(flags & cls.FLAG_PRO)
        err = bool(flags & cls.FLAG_ERR)

        return cls(
            sequence_number=sequence_number,
            ack_number=ack_number,
            payload=payload,
            syn=syn,
            fin=fin,
            ope=ope,
            ack=ack,
            pro=pro,
            err=err,
            sack_blocks=sack_blocks,
        )

    def is_syn(self):
        return self.syn_flag

    def is_ack(self):
        return self.ack_flag

    def is_fin(self):
        return self.fin_flag
