# -------------------- Implementacion SACK --------------------#
from .fragmentation import fragment_data
from .connection import Connection
from .logger import logger
from .segment import Segment


class SACK(Connection):
    """
    KUROSE explicacion como se hacen los algoritmos con pipelining.

        Esto es asi en Kurose que tiene 1 paquete -> 1 nro de secuencia. Como tenemos con bytes nosotros hay que cambiarlo.

        (Se podria poner al N size como cantidad de paquetes sin confirmar.)

        N size -> Window Size: Cantidad maxima permitida de paquetes que pueden pendientes de confirmacion.
        base : numero de secuencia del paquete enviado mas antiguo que todavia NO se confirmo por un ACK del receptor. (borde izq de la tupla)
        nextseqnum: Es el numero de secuencia que se le asigna al proximo paquete.

        Entonces nos va a quedar algo del estilo:
        [Ya confirmados]   [ En viaje (Sin ACK) ]        [Disponibles ]       [ Bloqueados ]
        0.........base-1  base.........nexseqnum-1   nextseqnum....base+N-1    base + N
    """

    # WINDOW_SIZE = ALGUN VALOR. EN TCP se calcula de manera dinamica, aca es un quilombo.

    def __init__(self, sock, window_size):

        super().__init__(sock)
        # definimos cuantos paquetes pueden estar en vuelo
        self.window_size = window_size
        # si usamos la cte hay que reemplazar ese window_size por self.window_size y sacar el parametro

        # guarda los segmentos enviados pendientes de confirmacion
        # Diccionario {nro_seq, segmento}
        self.segments_falta_ack = {}

        # Buffer de recepción fuera de orden
        # los retenemos para no forzar su retransmisión
        self.recive_buffer = {}

        # retransmisiones en tránsito
        # Evita retransmisiones duplicadas durante el RTT mientras el paquete retransmitido viaja
        self.retransmitted_seqs = set()

    def send(self, data: bytes):
        #configuramos el temporizador de retransmisión (RTO)
        self.sock.set_timeout(self.timeout)

        # TEORÍA: Fragmentación del flujo de bytes de la aplicación en segmentos
        segments = fragment_data(data, self.seq_num)
        cant_segments = len(segments)
        self.original_segments = cant_segments

        cant_acks_recibidos = 0
        indice_seg_enviado = 0

        timeouts_sin_progreso = 0
        self.retransmitted_seqs.clear()

        # mientras haya segmentos para mandar
        while cant_segments != cant_acks_recibidos:
            # mientras haya paquetes disponibles y la cantidad de paquetes pendientes de confirmación en la red sea menor al tamaño de la ventana
            
            while (
                len(self.segments_falta_ack) < self.window_size
                and indice_seg_enviado < cant_segments
            ):
                segment = segments[indice_seg_enviado]

                self.sock.send(segment)
                logger.debug(f"Enviando segment {self.seq_num}")
                
                # guardamos copia en el buffer del emisor hasta que llegue su ACK
                self.segments_falta_ack[segment.sequence_number] = segment
                
                self.seq_num += segment.payload_length
                indice_seg_enviado += 1

            try:
                response = self.sock.recv()
                timeouts_sin_progreso = 0

                if not response.is_ack():
                    continue

                # PROCESAMIENTO DE ACK ACUMULATIVO (Cumulative ACK)
                # En TCP, ack_number confirma todos los bytes contiguos anteriores
                # Si seq + length <= ack_number, el segmento fue recibido correctamente en orden
                
                confirmados = []

                for seq, seg in self.segments_falta_ack.items():
                    if seq + seg.payload_length <= response.ack_number:
                        confirmados.append(seq)

                for seq in confirmados:
                    self.segments_falta_ack.pop(seq)
                    self.retransmitted_seqs.discard(seq)
                    cant_acks_recibidos += 1
                    logger.debug(f"ACK confirmo segment {seq}")

                # PROCESAMIENTO DE BLOQUES SACK 
                # cada bloque [start, end) informa fragmentos recibidos fuera de orden (islas)
                # el emisor los confirma individualmente y los retira de su buffer de retransmisión, evitando retransmitirlos innecesariamente
                for start, end in response.sack_blocks:
                    for seq in list(self.segments_falta_ack.keys()):
                        seg = self.segments_falta_ack[seq]
                        if start <= seq and seq + seg.payload_length <= end:
                            self.segments_falta_ack.pop(seq)
                            self.retransmitted_seqs.discard(seq)
                            cant_acks_recibidos += 1
                            logger.debug(f"SACK confirmo segment {seq}")

                # DETECCIÓN RÁPIDA DE PÉRDIDAS Y RETRANSMISIÓN SELECTIVA
                # si el receptor ya confirmó bloques posteriores a un segmento aún pendiente
                # (seq < highest_sack_end), inferimos que ese segmento intermedio se perdió ("hueco")
                # Se retransmite de inmediato sin esperar al temporizador, solo retransmitimos si el paquete aún no fue retransmitido en este vuelo
                if response.sack_blocks:
                    highest_sack_end = max(end for start, end in response.sack_blocks)
                    for seq, seg in list(self.segments_falta_ack.items()):
                        if (
                            seq < highest_sack_end
                            and seq not in self.retransmitted_seqs
                        ):
                            self.sock.send(seg)
                            self.retransmitted_seqs.add(seq)
                            self.retransmissions += 1
                            logger.debug(
                                f"Reenvio {seq} (retransmision #{self.retransmissions})"
                            )

            except TimeoutError:
                # RECUPERACIÓN POR TEMPORIZADOR (Timeout) y reseteamos el estado de retransmisión
                timeouts_sin_progreso += 1
                if timeouts_sin_progreso >= self.max_retries:
                    raise ConnectionError("[TIMEOUT]")

                logger.debug(f"[TIMEOUT]: Retransmitiendo segmentos pendientes")
                self.retransmitted_seqs.clear()
                for seq_perdido, segment_perdido in self.segments_falta_ack.items():
                    self.sock.send(segment_perdido)
                    self.retransmitted_seqs.add(seq_perdido)
                    self.retransmissions += 1
                    logger.debug(
                        f"Reenviando segment {seq_perdido} (retransmision #{self.retransmissions})"
                    )

    def recv(self) -> bytes:
        # quitamos el temporizador para que el receptor se quede esperando
        self.sock.set_timeout(None)

        while True:
            # Entrega ordenada a la aplicación
            # la capa de transporte garantiza un flujo contiguo. Si expected_seq_num está listo en el buffer, se extrae y se entrega
            if self.expected_seq_num in self.recive_buffer:
                segmento_listo = self.recive_buffer.pop(self.expected_seq_num)

                # Actualizamos el próximo byte que esperamos recibir en el futuro
                self.expected_seq_num += segmento_listo.payload_length
                self.received_segments += 1
                return segmento_listo.payload

            segment = self.sock.recv()

            if (
                segment.is_ack()
                and segment.payload_length == 0
                and not segment.is_fin()
            ):
                continue

            # si terminamos
            if segment.is_fin():
                self._send_ack(segment.sequence_number + 1)
                self.is_connected = False
                return b""

            # Buffer de recepción y detección de duplicados
            # si el segmento es futuro (seq >= expected), se guarda en el buffer de recepción
            # si es anterior o ya existía, es un duplicado duplicado (pero igual se ACKea para resincronizar)
            seq = segment.sequence_number
            if seq >= self.expected_seq_num and seq not in self.recive_buffer:
                self.recive_buffer[seq] = segment
            else:
                self.duplicate_received += 1
                logger.debug(
                    f"Segmento duplicado recibido seq={seq} (esperado={self.expected_seq_num}, total duplicados={self.duplicate_received})"
                )

            # Cálculo del ACK Acumulativo Contiguo
            # avanzamos ack_num hasta el último byte que tenemos de forma contigua
            # calculamos hasta dónde tenemos datos contiguos a partir de expected_seq_num
            ack_num = self.expected_seq_num
            while ack_num in self.recive_buffer:
                ack_num += self.recive_buffer[ack_num].payload_length

            # generación de Bloques SACK (RFC 2018)
            # solo los segmentos mayores a ack_num constituyen "islas" recibidas fuera de orden
            # se agrupan en intervalos continuos [start, end) para informar al emisor qué datos ya no debe reenviar
            # armamos los bloques SACK SOLO para los paquetes mayores a ack_num (huecos reales)
            secuencias_guardadas = sorted(
                s for s in self.recive_buffer.keys() if s >= ack_num
            )
            sack_blocks = []

            if secuencias_guardadas:
                # Empezamos el primer bloque con el primer paquete que tenemos
                start = secuencias_guardadas[0]
                end = start + self.recive_buffer[start].payload_length

                # Recorremos el resto de los paquetes para ver si están pegados (contiguos)
                for seq_guardada in secuencias_guardadas[1:]:
                    if seq_guardada == end:
                        # Si están pegados, estiramos el final del bloque
                        end += self.recive_buffer[seq_guardada].payload_length
                    else:
                        # Si hay un hueco, cerramos este bloque y lo guardamos
                        sack_blocks.append((start, end))

                        # Empezamos un bloque nuevo
                        start = seq_guardada
                        end = start + self.recive_buffer[start].payload_length

                sack_blocks.append((start, end))

            # el datagrama de confirmación transporta simultáneamente:
            # - ack_number: ACK acumulativo (próximo byte esperado)
            # - sack_blocks: Lista de tuplas [start, end) de paquetes recibidos fuera de orden
            ack_segment = Segment(
                sequence_number=self.seq_num,
                ack_number=ack_num,
                ack=True,
                sack_blocks=sack_blocks,  # Le decimos "pero ya tengo estas islas del futuro"
            )
            self.sock.send(ack_segment)
            logger.debug(f"Pidiendo {ack_num} | Islas a salvo: {sack_blocks}")
