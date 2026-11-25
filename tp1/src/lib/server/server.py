import os
import threading

from ..common.logger import logger
from ..common.segment import Segment
from ..common.socket_udp import SocketUDP
from ..common.stop_and_wait import StopAndWait
from ..common.sack import SACK

DEFAULT_HOST = "0.0.0.0"  # escucha en todas las interfaces del host
DEFAULT_PORT = 12000


class Server:

    # Aca se liga el valor del puerto al socket UDP de recepcion.
    def __init__(self, host, port, storage):
        self.host = host
        self.storage = storage

        # La "recepcion": socket UDP en el puerto conocido. Solo recibe SYNs.
        self.listener = SocketUDP()
        self.listener.bind(host, port)

        self.clients = {}  # Clientes que ya tienen un thread.
        self.lock = (
            threading.Lock()
        )  # Para que el diccionario lo toque un thread a la vez.

    # Aca empieza a trabajar el servidor, el socket de recepcion espera a que llegue algun SYN.
    def run(self):
        logger.info(
            "Servidor escuchando en %s:%s",
            self.host,
            self.listener.sock.getsockname()[1],
        )  # De aca sacamos el puerto del socket.
        try:
            while True:
                try:
                    segment, addr = self.listener.recv_from()
                except ValueError:  # from_bytes no pudo parsear el datagrama
                    logger.debug("Segmento mal formado, descartado")
                    continue

                if (
                    segment.is_syn()
                ):  # Si es un syn, lo llevamos a verificar si se trata de un pedido válido.
                    self.process_syn(segment, addr)
        finally:
            self.listener.close()

    # En process_syn verificamos los caminos que puede tomar el recibir ese SYN.
    def process_syn(self, syn: Segment, addr):

        # Ya tiene un socket asignado -> SYN retransmitido porque se perdio un ACK.
        # Lo reenviamos.

        with self.lock:
            conn = self.clients.get(
                addr
            )  # Busca si la direccion ya tiene un socket asignado.
        if conn is not None:
            logger.debug("SYN duplicado de %s, reenvio ACK", addr)
            conn._send_ack(syn.sequence_number)  # Si la encuentra, reenvia el ACK.
            return

        # Si se trata de un error se prende el Flag de error y se manda el error en el payload.
        error = self.validate(syn)
        if error:
            logger.info("Pedido de %s rechazado: %s", addr, error)
            self._send_error_to(
                self.listener,
                error,
                addr,
                sequence_number=0,
                ack_number=syn.sequence_number,
            )
            return

        # Pedido valido: Se abre un socket nuevo en un puerto nuevo,
        # manda al ack desde ahi y le asigna un thread.
        sock = SocketUDP()
        sock.bind(self.host, 0)
        # instanciamos según el protocolo elegido:
        if syn.pro_flag:
            # Cambiar cuanto ponemos de window_size, por ahora puse un valor por defecto
            conn = SACK(sock, window_size=10)
            logger.info(f"Conexión aceptada desde {addr}, utilizando SACK")
        else:
            conn = StopAndWait(sock)
            logger.info(f"Conexión aceptada desde {addr}, utilizando Stop & Wait")

        conn.accept(syn, addr)

        with self.lock:
            self.clients[addr] = conn

        threading.Thread(
            target=self.serve_client, args=(conn, syn, addr), daemon=True
        ).start()

    def _send_error_to(self, sock, message, addr=None, sequence_number=0, ack_number=0):
        error = Segment(
            sequence_number,
            ack_number,
            err=True,
            payload=message.encode(),
        )
        if addr is None:
            sock.send(error)
        else:
            sock.send_to(error, addr)

    # Valida si el pedido es valido, sino devuelve mensaje de error.
    def validate(self, syn: Segment):
        """Devuelve el mensaje de error, o None si el pedido es valido."""
        try:
            name = os.path.basename(syn.payload.decode())
        except UnicodeDecodeError:
            return "Nombre de archivo invalido"
        if name in ("", ".", ".."):
            return "Nombre de archivo invalido"
        # Verifica si no es una descarga y si no existe.
        if not syn.ope_flag and not os.path.isfile(os.path.join(self.storage, name)):
            return f"El archivo '{name}' no existe en el servidor"
        return None

    # Maneja las dos operaciones, upload y download.
    def serve_client(self, conn, syn: Segment, addr):
        name = os.path.basename(syn.payload.decode())
        path = os.path.join(self.storage, name)

        try:
            if syn.ope_flag:
                self.receive_upload(conn, path, addr)
            else:
                self.serve_download(conn, path, addr)

        # Si algun error ocurre en un socket, se cierra y el thread termina.
        except ConnectionError:
            logger.info("El cliente %s cancelo la transferencia", addr)
            conn.sock.close()
        except (OSError, ValueError) as e:
            logger.error("Fallo la transferencia con %s: %s", addr, e)
            try:
                conn.send_error(str(e))
            except OSError:
                pass
            conn.sock.close()
        finally:
            with self.lock:
                self.clients.pop(addr, None)

    def receive_upload(self, conn, path, addr):

        logger.info("UPLOAD de %s -> %s", addr, path)
        # Archivo temporal por si 2 clientes suben un archivo con el mismo nombre al mismo tiempo.
        temporary_file = f"{path}.part-{threading.get_ident()}"

        try:
            with open(temporary_file, "wb") as file:
                while True:
                    chunk = conn.recv()
                    if chunk == b"":  # llego el FIN (recv ya lo ACKeo)
                        break
                    file.write(chunk)
            os.replace(
                temporary_file, path
            )  # Renombra el archivo temporal con el nombre original.

        # Si pasa algo en el medio se borra el temporal.
        except BaseException:
            if os.path.exists(temporary_file):
                os.remove(temporary_file)
            raise

        # Se cierra el socket luego de finalizar el Upload.
        stats = conn.get_stats()
        conn.sock.close()
        logger.info(
            "UPLOAD de %s completo | Recibidos: %s | Duplicados: %s | Total: %s",
            addr,
            stats["received_segments"],
            stats["duplicate_received"],
            stats["total_received"],
        )

    def serve_download(self, conn, path, addr):

        logger.info("DOWNLOAD de %s -> %s", path, addr)
        with open(path, "rb") as file:
            data = file.read()
        conn.send(data)
        stats = conn.get_stats()
        conn.close()  # el que manda los datos inicia el cierre (FIN)
        logger.info(
            "DOWNLOAD a %s completo (%s bytes) | Originales: %s | Retransmisiones: %s | Total enviados: %s (%.1f%%)",
            addr,
            len(data),
            stats["original_segments"],
            stats["retransmissions"],
            stats["total_sent"],
            stats["retransmission_pct"],
        )
