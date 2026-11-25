import os
from ..common.logger import logger
from ..common.socket_udp import SocketUDP
from ..common.stop_and_wait import StopAndWait
from ..common.sack import SACK

DEFAULT_PORT = 12000
DEFAULT_HOST = "127.0.0.1"


def upload_file(
    host: str, port: int, src: str, name: str, protocol: str, verbose=False, quiet=False
):
    # Valores por defecto en caso de que no se hayan pasado en CLI
    host = host or DEFAULT_HOST
    port = port or DEFAULT_PORT

    if not quiet:
        print(
            f"Iniciando subida de {name} hacia {host}:{port} usando protocolo {protocol}"
        )

    # Verificamos y leemos el archivo local en binario
    # No lanzamos error asi cubrimos una de las condiciones de error que exige el informe
    if not os.path.exists(src):
        print(f"Error: El archivo de origen '{src}' no existe.")
        return

    with open(src, "rb") as f:
        file_data = f.read()

    # Inicializamos el socket y la capa de transporte según el protocolo
    client_socket = SocketUDP()

    if protocol == "sw":
        connection = StopAndWait(client_socket)
        if not quiet:
            print("Enviando mediante S&W")

    elif protocol == "sack":
        connection = SACK(client_socket, 16)
        if not quiet:
            print("Enviando mediante SACK")

    else:
        raise ValueError(f"Protocolo desconocido: {protocol}")

    try:
        # Establecemos Handshake con el servidor
        # Se enviará el SYN al server
        connection.connect(
            host, port, ope=True, payload=name.encode(), pro=(protocol == "sack")
        )

        # Enviamos el contenido del archivo fragmentado
        if not quiet:
            print("Enviando Contenido del archivo...")
        connection.send(file_data)

        # Cerramos la conexión
        stats = connection.get_stats()
        if not quiet:
            print("Cerrando conexión")
        connection.close()

        # Mensaje final
        if not quiet:
            print("Archivo subido con éxito.")
            print(f"- Segmentos originales: {stats['original_segments']}")
            print(f"- Retransmisiones: {stats['retransmissions']}")
            print(
                f"- Total paquetes enviados: {stats['total_sent']} "
                f"({stats['retransmission_pct']:.1f}% retransmitidos)"
            )
        logger.info(
            "Subida completa de %s | Originales: %s | Retransmisiones: %s | Total: %s",
            name,
            stats["original_segments"],
            stats["retransmissions"],
            stats["total_sent"],
        )

    except ConnectionError as e:
        print(f"Error de conexión: {e}")
        client_socket.close()
        return


def download_file(
    host: str, port: int, dst: str, name: str, protocol: str, verbose=False, quiet=False
):
    host = host or DEFAULT_HOST
    port = port or DEFAULT_PORT

    if not quiet:
        print(
            f"Iniciando descarga de '{name}' desde {host}:{port} usando protocolo {protocol}"
        )

    client_socket = SocketUDP()

    if protocol == "sw":
        connection = StopAndWait(client_socket)
        if not quiet:
            print("Recibiendo mediante S&W")
    elif protocol == "sack":
        connection = SACK(client_socket, 16)
        if not quiet:
            print("Recibiendo mediante SACK")
    else:
        raise ValueError(f"Protocolo desconocido: {protocol}")

    try:
        # ope=False le avisa al servidor en el SYN que es un DOWNLOAD
        connection.connect(
            host, port, ope=False, payload=name.encode(), pro=(protocol == "sack")
        )

        if not quiet:
            print("Conexión establecida. Recibiendo datos...")

        with open(dst, "wb") as f:
            while True:
                chunk = (
                    connection.recv()
                )  # Stop & Wait se encarga de la recepción confiable[cite: 8]
                if chunk == b"":
                    if not quiet:
                        print("El servidor finalizó la transmisión.")
                    break

                f.write(chunk)

        stats = connection.get_stats()
        if not quiet:
            print(f"Archivo guardado exitosamente en '{dst}'.")
            print(f"- Segmentos recibidos: {stats['received_segments']}")
            print(f"- Duplicados recibidos: {stats['duplicate_received']}")
            print(
                f"- Total paquetes recibidos: {stats['total_received']} "
                f"({stats['duplicate_pct']:.1f}% duplicados)"
            )
        logger.info(
            "Descarga completa de %s | Recibidos: %s | Duplicados: %s | Total: %s",
            name,
            stats["received_segments"],
            stats["duplicate_received"],
            stats["total_received"],
        )

    except ConnectionError as e:
        print(f"Error de red: {e}")
    except OSError as e:
        if connection.is_connected:
            try:
                connection.send_error(str(e))
            except OSError:
                pass
        print(f"Error al guardar el archivo local: {e}")
    finally:
        client_socket.close()
        if not quiet:
            print("Conexión cerrada.")
