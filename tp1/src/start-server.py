import argparse
import os
from lib.common.logger import configure_logger
from lib.server.server import Server, DEFAULT_HOST, DEFAULT_PORT


def main():
    parser = argparse.ArgumentParser(
        prog="start-server",
        description="El servidor provee el servicio de almacenamiento y descarga de archivos.",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-v", "--verbose", action="store_true", help="increase output verbosity"
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", help="decrease output verbosity"
    )
    parser.add_argument("-H", "--host", type=str, help="service IP address")
    parser.add_argument("-p", "--port", type=int, help="service port")
    parser.add_argument(
        "-s", "--storage", type=str, required=True, help="storage dir path"
    )

    args = parser.parse_args()
    logger = configure_logger("server", verbose=args.verbose, quiet=args.quiet)

    # Crea la carpeta de almacenamiento si no existe.
    os.makedirs(args.storage, exist_ok=True)

    # Si no pasaron -H o -p, se usan los valores por defecto del servidor.
    server = Server(args.host or DEFAULT_HOST, args.port or DEFAULT_PORT, args.storage)

    try:
        server.run()  # queda escuchando hasta Ctrl+C
    except KeyboardInterrupt:
        logger.info("Servidor detenido")


if __name__ == "__main__":
    main()
