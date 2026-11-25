import argparse
from lib.client.client import download_file
from lib.common.logger import configure_logger

from lib.common.logger import configure_logger


def main():
    parser = argparse.ArgumentParser(
        prog="download",
        description="El comando download descarga un archivo especificado desde el servidor",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-v", "--verbose", action="store_true", help="increase output verbosity"
    )
    group.add_argument(
        "-q", "--quiet", action="store_true", help="decrease output verbosity"
    )
    parser.add_argument("-H", "--host", type=str, help="server IP address")
    parser.add_argument("-p", "--port", type=int, help="server port")
    parser.add_argument(
        "-d", "--dst", type=str, required=True, help="destination file path"
    )
    parser.add_argument("-n", "--name", type=str, required=True, help="file name")
    parser.add_argument(
        "-r",
        "--protocol",
        type=str,
        choices=["sw", "sack"],
        default="sw",
        help="error recovery protocol",
    )

    args = parser.parse_args()
    configure_logger("download", verbose=args.verbose, quiet=args.quiet)

    configure_logger("download", verbose=args.verbose, quiet=args.quiet)

    download_file(
        host=args.host,
        port=args.port,
        dst=args.dst,
        name=args.name,
        protocol=args.protocol,
        verbose=args.verbose,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    main()
