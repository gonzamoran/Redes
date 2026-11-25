import logging

logger = logging.getLogger("file_transfer")  # inicia un logger comun para toda la app.


def configure_logger(app_name, verbose=False, quiet=False):
    """Configura el nivel y el nombre a mostrar en el formato."""
    if verbose and quiet:
        raise ValueError("verbose y quiet no pueden estar activos a la vez")
    if not app_name:
        raise ValueError("el nombre del logger no puede estar vacio")

    # es jerarquico Debug > Info > Warning > Error > Critical
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    if not logger.handlers:
        logger.addHandler(logging.StreamHandler())

    # ej: 2026-10-01 14:30:00,123 [INFO] server: mensaje
    formatter = logging.Formatter(
        f"%(asctime)s [%(levelname)s] {app_name}: %(message)s"
    )
    for handler in logger.handlers:
        handler.setFormatter(formatter)

    logger.setLevel(level)
    logger.propagate = False
    return logger
