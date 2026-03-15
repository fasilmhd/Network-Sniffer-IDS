import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logger(
    log_file: str = "logs/app.log",
    level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3
) -> logging.Logger:
    """
    Configure the root logger with console and rotating file handlers.
    Args:
      log_file: path to log file
      level: logging level
      max_bytes: max file size before rotation
      backup_count: number of rotated files to keep
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    root = logging.getLogger()
    root.setLevel(level)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file handler
    fh = RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    fh.setLevel(level)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    root.debug("Logger initialized (level=%s, file=%s)", level, log_file)
    return root