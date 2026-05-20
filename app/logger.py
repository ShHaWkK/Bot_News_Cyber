"""
Initialisation du logger applicatif avec rotation et couleurs console.
"""

import logging
import logging.handlers
from pathlib import Path

import colorlog

from app import config


def setup_logger(name: str = "cyberbot") -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    logger.setLevel(level)

    #  Console colorée 
    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(
        colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            },
        )
    )

    #  Fichier avec rotation (10 Mo × 5 fichiers) 
    log_file = config.LOG_DIR / "bot.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.propagate = False
    return logger


log = setup_logger()
