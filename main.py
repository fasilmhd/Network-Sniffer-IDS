#!/usr/bin/env python3
"""
Entry point for the Network Security Toolkit.
Initializes logging, loads config, applies theme, and launches GUI.
"""

import os
import sys
import asyncio
import logging

from PySide6.QtGui import QIcon, QColor
from PySide6.QtWidgets import QApplication

from utils.logging import setup_logger
from utils.constants import AppConstants
from utils.config_loader import ConfigLoader
from gui.windows.MainWindow import MainWindow

from utils.animations import AnimationUtils as Animations


def load_theme(app: QApplication, theme_path: str) -> None:
    """Load and apply QSS theme."""

    logger = logging.getLogger("main")

    if not os.path.isfile(theme_path):
        logger.warning("Theme file not found: %s", theme_path)
        return

    if not os.access(theme_path, os.R_OK):
        logger.warning("Cannot read theme file: %s", theme_path)
        return

    with open(theme_path, "r", encoding="utf-8") as f:
        data = f.read()

    if not data.strip():
        logger.warning("Theme file empty")
        return

    preview = "\n".join(data.splitlines()[:10])
    logger.info("Loading theme preview:\n%s", preview)

    app.setStyleSheet(data)
    logger.info("Theme applied")


def main() -> None:

    # Windows asyncio compatibility (important for pyshark)
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # Logging
    setup_logger(AppConstants.LOG_FILE)
    logger = logging.getLogger("main")
    logger.info("Starting Network Security Toolkit")

    # Load config
    config = ConfigLoader.load()

    # Enable HiDPI
    os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
    os.environ["QT_ENABLE_HIGHDPI_PIXMAPS"] = "1"

    # Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName(AppConstants.APP_NAME)
    app.setApplicationVersion(AppConstants.VERSION)
    app.setOrganizationName(AppConstants.ORGANIZATION_NAME)
    app.setOrganizationDomain(AppConstants.ORGANIZATION_DOMAIN)

    if os.path.exists(AppConstants.APP_ICON):
        app.setWindowIcon(QIcon(AppConstants.APP_ICON))

    # Apply theme
    load_theme(app, AppConstants.THEME_FILE)

    # Create main window
    window = MainWindow(config)

    # Initial background
    window.setStyleSheet("background-color: #000000;")

    # Show window
    window.show()

    # Startup animations
    Animations.fade_window(window, duration=800)

    Animations.animate_bg_color(
        window,
        start=QColor("#000000"),
        end=QColor("#1E1E1E"),
        duration=600
    )

    # Start application
    sys.exit(app.exec())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Fatal startup error: %s", e)