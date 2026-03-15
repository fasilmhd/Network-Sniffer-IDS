import os
import yaml
from utils.constants import AppConstants


class ConfigService:
    """
    Load and save application settings from/to a YAML file.
    """

    def __init__(self):
        # Ensure config directory exists
        cfg_path = AppConstants.CONFIG_FILE
        os.makedirs(os.path.dirname(cfg_path), exist_ok=True)

    def load(self) -> dict:
        """
        Read and return the settings as a dict.
        If the file does not exist or is empty, returns an empty dict.
        """
        try:
            with open(AppConstants.CONFIG_FILE, "r") as f:
                data = yaml.safe_load(f) or {}
            return data
        except FileNotFoundError:
            return {}
        except Exception as e:
            # Log but do not raise to keep UI responsive
            import logging
            logging.getLogger("ConfigService").error("Failed to load config: %s", e)
            return {}

    def save(self, config: dict) -> None:
        """
        Write the provided settings dict back to the YAML file.
        """
        try:
            with open(AppConstants.CONFIG_FILE, "w") as f:
                yaml.safe_dump(config, f)
        except Exception as e:
            import logging
            logging.getLogger("ConfigService").error("Failed to save config: %s", e)