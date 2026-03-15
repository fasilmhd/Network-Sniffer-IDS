import yaml
from utils.constants import AppConstants


class ConfigLoader:
    """Load application settings from YAML."""

    @staticmethod
    def load() -> dict:
        try:
            with open(AppConstants.CONFIG_FILE, "r") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}
        except Exception:
            return {}