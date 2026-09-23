from platformdirs import user_config_path

__all__ = ["USER_CONFIG_PATH"]

USER_CONFIG_PATH = user_config_path("cfms-maintain-cli", appauthor=False)
