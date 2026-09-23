from ._support import get_registry


def set_default(name: str) -> None:
    """Use a registered instance when no name is specified."""
    get_registry().set_default(name)
    print(f"Default instance set to {name!r}.")
