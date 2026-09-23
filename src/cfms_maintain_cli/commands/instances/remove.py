from ._common import get_registry


def remove(name: str) -> None:
    """Remove a registered instance by name."""
    get_registry().remove(name)
    print(f"Removed instance {name!r}.")
