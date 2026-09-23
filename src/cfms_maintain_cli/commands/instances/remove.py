from ._common import get_registry, run


def remove(name: str) -> None:
    """Remove a registered instance by name."""
    run(lambda: get_registry().remove(name))
    print(f"Removed instance {name!r}.")
