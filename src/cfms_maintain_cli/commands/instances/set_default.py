from ._common import get_registry, run


def set_default(name: str) -> None:
    """Use a registered instance when no name is specified."""
    run(lambda: get_registry().set_default(name))
    print(f"Default instance set to {name!r}.")
