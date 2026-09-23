from ._support import get_registry


def show(name: str) -> None:
    """Show one registered instance by name."""
    registry = get_registry()
    instance = registry.get(name)
    default_name = registry.default_name()
    marker = " [default]" if name == default_name else ""
    print(f"{instance.name}{marker}\t{instance.location}")
