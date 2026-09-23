from ._common import get_registry, run


def show(name: str) -> None:
    """Show one registered instance by name."""
    registry = get_registry()
    instance = run(lambda: registry.get(name))
    default_name = run(registry.default_name)
    marker = " [default]" if name == default_name else ""
    print(f"{instance.name}{marker}\t{instance.location}")
