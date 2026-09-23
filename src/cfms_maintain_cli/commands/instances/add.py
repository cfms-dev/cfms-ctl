from pathlib import Path

from ._common import get_registry


def add(name: str, location: Path, *, set_default: bool = False) -> None:
    """Register a server directory containing config.toml."""
    registry = get_registry()
    instance = registry.add(name, location, set_default=set_default)
    print(f"Added instance {instance.name!r}: {instance.location}")
