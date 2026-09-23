"""CLI composition and expected error reporting for instance commands."""

import sys
from collections.abc import Callable

from platformdirs import user_config_path

from cfms_maintain_cli.registry.registry import InstanceRegistry, InstanceRegistryError
from cfms_maintain_cli.registry.store import InstanceRegistryStore, RegistryFormatError
from cfms_maintain_cli.storage import FileTOMLStore


def get_registry() -> InstanceRegistry:
    path = user_config_path("cfms-maintain-cli", appauthor=False) / "instances.toml"
    return InstanceRegistry(InstanceRegistryStore(FileTOMLStore(path)))


def run[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (InstanceRegistryError, RegistryFormatError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1) from None
