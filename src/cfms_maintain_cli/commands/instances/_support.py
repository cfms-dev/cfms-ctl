"""CLI composition and expected error reporting for instance commands."""

from cfms_maintain_cli.paths import USER_CONFIG_PATH
from cfms_maintain_cli.registry.registry import InstanceRegistry
from cfms_maintain_cli.registry.store import InstanceRegistryStore
from cfms_maintain_cli.storage import FileTOMLStore


def get_registry() -> InstanceRegistry:
    path = USER_CONFIG_PATH / "instances.toml"
    return InstanceRegistry(InstanceRegistryStore(FileTOMLStore(path)))
