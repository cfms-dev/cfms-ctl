from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Instance", "RegistryData"]


@dataclass(frozen=True, slots=True)
class Instance:
    # Name is decided by the table name in the registry.
    name: str

    # Location is the path to the instance's root directory,
    # which contains the config.toml file.
    location: Path


@dataclass(slots=True)
class RegistryData:
    schema_version: int = 1
    default_instance: str | None = None
    instances: dict[str, Instance] = field(default_factory=dict)
