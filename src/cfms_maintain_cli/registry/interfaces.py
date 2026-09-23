"""Storage boundary used by instance business operations."""

from typing import Protocol

from .models import RegistryData


class RegistryStore(Protocol):
    def load(self) -> RegistryData: ...

    def save(self, data: RegistryData) -> None: ...
