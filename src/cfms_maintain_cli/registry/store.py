"""Map instance registry data to a reusable TOML document store."""

from pathlib import Path

import tomlkit
from tomlkit.exceptions import ParseError
from tomlkit.toml_document import TOMLDocument

from cfms_maintain_cli.storage import TOMLStore

from .models import Instance, RegistryData


class RegistryFormatError(ValueError):
    pass


class InstanceRegistryStore:
    def __init__(self, toml_store: TOMLStore) -> None:
        self._toml_store = toml_store

    def load(self) -> RegistryData:
        return self._decode(self._read_document())

    def save(self, data: RegistryData) -> None:
        document = self._read_document()
        self._decode(document)  # Never overwrite a malformed or newer registry.

        if data.schema_version != 1:
            raise RegistryFormatError(
                f"Unsupported registry schema version: {data.schema_version!r}"
            )
        if (
            data.default_instance is not None
            and data.default_instance not in data.instances
        ):
            raise RegistryFormatError("Default instance is not registered.")

        document["schema_version"] = 1
        if data.default_instance is None:
            if "default_instance" in document:
                del document["default_instance"]
        else:
            document["default_instance"] = data.default_instance

        if "instances" not in document:
            document["instances"] = tomlkit.table()
        instances = document["instances"]

        for name in list(instances):
            if name not in data.instances:
                del instances[name]
        for name, instance in data.instances.items():
            if name not in instances:
                instances[name] = tomlkit.table()
            instances[name]["location"] = str(instance.location)

        self._toml_store.write(document)

    def _read_document(self) -> TOMLDocument:
        try:
            return self._toml_store.read()
        except FileNotFoundError:
            return tomlkit.document()
        except ParseError as error:
            raise RegistryFormatError(f"Invalid registry TOML: {error}") from error

    @staticmethod
    def _decode(document: TOMLDocument) -> RegistryData:
        raw = document.unwrap()
        version = raw.get("schema_version", 1)
        if type(version) is not int or version != 1:
            raise RegistryFormatError(
                f"Unsupported registry schema version: {version!r}"
            )

        raw_instances = raw.get("instances", {})
        if not isinstance(raw_instances, dict):
            raise RegistryFormatError("Registry 'instances' must be a table.")

        instances: dict[str, Instance] = {}
        for name, value in raw_instances.items():
            if not isinstance(value, dict) or not isinstance(
                value.get("location"), str
            ):
                raise RegistryFormatError(f"Instance {name!r} needs a string location.")
            if not value["location"]:
                raise RegistryFormatError(f"Instance {name!r} has an empty location.")
            instances[name] = Instance(name=name, location=Path(value["location"]))

        default = raw.get("default_instance")
        if default is not None and (
            not isinstance(default, str) or default not in instances
        ):
            raise RegistryFormatError("Default instance is not registered.")

        return RegistryData(
            schema_version=version,
            default_instance=default,
            instances=instances,
        )
