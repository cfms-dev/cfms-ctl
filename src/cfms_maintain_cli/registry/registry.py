import re
from pathlib import Path

from .interfaces import RegistryStore
from .models import Instance

_INSTANCE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class InstanceRegistryError(ValueError):
    pass


class InstanceNotFoundError(InstanceRegistryError):
    pass


class InstanceAlreadyExistsError(InstanceRegistryError):
    pass


class DefaultInstanceNotSetError(InstanceRegistryError):
    pass


class InvalidInstanceNameError(InstanceRegistryError):
    pass


class InvalidInstanceLocationError(InstanceRegistryError):
    pass


class InstanceRegistry:
    def __init__(self, store: RegistryStore) -> None:
        self._store = store

    def add(
        self,
        name: str,
        instance_path: Path,
        *,
        set_default: bool = False,
    ) -> Instance:
        self._validate_name(name)

        data = self._store.load()

        if name in data.instances:
            raise InstanceAlreadyExistsError(f"Instance {name!r} already exists.")

        instance_path = instance_path.expanduser().resolve()
        if not instance_path.is_dir():
            raise InvalidInstanceLocationError(
                f"Instance directory does not exist: {instance_path}"
            )
        if not (instance_path / "config.toml").is_file():
            raise InvalidInstanceLocationError(
                f"Instance directory has no config.toml: {instance_path}"
            )

        instance = Instance(name=name, location=instance_path)

        data.instances[name] = instance

        if set_default or len(data.instances) == 1:
            data.default_instance = name

        self._store.save(data)

        return instance

    def remove(self, name: str) -> None:
        data = self._store.load()

        if name not in data.instances:
            raise InstanceNotFoundError(f"Instance {name!r} is not registered.")

        if data.default_instance == name:
            data.default_instance = None

        del data.instances[name]

        self._store.save(data)

    def get(self, name: str) -> Instance:
        data = self._store.load()

        try:
            return data.instances[name]
        except KeyError:
            raise InstanceNotFoundError(
                f"Instance {name!r} is not registered."
            ) from None

    def list(self) -> tuple[Instance, ...]:
        data = self._store.load()
        return tuple(data.instances[name] for name in sorted(data.instances))

    def default_name(self) -> str | None:
        return self._store.load().default_instance

    def set_default(self, name: str) -> None:
        data = self._store.load()

        if name not in data.instances:
            raise InstanceNotFoundError(f"Instance {name!r} is not registered.")

        data.default_instance = name
        self._store.save(data)

    def clear_default(self) -> None:
        data = self._store.load()
        data.default_instance = None
        self._store.save(data)

    def get_default(self) -> Instance:
        data = self._store.load()

        if data.default_instance is None:
            raise DefaultInstanceNotSetError("No default instance is set.")

        return data.instances[data.default_instance]

    def resolve(
        self,
        name: str | None = None,
    ) -> Instance:
        if name is not None:
            return self.get(name)

        return self.get_default()

    @staticmethod
    def _validate_name(name: str) -> None:
        if not _INSTANCE_NAME_PATTERN.fullmatch(name):
            raise InvalidInstanceNameError(
                "Instance name must be 1-64 characters: letters, digits, dot, "
                "underscore, or hyphen; it must start with a letter or digit."
            )
