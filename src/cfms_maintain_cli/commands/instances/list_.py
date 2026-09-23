from ._common import get_registry


def list_() -> None:
    """List registered instances and mark the default."""
    registry = get_registry()
    instances = registry.list()
    default_name = registry.default_name()
    if not instances:
        print("No instances registered.")
        return

    for instance in instances:
        marker = " [default]" if instance.name == default_name else ""
        print(f"{instance.name}{marker}\t{instance.location}")
