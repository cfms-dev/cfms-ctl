from cyclopts import App

instance_app = App(
    "instance",
    help="Add, delete, set as default, or query instances to be managed via the CLI.",
)

instance_app.command(f"{__name__}.add:add", help="Add an instance to the registry.")
instance_app.command(
    f"{__name__}.remove:remove",
    synonym=["delete"],
    help="Remove an instance from the registry.",
)
instance_app.command(
    f"{__name__}.list_:list_", name="list", help="List all instances in the registry."
)
instance_app.command(
    f"{__name__}.show:show",
    help="Show the details of a specific instance in the registry.",
)
instance_app.command(
    f"{__name__}.set_default:set_default",
    name="set-default",
    help="Set a specific instance as the default instance.",
)
