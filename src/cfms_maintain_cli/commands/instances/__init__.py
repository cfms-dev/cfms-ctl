from cyclopts import App

instance_app = App(
    "instance",
    help="Add, delete, set as default, or query instances to be managed via the CLI.",
)

instance_app.command(f"{__name__}.add:add")
instance_app.command(f"{__name__}.remove:remove", synonym=["delete"])
instance_app.command(f"{__name__}.list_:list_", name="list")
instance_app.command(f"{__name__}.show:show")
instance_app.command(f"{__name__}.set_default:set_default", name="set-default")
