from cyclopts import App

extension_app = App(
    "extension",
    help="Install, uninstall, and manage extensions on the instance.",
)

extension_app.command(f"{__name__}.install:install")
extension_app.command(f"{__name__}.uninstall:uninstall", synonym=["remove"])
