from cyclopts import App
from rich.console import Console
from rich.traceback import install as install_rich_traceback

from .commands.backups import backup_app
from .commands.extensions import extension_app
from .commands.instances import instance_app

console = Console(stderr=True)
app = App(console=console, error_console=console)  # Root application for the CLI

# Install rich traceback handler using the error console
install_rich_traceback(console=console)

app.command(backup_app)
app.command(instance_app)
app.command(extension_app)
app.command(
    "cfms_maintain_cli.commands.fetch:fetch",
    help="Fetch server information and display it in a visually appealing way.",
)


if __name__ == "__main__":
    app()
