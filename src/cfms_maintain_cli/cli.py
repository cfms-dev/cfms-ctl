from cyclopts import App

from .commands.backups import backup_app
from .commands.instances import instance_app

app = App()  # Root application for the CLI
app.command(backup_app)
app.command(instance_app)
app.command(
    "cfms_maintain_cli.commands.fetch:fetch",
    help="Fetch server information and display it in a visually appealing way.",
)


if __name__ == "__main__":
    app()
