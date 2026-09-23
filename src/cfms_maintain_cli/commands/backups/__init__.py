from cyclopts import App

backup_app = App("backup", help="Commands related to backup operations.")

backup_app.command(f"{__name__}.info:info")
backup_app.command(f"{__name__}.export:export")
backup_app.command(f"{__name__}.import_:import_", name="import")
