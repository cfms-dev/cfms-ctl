"""TOML document I/O without knowledge of any business schema."""

import os
import tempfile
from pathlib import Path
from typing import Protocol

import tomlkit
from tomlkit.toml_document import TOMLDocument


class TOMLStore(Protocol):
    def read(self) -> TOMLDocument: ...

    def write(self, document: TOMLDocument) -> None: ...


class FileTOMLStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> TOMLDocument:
        # A single open handle yields a complete old or new snapshot when writers
        # replace the file atomically.
        with self.path.open("r", encoding="utf-8") as file:
            return tomlkit.parse(file.read())

    def write(self, document: TOMLDocument) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=self.path.parent,
                delete=False,
            ) as file:
                temporary_path = Path(file.name)
                tomlkit.dump(document, file)
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self.path)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
