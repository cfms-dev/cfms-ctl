import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tomlkit

from cfms_maintain_cli import app
from cfms_maintain_cli.registry.registry import (
    DefaultInstanceNotSetError,
    InstanceAlreadyExistsError,
    InstanceNotFoundError,
    InstanceRegistry,
    InvalidInstanceLocationError,
    InvalidInstanceNameError,
)
from cfms_maintain_cli.registry.store import InstanceRegistryStore, RegistryFormatError
from cfms_maintain_cli.storage import FileTOMLStore


class InstanceRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.registry_path = self.root / "instances.toml"
        self.registry = InstanceRegistry(
            InstanceRegistryStore(FileTOMLStore(self.registry_path))
        )

    def instance_directory(self, name: str) -> Path:
        directory = self.root / name
        directory.mkdir()
        (directory / "config.toml").write_text("", encoding="utf-8")
        return directory

    def test_add_list_show_and_resolve_default(self) -> None:
        beta = self.instance_directory("beta")
        alpha = self.instance_directory("alpha")

        self.registry.add("beta", beta)
        self.registry.add("alpha", alpha)

        self.assertEqual(
            [item.name for item in self.registry.list()], ["alpha", "beta"]
        )
        self.assertEqual(self.registry.get("alpha").location, alpha.resolve())
        self.assertEqual(self.registry.default_name(), "beta")
        self.assertEqual(self.registry.resolve().name, "beta")
        self.assertEqual(self.registry.resolve("alpha").name, "alpha")

        self.registry.set_default("alpha")
        self.assertEqual(self.registry.resolve().name, "alpha")

    def test_add_can_select_default_and_quote_dotted_name(self) -> None:
        first = self.instance_directory("first")
        second = self.instance_directory("second")
        self.registry.add("first", first)
        self.registry.add("team.second", second, set_default=True)

        self.assertEqual(self.registry.default_name(), "team.second")
        self.assertEqual(self.registry.resolve().name, "team.second")
        self.assertIn('[instances."team.second"]', self.registry_path.read_text())

    def test_delete_default_leaves_it_unset_even_after_another_add(self) -> None:
        for name in ("alpha", "beta", "gamma"):
            directory = self.instance_directory(name)
            if name == "gamma":
                self.registry.remove("alpha")
                with self.assertRaises(DefaultInstanceNotSetError):
                    self.registry.resolve()
            self.registry.add(name, directory)

        self.assertIsNone(self.registry.default_name())
        self.assertEqual(
            [item.name for item in self.registry.list()], ["beta", "gamma"]
        )

    def test_invalid_add_and_missing_names(self) -> None:
        directory = self.instance_directory("valid")
        self.registry.add("valid", directory)

        with self.assertRaises(InstanceAlreadyExistsError):
            self.registry.add("valid", directory)
        with self.assertRaises(InvalidInstanceNameError):
            self.registry.add("bad name", directory)
        with self.assertRaises(InvalidInstanceLocationError):
            self.registry.add("missing", self.root / "absent")

        without_config = self.root / "without-config"
        without_config.mkdir()
        with self.assertRaises(InvalidInstanceLocationError):
            self.registry.add("without-config", without_config)

        with self.assertRaises(InstanceNotFoundError):
            self.registry.get("unknown")
        with self.assertRaises(InstanceNotFoundError):
            self.registry.remove("unknown")
        with self.assertRaises(InstanceNotFoundError):
            self.registry.set_default("unknown")

    def test_registry_comments_and_unrelated_fields_survive_changes(self) -> None:
        old = self.instance_directory("old")
        self.registry_path.write_text(
            "# Keep this heading\n"
            "schema_version = 1\n"
            "extra = 'keep'\n\n"
            "[instances.old]\n"
            f"location = {tomlkit.dumps({'value': str(old)}).partition(' = ')[2].strip()}\n"
            "note = 'keep this metadata' # and this comment\n",
            encoding="utf-8",
        )
        new = self.instance_directory("new")

        self.registry.add("new", new)
        text = self.registry_path.read_text(encoding="utf-8")
        self.assertIn("# Keep this heading", text)
        self.assertIn("extra = 'keep'", text)
        self.assertIn("note = 'keep this metadata' # and this comment", text)
        self.assertEqual(self.registry.get("old").location, old)

        self.registry.remove("old")
        text = self.registry_path.read_text(encoding="utf-8")
        self.assertIn("extra = 'keep'", text)
        self.assertNotIn("[instances.old]", text)

    def test_invalid_registry_is_not_overwritten(self) -> None:
        directory = self.instance_directory("new")
        for content in (
            "not = [valid TOML",
            "schema_version = 2\n",
            "schema_version = true\n",
            "schema_version = 1\ndefault_instance = 'absent'\n",
            "schema_version = 1\n[instances.bad]\nlocation = 42\n",
        ):
            with self.subTest(content=content):
                self.registry_path.write_text(content, encoding="utf-8")
                with self.assertRaises(RegistryFormatError):
                    self.registry.add("new", directory)
                self.assertEqual(
                    self.registry_path.read_text(encoding="utf-8"), content
                )

    def test_replace_failure_preserves_original_and_cleans_temp_file(self) -> None:
        original = "# original\nschema_version = 1\n"
        self.registry_path.write_text(original, encoding="utf-8")
        directory = self.instance_directory("new")

        with (
            patch("cfms_maintain_cli.storage.toml.os.replace", side_effect=OSError),
            self.assertRaises(OSError),
        ):
            self.registry.add("new", directory)

        self.assertEqual(self.registry_path.read_text(encoding="utf-8"), original)
        self.assertEqual(set(self.root.iterdir()), {self.registry_path, directory})


class InstanceCommandTests(unittest.TestCase):
    def test_cli_success_and_error_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance_path = root / "server"
            instance_path.mkdir()
            (instance_path / "config.toml").write_text("", encoding="utf-8")
            output = io.StringIO()
            errors = io.StringIO()

            with (
                patch(
                    "cfms_maintain_cli.commands.instances._common.user_config_path",
                    return_value=root,
                ),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                app(
                    ["instance", "add", "server", str(instance_path)],
                    result_action="return_value",
                )
                app(["instance", "list"], result_action="return_value")
                app(["instance", "show", "server"], result_action="return_value")
                app(["instance", "remove", "server"], result_action="return_value")
                with self.assertRaises(SystemExit) as exit_error:
                    app(["instance", "show", "server"], result_action="return_value")

            self.assertEqual(exit_error.exception.code, 1)
            self.assertIn("server [default]", output.getvalue())
            self.assertIn("Removed instance 'server'.", output.getvalue())
            self.assertIn("is not registered", errors.getvalue())

    def test_cli_set_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / name for name in ("first", "second")]
            for path in paths:
                path.mkdir()
                (path / "config.toml").write_text("", encoding="utf-8")

            with (
                patch(
                    "cfms_maintain_cli.commands.instances._common.user_config_path",
                    return_value=root,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                app(
                    ["instance", "add", "first", str(paths[0])],
                    result_action="return_value",
                )
                app(
                    ["instance", "add", "second", str(paths[1])],
                    result_action="return_value",
                )
                app(["instance", "set-default", "second"], result_action="return_value")

            registry = InstanceRegistry(
                InstanceRegistryStore(FileTOMLStore(root / "instances.toml"))
            )
            self.assertEqual(registry.resolve().name, "second")


if __name__ == "__main__":
    unittest.main()
