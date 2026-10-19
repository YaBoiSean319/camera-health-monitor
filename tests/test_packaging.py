import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_docker_image_copies_every_local_app_module(self):
        tree = ast.parse((ROOT / "app.py").read_text())
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".", 1)[0])

        dockerfile = (ROOT / "Dockerfile").read_text()
        local_modules = sorted(module for module in modules if (ROOT / f"{module}.py").is_file())
        missing = [module for module in local_modules if f"COPY {module}.py ./{module}.py" not in dockerfile]
        self.assertEqual([], missing, f"Docker image is missing local app modules: {missing}")

    def test_compose_persists_state_and_bounds_runtime_resources(self):
        compose = (ROOT / "compose.yaml").read_text()
        for expected in (
            "camera-health-data:/data",
            "cpus: 2.0",
            "mem_limit: 1g",
            "pids_limit: 128",
            "read_only: true",
            "/tmp:rw,noexec,nosuid,size=64m",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, compose)


if __name__ == "__main__":
    unittest.main()
