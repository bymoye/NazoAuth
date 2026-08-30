from __future__ import annotations

import pathlib
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = ROOT / "crates" / "authorization-server"
CONTRACTS = ROOT / "crates" / "persistence"
POSTGRES_LAUNCHER = ROOT / "crates" / "authorization-server-postgres"


class PersistenceBoundaryTests(unittest.TestCase):
    def test_server_production_dependencies_do_not_include_diesel(self) -> None:
        manifest = tomllib.loads((SERVER / "Cargo.toml").read_text(encoding="utf-8"))
        dependencies = manifest.get("dependencies", {})
        self.assertNotIn("diesel", dependencies)
        self.assertNotIn("diesel-async", dependencies)
        self.assertNotIn("nazo-postgres", dependencies)

    def test_postgres_launcher_is_the_only_current_adapter_composition_root(self) -> None:
        postgres = tomllib.loads(
            (POSTGRES_LAUNCHER / "Cargo.toml").read_text(encoding="utf-8")
        )
        postgres_dependencies = postgres.get("dependencies", {})
        self.assertIn("nazo-postgres", postgres_dependencies)
        self.assertEqual(postgres["bin"][0]["name"], "nazoauth")

        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))[
            "workspace"
        ]
        self.assertEqual(
            set(workspace["default-members"]),
            {
                "crates/authorization-server",
                "crates/authorization-server-postgres",
            },
        )

    def test_dependency_graph_gate_is_run_by_ci(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "code-quality.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("python scripts/check_persistence_dependency_graph.py", workflow)

    def test_server_production_source_does_not_own_database_transactions(self) -> None:
        forbidden = (
            "diesel::",
            "diesel_async",
            "AsyncPgConnection",
            "DbConnection",
            "_on_connection(",
        )
        violations: list[str] = []
        for path in sorted((SERVER / "src").rglob("*.rs")):
            source = path.read_text(encoding="utf-8")
            for marker in forbidden:
                if marker in source:
                    violations.append(f"{path.relative_to(ROOT)}: {marker}")
        self.assertEqual(violations, [])

    def test_persistence_contracts_do_not_depend_on_an_adapter(self) -> None:
        manifest = tomllib.loads((CONTRACTS / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertNotIn("nazo-postgres", manifest.get("dependencies", {}))
        forbidden = ("diesel", "postgres", "sql_query", "AsyncPgConnection")
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((CONTRACTS / "src").rglob("*.rs"))
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
