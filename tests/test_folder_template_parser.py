from __future__ import annotations

import unittest

from src.standards.folder_template_parser import parse_folder_structure_template


class FolderTemplateParserTests(unittest.TestCase):
    def test_parses_kv_template_and_required_roles(self) -> None:
        template = "\n".join(
            [
                "routes: src/api/routes",
                "services: src/core/services",
                "repositories: src/data/repositories",
            ]
        )
        parsed = parse_folder_structure_template(
            template,
            required_roles=["routes", "services", "repositories"],
            known_roles=["routes", "services", "repositories"],
        )
        self.assertTrue(parsed.is_valid)
        self.assertEqual(parsed.folder_structure["routes"], "src/api/routes")
        self.assertEqual(parsed.folder_structure["services"], "src/core/services")
        self.assertEqual(parsed.folder_structure["repositories"], "src/data/repositories")

    def test_reports_invalid_line_and_missing_required_role(self) -> None:
        template = "\n".join(
            [
                "routes -> src/api/routes",
                "this line is invalid",
            ]
        )
        parsed = parse_folder_structure_template(
            template,
            required_roles=["routes", "services"],
            known_roles=["routes", "services"],
        )
        self.assertFalse(parsed.is_valid)
        messages = [err.message for err in parsed.errors]
        self.assertTrue(
            any("Invalid folder mapping line" in msg for msg in messages),
            f"Expected invalid-line error, got: {messages}",
        )
        self.assertTrue(
            any("Missing required roles" in msg for msg in messages),
            f"Expected missing-role error, got: {messages}",
        )


if __name__ == "__main__":
    unittest.main()

