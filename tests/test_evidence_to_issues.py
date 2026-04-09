from __future__ import annotations

import unittest

from src.schemas.issues import Severity
from src.standards.evidence_collectors.base import CategoryEvidenceResult, Evidence
from src.standards.evidence_to_issues import convert_evidence_to_issues


class EvidenceToIssuesTests(unittest.TestCase):
    def test_converts_violation_evidence_with_file_and_line(self) -> None:
        ev_result = CategoryEvidenceResult(
            category="request_validation",
            declared_style="pydantic_models",
            overall_status="non_compliant",
        )
        ev_result.add(
            Evidence(
                category="request_validation",
                style="pydantic_models",
                status="violation",
                file="src/api/routes/users.py",
                line=42,
                endpoint="POST /users",
                service="users-service",
                message="Write endpoint is not using Pydantic model validation.",
                confidence=0.92,
            )
        )
        ev_result.compute_status()

        issues = convert_evidence_to_issues([ev_result])
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertTrue(issue.type.startswith("standards_violation_request_validation"))
        self.assertEqual(issue.severity, Severity.HIGH)
        self.assertEqual(issue.file, "src/api/routes/users.py")
        self.assertEqual(issue.line, 42)
        self.assertEqual(issue.service, "users-service")
        self.assertEqual(issue.endpoint, "POST /users")
        self.assertEqual(issue.source, "standards_engine")
        self.assertIn("standards_engine", issue.provenance)

    def test_skips_non_violation_evidence(self) -> None:
        ev_result = CategoryEvidenceResult(
            category="http_client",
            declared_style="axios",
            overall_status="compliant",
        )
        ev_result.add(
            Evidence(
                category="http_client",
                style="axios",
                status="compliant",
                file="src/features/users/api.ts",
                line=12,
                endpoint="GET /users",
                service="web-app",
                message="Axios usage found",
                confidence=0.88,
            )
        )
        ev_result.compute_status()
        issues = convert_evidence_to_issues([ev_result])
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()

