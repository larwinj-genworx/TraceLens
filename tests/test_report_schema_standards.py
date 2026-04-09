from __future__ import annotations

import unittest

from src.schemas.issues import Issue, Severity
from src.schemas.report import (
    AnalysisReport,
    CoverageMatrix,
    CoverageMatrixRow,
    ReportSummary,
    StandardsComplianceSection,
)


class ReportSchemaStandardsTests(unittest.TestCase):
    def test_report_serializes_standards_findings_and_coverage_rows(self) -> None:
        issue = Issue(
            type="standards_violation_request_validation_pydantic_models",
            severity=Severity.HIGH,
            service="users-service",
            endpoint="POST /users",
            file="src/api/routes/users.py",
            line=42,
            description="Write endpoint is missing Pydantic request model.",
            evidence={"category": "request_validation"},
            impact="Request validation is inconsistent with the selected standard.",
            fix="Use BaseModel request schema for write endpoints.",
            confidence=0.91,
            source="standards_engine",
            provenance=["standards_engine"],
        )
        section = StandardsComplianceSection(
            category="request_validation",
            declared_style="pydantic_models",
            status="non_compliant",
            confidence=0.9,
            evidence_count=2,
            violations=1,
            compliant=1,
            findings=[issue],
            evidence_summary=[
                {
                    "status": "violation",
                    "file": "src/api/routes/users.py",
                    "line": 42,
                    "endpoint": "POST /users",
                    "service": "users-service",
                    "message": "Write endpoint is missing Pydantic request model.",
                    "confidence": 0.91,
                }
            ],
        )
        coverage = CoverageMatrix(
            total_checks=1,
            checked=1,
            unchecked=0,
            coverage_pct=100.0,
            rows=[
                CoverageMatrixRow(
                    stack="fastapi",
                    service="users-service",
                    category="request_validation",
                    endpoint="POST /users",
                    checked=True,
                    status="violation",
                    file="src/api/routes/users.py",
                    line=42,
                )
            ],
            unchecked_details=[],
        )

        report = AnalysisReport(
            summary=ReportSummary(score=90, critical=0, high=1, medium=0),
            issues=[issue],
            standards_compliance=[section],
            coverage_matrix=coverage,
        )

        payload = report.model_dump(mode="json")
        self.assertEqual(payload["standards_compliance"][0]["findings"][0]["line"], 42)
        self.assertEqual(payload["coverage_matrix"]["rows"][0]["stack"], "fastapi")


if __name__ == "__main__":
    unittest.main()

