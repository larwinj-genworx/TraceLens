"""Tests for evidence trace file emission."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.graph import _write_trace, _TRACE_NODE_FILES


class TestWriteTrace:
    def setup_method(self):
        self.trace_dir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.trace_dir, ignore_errors=True)

    def test_writes_json_file_when_enabled(self):
        with patch("src.agents.graph.settings") as mock_settings:
            mock_settings.evidence_trace_enabled = True
            mock_settings.evidence_trace_dir = self.trace_dir

            data = {"endpoints": [{"path": "/test", "method": "GET"}]}
            _write_trace("job123", "prepare_evidence", data)

            filepath = self.trace_dir / "job123" / "01_evidence_package.json"
            assert filepath.exists()

            content = json.loads(filepath.read_text())
            assert content["_meta"]["job_id"] == "job123"
            assert content["_meta"]["node"] == "prepare_evidence"
            assert content["data"] == data

    def test_no_file_when_disabled(self):
        with patch("src.agents.graph.settings") as mock_settings:
            mock_settings.evidence_trace_enabled = False

            _write_trace("job123", "prepare_evidence", {"test": True})

            job_dir = self.trace_dir / "job123"
            assert not job_dir.exists()

    def test_writes_all_node_types(self):
        with patch("src.agents.graph.settings") as mock_settings:
            mock_settings.evidence_trace_enabled = True
            mock_settings.evidence_trace_dir = self.trace_dir

            for node_name, (filename, _) in _TRACE_NODE_FILES.items():
                _write_trace("job456", node_name, {"node": node_name})

                filepath = self.trace_dir / "job456" / filename
                assert filepath.exists(), f"Missing trace for {node_name}"
                content = json.loads(filepath.read_text())
                assert content["_meta"]["node"] == node_name

    def test_skips_unknown_nodes(self):
        with patch("src.agents.graph.settings") as mock_settings:
            mock_settings.evidence_trace_enabled = True
            mock_settings.evidence_trace_dir = self.trace_dir

            _write_trace("job789", "unknown_node", {"test": True})

            job_dir = self.trace_dir / "job789"
            assert not job_dir.exists() or len(list(job_dir.iterdir())) == 0

    def test_handles_pydantic_models(self):
        from src.schemas.issues import Issue, Severity

        with patch("src.agents.graph.settings") as mock_settings:
            mock_settings.evidence_trace_enabled = True
            mock_settings.evidence_trace_dir = self.trace_dir

            issue = Issue(
                type="missing_auth",
                severity=Severity.CRITICAL,
                service="backend",
                description="No auth",
                impact="Bad",
                fix="Add auth",
                confidence=0.9,
                source="test",
            )
            _write_trace("job_pydantic", "cross_review", [issue])

            filepath = self.trace_dir / "job_pydantic" / "06_reviewed_issues.json"
            assert filepath.exists()
            content = json.loads(filepath.read_text())
            assert isinstance(content["data"], list)

    def test_trace_file_count(self):
        assert len(_TRACE_NODE_FILES) == 8
        expected_files = {
            "01_evidence_package.json",
            "02_security_issues.json",
            "03_integration_issues.json",
            "04_quality_issues.json",
            "05_consolidated_issues.json",
            "05b_filtered_issues.json",
            "06_reviewed_issues.json",
            "07_final_report.json",
        }
        actual_files = {filename for filename, _ in _TRACE_NODE_FILES.values()}
        assert actual_files == expected_files
