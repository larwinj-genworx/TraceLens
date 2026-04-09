from __future__ import annotations

import unittest

from src.api.rest.routes.analysis import _build_upload_request
from src.schemas.input import RepoInput


class UploadRequestBuilderTests(unittest.TestCase):
    def test_build_upload_request_keeps_standard_id(self) -> None:
        repo_inputs = [
            RepoInput(
                url="",
                source_type="zip",
                local_path="/tmp/example-repo",
            )
        ]
        cfg = {
            "enable_runtime": True,
            "enable_llm_enhancement": False,
            "runtime_timeout_seconds": 120,
            "standard_id": "strict_backend_standard",
        }
        request = _build_upload_request(repo_inputs, cfg)
        self.assertEqual(request.standard_id, "strict_backend_standard")
        self.assertEqual(request.runtime_timeout_seconds, 120)
        self.assertEqual(len(request.repos), 1)

    def test_build_upload_request_defaults_when_missing(self) -> None:
        repo_inputs = [
            RepoInput(
                url="",
                source_type="zip",
                local_path="/tmp/example-repo",
            )
        ]
        request = _build_upload_request(repo_inputs, {})
        self.assertIsNone(request.standard_id)
        self.assertTrue(request.enable_runtime)
        self.assertTrue(request.enable_llm_enhancement)
        self.assertEqual(request.runtime_timeout_seconds, 240)


if __name__ == "__main__":
    unittest.main()

