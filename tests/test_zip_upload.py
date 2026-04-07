"""Tests for ZIP upload endpoint and RepoLoader.load_from_paths."""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.utils.repo_loader import RepoLoader


class TestRepoLoaderFromPaths:
    def setup_method(self):
        self.workspace = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_loads_fastapi_project(self):
        project_dir = self.workspace / "my-backend"
        project_dir.mkdir()
        (project_dir / "requirements.txt").write_text("fastapi\nuvicorn\n")
        (project_dir / "main.py").write_text(
            'from fastapi import FastAPI\napp = FastAPI()\n'
            '@app.get("/health")\ndef health(): return {"ok": True}\n'
        )

        loader = RepoLoader(workspace_root=self.workspace)
        descriptors, assumptions = loader.load_from_paths([project_dir])

        assert len(descriptors) == 1
        assert descriptors[0].repo_type.value == "backend"
        assert descriptors[0].name == "my-backend"

    def test_loads_react_project(self):
        project_dir = self.workspace / "my-frontend"
        project_dir.mkdir()
        (project_dir / "package.json").write_text(
            json.dumps({"dependencies": {"react": "^18.0.0"}})
        )

        loader = RepoLoader(workspace_root=self.workspace)
        descriptors, assumptions = loader.load_from_paths([project_dir])

        assert len(descriptors) == 1
        assert descriptors[0].repo_type.value == "frontend"

    def test_handles_missing_directory(self):
        missing_dir = self.workspace / "nonexistent"
        loader = RepoLoader(workspace_root=self.workspace)
        descriptors, assumptions = loader.load_from_paths([missing_dir])

        assert len(descriptors) == 1
        assert descriptors[0].clone_error == "directory_not_found"
        assert len(assumptions) == 1

    def test_custom_names(self):
        project_dir = self.workspace / "temp-abc123"
        project_dir.mkdir()
        (project_dir / "main.py").write_text("print('hello')")

        loader = RepoLoader(workspace_root=self.workspace)
        descriptors, _ = loader.load_from_paths([project_dir], names=["my-service"])

        assert descriptors[0].name == "my-service"


class TestZipExtraction:
    def setup_method(self):
        self.workspace = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def _create_zip(self, files: dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_extract_simple_zip(self):
        zip_bytes = self._create_zip({
            "main.py": 'from fastapi import FastAPI\napp = FastAPI()\n',
            "requirements.txt": "fastapi\n",
        })

        target = self.workspace / "test-project"
        target.mkdir()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(target)

        assert (target / "main.py").exists()
        assert (target / "requirements.txt").exists()

    def test_extract_nested_zip(self):
        zip_bytes = self._create_zip({
            "my-project/main.py": 'from fastapi import FastAPI\napp = FastAPI()\n',
            "my-project/requirements.txt": "fastapi\n",
        })

        target = self.workspace / "test-nested"
        target.mkdir()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(target)

        top_entries = list(target.iterdir())
        assert len(top_entries) == 1
        assert top_entries[0].name == "my-project"
        assert (top_entries[0] / "main.py").exists()

    def test_invalid_zip_rejected(self):
        with pytest.raises(zipfile.BadZipFile):
            with zipfile.ZipFile(io.BytesIO(b"not a zip file")) as _:
                pass


class TestUploadEndpoint:
    def _create_zip(self, files: dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_upload_route_exists(self):
        """Verify the upload endpoint is registered."""
        from src.api.rest.app import create_app
        app = create_app()
        routes = [r.path for r in app.routes if hasattr(r, "path")]
        upload_paths = [r for r in routes if "upload" in r]
        assert len(upload_paths) > 0, f"No upload route found in: {routes}"

    def test_upload_rejects_non_zip(self):
        from src.api.rest.app import create_app
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/analysis/upload",
            files=[("repos", ("test.txt", b"not a zip", "text/plain"))],
            data={"config": "{}"},
        )
        assert response.status_code == 400
        assert "zip" in response.json()["detail"].lower()

    def test_upload_rejects_bad_zip(self):
        from src.api.rest.app import create_app
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/analysis/upload",
            files=[("repos", ("test.zip", b"not a real zip", "application/zip"))],
            data={"config": "{}"},
        )
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()

    def test_upload_accepts_valid_zip(self):
        from src.api.rest.app import create_app
        app = create_app()
        client = TestClient(app)

        zip_bytes = self._create_zip({
            "main.py": 'from fastapi import FastAPI\napp = FastAPI()\n',
            "requirements.txt": "fastapi\n",
        })

        response = client.post(
            "/analysis/upload",
            files=[("repos", ("backend.zip", zip_bytes, "application/zip"))],
            data={"config": json.dumps({"enable_runtime": False, "enable_llm_enhancement": False})},
        )
        assert response.status_code == 200
        body = response.json()
        assert "job_id" in body
        assert body["status"] == "running"
