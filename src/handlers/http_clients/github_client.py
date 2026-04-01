from __future__ import annotations

import re
from urllib.parse import urlparse


class GitHubClient:
    @staticmethod
    def normalize_repo_url(url: str) -> str:
        value = url.strip()
        if value.endswith(".git"):
            return value
        if value.startswith("git@"):
            return value
        return value.rstrip("/") + ".git"

    @staticmethod
    def extract_repo_name(url: str) -> str:
        if url.startswith("git@"):
            path = url.split(":", maxsplit=1)[-1]
        else:
            path = urlparse(url).path
        name = path.strip("/").split("/")[-1]
        name = re.sub(r"\.git$", "", name)
        return re.sub(r"[^a-zA-Z0-9_-]", "-", name) or "repo"

    @staticmethod
    def is_github_url(url: str) -> bool:
        return "github.com" in url
