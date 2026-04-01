from __future__ import annotations


class TraceLensError(Exception):
    """Base application exception."""


class AnalysisFailedError(TraceLensError):
    """Raised when a non-recoverable analysis failure occurs."""


class RepositoryLoadError(TraceLensError):
    """Raised when repository cloning/loading fails."""
