"""TraceLens standards API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Response, status

from src.core.services.standards_service import TraceLensStandardsService
from src.schemas.standards import (
    MandatoryRulesCatalog,
    TraceLensStandard,
    TraceLensStandardListResponse,
)

router = APIRouter(prefix="/standards", tags=["standards"])

_service = TraceLensStandardsService()


@router.get("/catalog/questions")
def get_questions_catalog() -> dict[str, Any]:
    """Return the full questions catalog for standards builder UI."""
    return _service.get_questions_catalog()


@router.get("/catalog/mandatory", response_model=MandatoryRulesCatalog)
def get_mandatory_rules() -> MandatoryRulesCatalog:
    """Return the mandatory rules catalog."""
    return _service.get_mandatory_rules()


@router.get("", response_model=TraceLensStandardListResponse)
def list_standards() -> TraceLensStandardListResponse:
    """List all saved TraceLens standards."""
    return TraceLensStandardListResponse(standards=_service.list_standards())


@router.get("/{standard_id}", response_model=TraceLensStandard)
def get_standard(standard_id: str) -> TraceLensStandard:
    """Get a single TraceLens standard by ID."""
    try:
        return _service.get_standard(standard_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.post("", response_model=TraceLensStandard, status_code=status.HTTP_201_CREATED)
def create_standard(standard: TraceLensStandard) -> TraceLensStandard:
    """Create a new TraceLens standard."""
    try:
        return _service.save_standard(standard)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.put("/{standard_id}", response_model=TraceLensStandard)
def update_standard(standard_id: str, standard: TraceLensStandard) -> TraceLensStandard:
    """Update an existing TraceLens standard."""
    try:
        return _service.update_standard(standard_id, standard)
    except ValueError as exc:
        detail = str(exc)
        if "not found" not in detail.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=detail
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=detail
        ) from exc


@router.delete("/{standard_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_standard(standard_id: str) -> Response:
    """Delete a TraceLens standard."""
    try:
        _service.delete_standard(standard_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
