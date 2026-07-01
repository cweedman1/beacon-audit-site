from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FreeScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class CategoryGrade(BaseModel):
    score: int | None
    grade: str | None
    status: str


class OverallGrade(BaseModel):
    grade: str
    status: str
    summary: str


class IssueSummary(BaseModel):
    title: str
    severity: str
    explanation: str
    business_impact: str
    recommended_fix: str


class RecommendedFix(BaseModel):
    title: str
    priority: str
    estimated_effort: str
    business_impact: str


class FreeScanResponse(BaseModel):
    api_version: str
    scan_engine: str
    url: str
    overall: OverallGrade
    categories: dict[str, CategoryGrade]
    summary: str
    top_issues: list[IssueSummary]
    recommended_fixes: list[RecommendedFix]
    estimated_effort: str
    debug: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
    api_version: str
    python: str
    node: str
    lighthouse: str
    chromium: str


class RootResponse(BaseModel):
    service: str
    api_version: str
    status: str
    health: str


class ErrorResponse(BaseModel):
    error: str
    message: str
    status_code: int
